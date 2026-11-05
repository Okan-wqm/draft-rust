#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OPS-01, ADM-05, K-07, K-11, SOC-07 (wave 3A audit): the operator
//! commands through the **real binary** — exit codes, argument validation
//! before any database work, and every secret (one-time password,
//! enrollment link token) printed exactly once and never logged, even at
//! `RUST_LOG=trace`.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use sqlx::PgPool;

const EC_KEY: &str = include_str!("../../authn-oidc-client/tests/fixtures/test_ec_p256.pem");

fn example_config() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/example.toml")
}

/// The URL of the throw-away database behind `pool`.
fn database_url(pool: &PgPool) -> String {
    let base = std::env::var("DATABASE_URL").unwrap();
    let db = pool.connect_options().get_database().unwrap().to_owned();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&db);
    url.to_string()
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

fn run(pool: Option<&PgPool>, args: &[&str], stdin: Option<&str>) -> Run {
    run_env(pool, args, stdin, &[])
}

fn run_env(pool: Option<&PgPool>, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rust-authentication"));
    command.envs(env.iter().copied());
    command
        .arg("--config")
        .arg(example_config())
        .args(args)
        .env("RUST_LOG", "trace")
        .env_remove("AUTHN_CONFIG")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(pool) = pool {
        command.env("AUTHN__DATABASE__URL", database_url(pool));
    }
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output().unwrap();
    Run {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

/// The line after the line containing `marker`.
fn line_after(text: &str, marker: &str) -> String {
    let mut lines = text.lines();
    lines.find(|l| l.contains(marker)).unwrap_or_else(|| {
        panic!("`{marker}` not in output:\n{text}");
    });
    lines.next().unwrap().trim().to_owned()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_cli_create_admin_prints_the_one_time_password_exactly_once(pool: PgPool) {
    let p = pool.clone();
    let out = tokio::task::spawn_blocking(move || {
        run(
            Some(&p),
            &["create-admin", "--email", "root@example.com"],
            None,
        )
    })
    .await
    .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    let password = line_after(&out.stdout, "One-time password");
    assert!(password.len() >= 16, "{password}");
    assert_eq!(
        out.all().matches(&password).count(),
        1,
        "the one-time password must be printed once and never logged"
    );
    let admins: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE email_normalized = 'root@example.com' AND is_platform_admin",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(admins, 1);
    // An existing address is never silently promoted: non-zero exit, no
    // second password.
    let p = pool.clone();
    let again = tokio::task::spawn_blocking(move || {
        run(
            Some(&p),
            &["create-admin", "--email", "root@example.com"],
            None,
        )
    })
    .await
    .unwrap();
    assert_ne!(again.code, 0, "{}", again.all());
    assert!(
        !again.stdout.contains("One-time password"),
        "{}",
        again.all()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k11_cli_enrollment_link_token_is_printed_once_in_the_fragment(pool: PgPool) {
    let p = pool.clone();
    let out = tokio::task::spawn_blocking(move || {
        run(
            Some(&p),
            &[
                "create-admin",
                "--email",
                "glass@example.com",
                "--passkey-link",
                "--ttl",
                "20m",
            ],
            None,
        )
    })
    .await
    .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    let link = line_after(&out.stdout, "One-time passkey enrollment link");
    let url = url::Url::parse(&link).unwrap();
    assert_eq!(url.path(), "/admin/enroll");
    assert_eq!(url.query(), None);
    let token = url.fragment().unwrap().to_owned();
    assert!(token.len() >= 32, "{token}");
    assert_eq!(out.all().matches(&token).count(), 1, "{}", out.all());

    // K-07 offline commands: `--operator` is validated before anything
    // touches the database, with a data-error exit code and no echo.
    for operator in ["", "two words", "evil\u{202e}op", &"x".repeat(65)] {
        let p = pool.clone();
        let op = operator.to_owned();
        let bad = tokio::task::spawn_blocking(move || {
            run(
                Some(&p),
                &[
                    "suspend-admin",
                    "--target",
                    "glass@example.com",
                    "--reason",
                    "incident 42",
                    "--operator",
                    &op,
                ],
                None,
            )
        })
        .await
        .unwrap();
        assert_eq!(bad.code, 65, "{operator:?}: {}", bad.all());
        assert!(bad.stderr.contains("--operator"), "{}", bad.all());
    }
    let suspended: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE email_normalized = 'glass@example.com' AND status = 'suspended'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(suspended, 0);

    // A new link for the existing break-glass account: printed once, the
    // previous one no longer works (single active link).
    let p = pool.clone();
    let out = tokio::task::spawn_blocking(move || {
        run(
            Some(&p),
            &[
                "admin-enrollment-link",
                "--target",
                "glass@example.com",
                "--reason",
                "lost authenticator",
                "--operator",
                "oncall@example.com",
            ],
            None,
        )
    })
    .await
    .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    let link = line_after(&out.stdout, "One-time passkey enrollment link");
    let second = url::Url::parse(&link)
        .unwrap()
        .fragment()
        .unwrap()
        .to_owned();
    assert_ne!(second, token);
    assert_eq!(out.all().matches(&second).count(), 1, "{}", out.all());

    // Offline suspension through the binary works and is audited with the
    // operator label.
    let p = pool.clone();
    let out = tokio::task::spawn_blocking(move || {
        run(
            Some(&p),
            &[
                "suspend-admin",
                "--target",
                "glass@example.com",
                "--reason",
                "incident 42",
                "--operator",
                "oncall@example.com",
            ],
            None,
        )
    })
    .await
    .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    let suspended: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE email_normalized = 'glass@example.com' AND status = 'suspended'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(suspended, 1);
}

#[tokio::test]
async fn soc_07_cli_seal_apple_key_refuses_non_keys_without_echo() {
    // Not a key: refused, never echoed, non-zero exit.
    let input = "-----BEGIN PRIVATE KEY-----\nNOTAKEYsecretmaterial42\n-----END PRIVATE KEY-----\n";
    let out = tokio::task::spawn_blocking(move || {
        run(None, &["seal-apple-key", "--pem-file", "-"], Some(input))
    })
    .await
    .unwrap();
    assert_ne!(out.code, 0, "{}", out.all());
    assert!(!out.all().contains("secretmaterial42"), "{}", out.all());

    // Oversized input (more than 16 KiB) is refused, not truncated into a
    // "valid" prefix.
    let big = format!("{EC_KEY}\n{}", "A".repeat(20 * 1024));
    let out = tokio::task::spawn_blocking(move || {
        run(None, &["seal-apple-key", "--pem-file", "-"], Some(&big))
    })
    .await
    .unwrap();
    assert_eq!(out.code, 65, "{}", out.all());

    // A real key: sealed; the key itself never appears.
    let out = tokio::task::spawn_blocking(|| {
        run(None, &["seal-apple-key", "--pem-file", "-"], Some(EC_KEY))
    })
    .await
    .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(!out.all().contains("PRIVATE KEY"), "{}", out.all());
    let key_body = EC_KEY.lines().nth(1).unwrap();
    assert!(!out.all().contains(key_body));
    let sealed = line_after(&out.stdout, "private_key_ciphertext");
    assert!(sealed.len() > 100, "{sealed}");
}

/// ARC-07 (wave 3A audit): `check-config` must not call a configuration
/// valid that `serve` refuses at start-up — e.g. an envelope-encrypted
/// Apple key that does not open with the configured KEKs.
#[tokio::test]
async fn arc_07_check_config_refuses_what_serve_would_refuse() {
    let out = tokio::task::spawn_blocking(|| run(None, &["check-config"], None))
        .await
        .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    let out = tokio::task::spawn_blocking(|| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rust-authentication"));
        let output = command
            .arg("--config")
            .arg(example_config())
            .arg("check-config")
            .env_remove("AUTHN_CONFIG")
            .env("AUTHN__OIDC_CLIENT__APPLE__CLIENT_ID", "com.example.web")
            .env("AUTHN__OIDC_CLIENT__APPLE__TEAM_ID", "TEAMID1234")
            .env("AUTHN__OIDC_CLIENT__APPLE__KEY_ID", "APPLEKEY01")
            // base64("not-an-envelope")
            .env(
                "AUTHN__OIDC_CLIENT__APPLE__PRIVATE_KEY_CIPHERTEXT",
                "bm90LWFuLWVudmVsb3Bl",
            )
            .output()
            .unwrap();
        Run {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    })
    .await
    .unwrap();
    assert_ne!(out.code, 0, "{}", out.all());
    assert!(
        !out.stdout.contains("configuration is valid"),
        "{}",
        out.all()
    );
    assert!(out.stderr.contains("apple"), "{}", out.all());
}

/// `check-config` with extra `AUTHN__*` overrides.
fn check_config_with(env: &[(&str, &str)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rust-authentication"));
    command
        .arg("--config")
        .arg(example_config())
        .arg("check-config")
        .env_remove("AUTHN_CONFIG");
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// K-73 (ARC-07, K-36): `check-config` refuses an
/// `oidc_client.error_redirect` that `serve` would refuse at start-up (an
/// absolute URL not on the redirect allow-list), naming the setting but
/// not echoing its value; an allowed target passes.
#[tokio::test]
async fn arc_07_k73_check_config_validates_the_error_redirect() {
    const KEY: &str = "AUTHN__OIDC_CLIENT__ERROR_REDIRECT";
    let refused =
        tokio::task::spawn_blocking(|| check_config_with(&[(KEY, "https://evil.example/oops")]))
            .await
            .unwrap();
    assert_ne!(refused.code, 0, "{}", refused.all());
    assert!(
        !refused.stdout.contains("configuration is valid"),
        "{}",
        refused.all()
    );
    assert!(
        refused.stderr.contains("error_redirect"),
        "{}",
        refused.all()
    );
    assert!(!refused.all().contains("evil.example"), "{}", refused.all());
    let accepted = tokio::task::spawn_blocking(|| check_config_with(&[(KEY, "/login/error")]))
        .await
        .unwrap();
    assert_eq!(accepted.code, 0, "{}", accepted.all());
    assert!(
        accepted.stdout.contains("configuration is valid"),
        "{}",
        accepted.all()
    );
}

/// Audit finding (K-73, K-75): a configuration `check-config` refuses is
/// an invalid configuration, exit code 78 as documented in
/// `docs/operations/admin-recovery.md` (not 69, which means "database /
/// service failure"), whether `AppConfig::load` or the start-up settings
/// check (`check_startup_settings`) refuses it.
#[tokio::test]
async fn ops_01_check_config_refusals_exit_with_the_configuration_code() {
    let refused = tokio::task::spawn_blocking(|| {
        check_config_with(&[(
            "AUTHN__OIDC_CLIENT__ERROR_REDIRECT",
            "https://evil.example/oops",
        )])
    })
    .await
    .unwrap();
    assert_eq!(refused.code, 78, "{}", refused.all());
    let refused = tokio::task::spawn_blocking(|| {
        check_config_with(&[("AUTHN__ADMIN__FOUR_EYES_MAX_PENDING_REQUESTS", "0")])
    })
    .await
    .unwrap();
    assert_eq!(refused.code, 78, "{}", refused.all());
    assert!(
        refused.all().contains("four_eyes_max_pending_requests"),
        "{}",
        refused.all()
    );
}

/// K-76 (OPS-01): `grant-admin` / `revoke-admin` end to end through the
/// binary: flags validated before the database is touched (exit 65, no
/// echo), the grant and the revocation change the flags, and the last
/// active admin's rights are never revoked (exit 69, "last admin").
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k76_cli_grant_and_revoke_admin(pool: PgPool) {
    let cli = |args: Vec<String>| {
        let p = pool.clone();
        tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            run(Some(&p), &args, None)
        })
    };
    let args = |command: &str, target: &str, operator: &str| -> Vec<String> {
        [
            command,
            "--target",
            target,
            "--reason",
            "CHG-17 on-call rotation",
            "--operator",
            operator,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    };
    let out = cli(vec![
        "create-admin".into(),
        "--email".into(),
        "glass@example.com".into(),
    ])
    .await
    .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    let alice = authn_core::id::UserId::generate();
    sqlx::query(
        "INSERT INTO users (id, email, email_normalized, status, email_verified_at, created_at) \
         VALUES ($1, 'alice@example.com', 'alice@example.com', 'active', now(), now())",
    )
    .bind(alice)
    .execute(&pool)
    .await
    .unwrap();
    let is_admin = |email: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT is_platform_admin FROM users WHERE email_normalized = $1",
            )
            .bind(email)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };

    let bad = cli(args("grant-admin", "alice@example.com", "two words"))
        .await
        .unwrap();
    assert_eq!(bad.code, 65, "{}", bad.all());
    assert!(bad.stderr.contains("--operator"), "{}", bad.all());
    assert!(!bad.all().contains("two words"), "{}", bad.all());
    assert!(!is_admin("alice@example.com").await);

    let out = cli(args("grant-admin", "alice@example.com", "ops.oncall"))
        .await
        .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(out.stdout.contains("offline_grant_admin"), "{}", out.all());
    assert!(is_admin("alice@example.com").await);

    let out = cli(args("revoke-admin", &alice.to_string(), "ops.oncall"))
        .await
        .unwrap();
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(!is_admin("alice@example.com").await);

    // The break-glass account is now the last admin.
    let out = cli(args("revoke-admin", "glass@example.com", "ops.oncall"))
        .await
        .unwrap();
    assert_eq!(out.code, 69, "{}", out.all());
    assert!(out.stderr.contains("last admin"), "{}", out.all());
    assert!(is_admin("glass@example.com").await);
}

/// K-77: `rotate-audit-chain-key` switches the chain to the configured key
/// version and prints the switch checkpoint; `verify-audit-chain` verifies
/// the keyed chain (also after a rotation, with an anchor, and with a
/// pinned legacy prefix), reports tampering with a non-zero exit, and the
/// chain key never reaches the output, even at `RUST_LOG=trace`.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_cli_rotates_and_verifies_the_keyed_audit_chain(pool: PgPool) {
    async fn cli(
        pool: &PgPool,
        args: &'static [&'static str],
        env: &'static [(&'static str, &'static str)],
    ) -> Run {
        let p = pool.clone();
        tokio::task::spawn_blocking(move || run_env(Some(&p), args, None, env))
            .await
            .unwrap()
    }
    let mut output = String::new();

    let first = cli(&pool, &["rotate-audit-chain-key"], &[]).await;
    assert_eq!(first.code, 0, "{}", first.all());
    assert!(
        first
            .stdout
            .contains("switched from unkeyed to key version 1"),
        "{}",
        first.all()
    );
    let anchor = first.stdout.trim().rsplit(' ').next().unwrap().to_owned();
    assert!(anchor.starts_with("1:"), "{anchor}");
    output.push_str(&first.all());
    let again = cli(&pool, &["rotate-audit-chain-key"], &[]).await;
    assert!(
        again.stdout.contains("already uses key version 1"),
        "{}",
        again.all()
    );

    let rotated = cli(
        &pool,
        &["rotate-audit-chain-key"],
        &[("AUTHN__AUDIT__CHAIN__KEY_VERSION", "2")],
    )
    .await;
    assert_eq!(rotated.code, 0, "{}", rotated.all());
    assert!(
        rotated
            .stdout
            .contains("switched from version 1 to key version 2"),
        "{}",
        rotated.all()
    );
    output.push_str(&rotated.all());

    // Verifies with the old configuration too: every version is derivable.
    let verified = cli(
        &pool,
        &["verify-audit-chain", "--legacy-until-seq", "0"],
        &[],
    )
    .await;
    assert_eq!(verified.code, 0, "{}", verified.all());
    assert!(
        verified.stdout.contains("2 events verified")
            && verified.stdout.contains("(key version 2)"),
        "{}",
        verified.all()
    );
    output.push_str(&verified.all());
    let anchor: &'static str = Box::leak(anchor.into_boxed_str());
    let args: &'static [&'static str] =
        Box::leak(Box::new(["verify-audit-chain", "--anchor", anchor]));
    let from_anchor = cli(&pool, args, &[]).await;
    assert_eq!(from_anchor.code, 0, "{}", from_anchor.all());
    assert!(
        from_anchor.stdout.contains("1 events verified"),
        "{}",
        from_anchor.all()
    );

    // Tampering: a non-zero exit naming the defect.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_events SET outcome = 'failure' WHERE seq = 1")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let broken = cli(&pool, &["verify-audit-chain"], &[]).await;
    assert_ne!(broken.code, 0, "{}", broken.all());
    assert!(broken.all().contains("HashMismatch"), "{}", broken.all());
    output.push_str(&broken.all());

    // The chain keys never reach the output.
    let config = authn_core::config::AppConfig::load(Some(example_config().as_path())).unwrap();
    let ring = authn_crypto::kdf::KeyRing::from_config(&config.crypto).unwrap();
    let family = ring.audit_chain_keys().unwrap();
    let mut secrets = vec![
        *ring
            .key(authn_crypto::kdf::KeyPurpose::AuditChain)
            .unwrap()
            .expose(),
    ];
    for v in 1..=2 {
        secrets.push(*family.version(v).unwrap().expose());
    }
    for secret in secrets {
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!output.contains(&hex), "chain key leaked");
    }
}
