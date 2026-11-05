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
    let mut command = Command::new(env!("CARGO_BIN_EXE_rust-authentication"));
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
