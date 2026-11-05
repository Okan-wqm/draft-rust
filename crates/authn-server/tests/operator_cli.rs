#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Wave 8B operator paths through the **real binary**:
//!
//! * K-106: `serve` starts and is ready on a schema a newer release has
//!   already migrated (rolling deployment), with `migrate_on_start` off and
//!   on; it still refuses a modified migration of its own.
//! * K-107: `audit-checkpoint` prints an anchor `verify-audit-chain
//!   --anchor` accepts.
//! * K-108: `export-erasures` / `reapply-erasures`.
//! * K-109: the metrics listener can be switched off and bound to every
//!   interface (the container setting) from the environment.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use sqlx::PgPool;

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

fn command(pool: Option<&PgPool>, args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rust-authentication"));
    command
        .arg("--config")
        .arg(example_config())
        .args(args)
        .env_remove("AUTHN_CONFIG")
        .env("RUST_LOG", "info")
        // The example's Redis-free, Mailpit-free development settings.
        .env("AUTHN__SERVER__METRICS_BIND_ADDR", "off")
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(pool) = pool {
        command.env("AUTHN__DATABASE__URL", database_url(pool));
    }
    command
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

async fn run(
    pool: Option<&PgPool>,
    args: &[&str],
    env: &[(&str, &str)],
    stdin: Option<&str>,
) -> Run {
    let mut command = command(pool, args, env);
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let stdin = stdin.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
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
    })
    .await
    .unwrap()
}

/// The erasure ledger MAC key of `config/example.toml` (K-108).
fn example_ledger_key() -> authn_crypto::kdf::HmacKey {
    let config = authn_core::config::AppConfig::load(Some(&example_config())).unwrap();
    authn_crypto::kdf::KeyRing::from_config(&config.crypto)
        .unwrap()
        .key(authn_crypto::kdf::KeyPurpose::ErasureLedger)
        .unwrap()
        .clone()
}

/// Records version 99 as applied by a newer release (expand-only DDL).
async fn migrate_like_a_newer_release(pool: &PgPool) {
    sqlx::query("CREATE TABLE k106_newer_release (id bigint PRIMARY KEY)")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (99, 'newer release', true, $1, 1)",
    )
    .bind(vec![0xab_u8; 48])
    .execute(pool)
    .await
    .unwrap();
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `GET <path>` over plain HTTP/1.1; the status code, if any answer.
fn http_status(addr: SocketAddr, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response.split_whitespace().nth(1)?.parse().ok()
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts `serve`; `Ok(port)` once `/health/ready` answers 200, `Err` with
/// the output when the process exits first.
async fn start_server(pool: &PgPool, migrate_on_start: bool) -> (Server, Result<u16, Run>) {
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let mut command = command(
        Some(pool),
        &["serve"],
        &[
            ("AUTHN__SERVER__BIND_ADDR", bind.as_str()),
            (
                "AUTHN__DATABASE__MIGRATE_ON_START",
                if migrate_on_start { "true" } else { "false" },
            ),
        ],
    );
    command.stdin(Stdio::null());
    let mut server = Server(command.spawn().unwrap());
    let addr: SocketAddr = bind.parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut out) = server.0.stdout.take() {
                let _ = out.read_to_string(&mut stdout);
            }
            if let Some(mut err) = server.0.stderr.take() {
                let _ = err.read_to_string(&mut stderr);
            }
            let run = Run {
                code: status.code().unwrap_or(-1),
                stdout,
                stderr,
            };
            return (server, Err(run));
        }
        let ready = tokio::task::spawn_blocking(move || http_status(addr, "/health/ready"))
            .await
            .unwrap();
        if ready == Some(200) {
            return (server, Ok(port));
        }
        assert!(
            Instant::now() < deadline,
            "server not ready in time ({ready:?})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_106_serve_runs_on_a_schema_ahead_of_the_binary(pool: PgPool) {
    migrate_like_a_newer_release(&pool).await;
    for migrate_on_start in [false, true] {
        let (server, ready) = start_server(&pool, migrate_on_start).await;
        let port = ready.unwrap_or_else(|run| {
            panic!(
                "migrate_on_start = {migrate_on_start}: serve exited {}\n{}",
                run.code,
                run.all()
            )
        });
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert_eq!(
            tokio::task::spawn_blocking(move || http_status(addr, "/health/live"))
                .await
                .unwrap(),
            Some(200)
        );
        drop(server);
    }
    // Commands that need the database work as well (they share the check).
    let out = run(Some(&pool), &["migrate"], &[], None).await;
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(
        out.stdout.contains("schema is ahead of this binary"),
        "{}",
        out.all()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_106_serve_still_refuses_a_modified_migration(pool: PgPool) {
    migrate_like_a_newer_release(&pool).await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
        .bind(vec![0_u8; 48])
        .execute(&pool)
        .await
        .unwrap();
    let (_server, ready) = start_server(&pool, false).await;
    let run = ready.expect_err("serve must refuse a modified migration");
    assert_eq!(run.code, 69, "{}", run.all());
    assert!(
        run.all().contains("checksum_mismatch: [1]"),
        "{}",
        run.all()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_106_serve_refuses_a_schema_contracted_by_a_newer_release(pool: PgPool) {
    // A newer release that broke the expand-only rule (maintenance-window
    // release) marks its migration `<version>_contract_<…>.sql`; an old
    // binary (rollback, a restarted old instance) must not serve on it.
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (99, 'contract drop legacy column', true, $1, 1)",
    )
    .bind(vec![0xab_u8; 48])
    .execute(&pool)
    .await
    .unwrap();
    for migrate_on_start in [false, true] {
        let (_server, ready) = start_server(&pool, migrate_on_start).await;
        let run = ready.expect_err("serve must refuse a contracted schema");
        assert_ne!(run.code, 0, "{}", run.all());
        assert!(run.all().contains("contract"), "{}", run.all());
    }
    let out = run(Some(&pool), &["migrate"], &[], None).await;
    assert_ne!(out.code, 0, "{}", out.all());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_107_cli_audit_checkpoint_prints_a_verifiable_anchor(pool: PgPool) {
    // Some events (a keyed-chain activation writes one).
    let out = run(Some(&pool), &["rotate-audit-chain-key"], &[], None).await;
    assert_eq!(out.code, 0, "{}", out.all());
    let out = run(
        Some(&pool),
        &["create-admin", "--email", "root@example.com"],
        &[],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.all());

    let out = run(Some(&pool), &["audit-checkpoint"], &[], None).await;
    assert_eq!(out.code, 0, "{}", out.all());
    // The anchor is the last stdout line (log lines may precede it).
    let anchor = out.stdout.trim().lines().last().unwrap().trim().to_owned();
    let (seq, hash) = anchor.split_once(':').unwrap();
    assert!(seq.parse::<i64>().unwrap() >= 2, "{anchor}");
    assert_eq!(hash.len(), 64, "{anchor}");
    let reason: String =
        sqlx::query_scalar("SELECT reason FROM audit_chain_checkpoints WHERE seq = $1")
            .bind(seq.parse::<i64>().unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason, "manual");

    let out = run(
        Some(&pool),
        &["verify-audit-chain", "--anchor", anchor.as_str()],
        &[],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(out.stdout.contains("audit chain intact"), "{}", out.all());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_108_cli_reapplies_an_exported_ledger(pool: PgPool) {
    // A "restored" account: present in the database, erased according to
    // the ledger kept outside it.
    let user = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, email_normalized, email_verified_at, status) \
         VALUES ($1, 'back@example.com', 'back@example.com', now(), 'active')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let record = authn_account::ErasureRecord {
        user_id: serde_json::from_value(serde_json::json!(user)).unwrap(),
        erased_at: time::OffsetDateTime::parse(
            "2026-11-01T10:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
        reason: "grace_period_elapsed".to_owned(),
    };
    let ledger = format!(
        "# exported by export-erasures\n{}\n",
        authn_account::ledger_line(&record, &example_ledger_key())
    );
    let out = run(
        Some(&pool),
        &["reapply-erasures", "--from", "-"],
        &[],
        Some(&ledger),
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(
        out.stdout
            .contains("1 accounts erased again, 0 already erased, 0 blocked"),
        "{}",
        out.all()
    );
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!exists);
    // No personal data reaches the output or the logs.
    assert!(!out.all().contains("back@example.com"), "{}", out.all());

    // Idempotent.
    let out = run(
        Some(&pool),
        &["reapply-erasures", "--from", "-"],
        &[],
        Some(&ledger),
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(
        out.stdout
            .contains("0 accounts erased again, 1 already erased"),
        "{}",
        out.all()
    );

    // The ledger keeps the original record; export writes it as JSON lines
    // that `reapply-erasures` reads back.
    let dir = std::env::temp_dir().join(format!("k108-{}", uuid::Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("ledger.jsonl");
    let path = file.to_str().unwrap().to_owned();
    let out = run(
        Some(&pool),
        &[
            "export-erasures",
            "--since",
            "2026-11-01T00:00:00Z",
            "--output",
            path.as_str(),
        ],
        &[],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(
        out.stdout.contains("1 erasure ledger entries written"),
        "{}",
        out.all()
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{}\n", ledger.lines().nth(1).unwrap())
    );
    let out = run(
        Some(&pool),
        &["reapply-erasures", "--from", path.as_str()],
        &[],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(out.stdout.contains("1 already erased"), "{}", out.all());
    let out = run(
        Some(&pool),
        &[
            "export-erasures",
            "--since",
            "2026-11-02T00:00:00Z",
            "--output",
            path.as_str(),
        ],
        &[],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.all());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
    std::fs::remove_dir_all(&dir).unwrap();

    // An invalid ledger is refused before anything is erased (exit 65).
    let out = run(
        Some(&pool),
        &["reapply-erasures", "--from", "-"],
        &[],
        Some("{\"user_id\":\"someone@example.com\"}\n"),
    )
    .await;
    assert_eq!(out.code, 65, "{}", out.all());
    assert!(!out.all().contains("someone@example.com"), "{}", out.all());
}

/// K-108 audit: the ledger file lives in storage outside the database —
/// often a weaker security domain than the database itself — and
/// `reapply-erasures` irreversibly erases every account it names. A line
/// that `export-erasures` did not write (no or a wrong MAC under the
/// deployment's `crypto.hmac_root_key`) must be refused before anything is
/// erased, so write access to the export storage is not a way to delete
/// arbitrary accounts after the next restore.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_k108_forged_ledger_lines_are_refused(pool: PgPool) {
    let user = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, email_normalized, email_verified_at, status) \
         VALUES ($1, 'victim@example.com', 'victim@example.com', now(), 'active')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let unsigned = format!(
        "{{\"user_id\":\"{user}\",\"erased_at\":\"2026-11-01T10:00:00Z\",\"reason\":\"grace_period_elapsed\"}}\n"
    );
    let wrong_mac = format!(
        "{{\"user_id\":\"{user}\",\"erased_at\":\"2026-11-01T10:00:00Z\",\"reason\":\"grace_period_elapsed\",\"mac\":\"{}\"}}\n",
        "00".repeat(32)
    );
    for forged in [unsigned, wrong_mac] {
        let out = run(
            Some(&pool),
            &["reapply-erasures", "--from", "-"],
            &[],
            Some(&forged),
        )
        .await;
        assert_eq!(out.code, 65, "{}", out.all());
        assert!(out.all().contains("line 1"), "{}", out.all());
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(exists, "a forged ledger line erased an account");
    }
}

#[tokio::test]
async fn k_109_metrics_listener_settings_from_the_environment_are_valid() {
    for value in ["off", "0.0.0.0:9090"] {
        let out = run(
            None,
            &["check-config"],
            &[("AUTHN__SERVER__METRICS_BIND_ADDR", value)],
            None,
        )
        .await;
        assert_eq!(out.code, 0, "{value}: {}", out.all());
    }
    let out = run(
        None,
        &["check-config"],
        &[("AUTHN__SERVER__METRICS_BIND_ADDR", "everywhere")],
        None,
    )
    .await;
    assert_eq!(out.code, 78, "{}", out.all());
    assert!(out.all().contains("metrics_bind_addr"), "{}", out.all());
}
