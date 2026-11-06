//! # authn-testkit
//!
//! Shared test support for every crate (dev-dependency only):
//!
//! * [`MIGRATOR`] — the workspace migrations for
//!   `#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]`.
//! * [`FakeClock`] and a fake for **every** port in `authn_core::ports`
//!   ([`fakes`]), bundled in [`TestPorts`].
//! * [`config`] — a valid, deterministic [`AppConfig`](authn_core::config::AppConfig)
//!   for tests (fixed, publicly known keys: never use outside tests).
//! * [`http`] — build requests, send them through a `Router` with
//!   `tower::ServiceExt::oneshot`, parse the error envelope.
//! * [`mmdb`] — a minimal MaxMind DB writer for GeoIP fixtures (RSK-05;
//!   no third-party GeoIP data in the repository).
//! * [`timing`] — statistical timing comparison for account-enumeration
//!   tests (TST-02).
//! * [`bench`](mod@bench) — latency statistics, the micro-benchmark runner of the
//!   bench targets and the SQL statement counter (K-70).
//!
//! Panicking on misuse is the desired behaviour of test helpers, so the
//! workspace bans on `unwrap`/`expect`/`panic` are lifted for this crate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod bench;
pub mod clock;
pub mod config;
pub mod fakes;
pub mod http;
pub mod mmdb;
pub mod timing;

use sqlx::migrate::Migrator;

pub use clock::FakeClock;
pub use fakes::TestPorts;

/// The workspace migrations. Usage:
///
/// ```ignore
/// #[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
/// async fn pwd_07_reset_token_is_single_use(pool: sqlx::PgPool) { /* … */ }
/// ```
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Installs a test-friendly `tracing` subscriber once (respects `RUST_LOG`).
pub fn init_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}
