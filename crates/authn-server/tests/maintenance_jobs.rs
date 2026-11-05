#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OPS-06: the background cleanups (`jobs::run_maintenance_once`) remove
//! expired sessions, expired one-time tokens and stale unverified accounts,
//! and two instances running them at the same moment over one database
//! neither fail nor double-process (`FOR UPDATE SKIP LOCKED` / advisory
//! locks in the module functions).

mod common;

use std::time::Duration;

use common::{App, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Starts a registration that is never verified (ACC-05 placeholder).
async fn unverified_signup(app: &App, email: &str) {
    let mut browser = app.browser();
    browser.csrf(app).await;
    let terms: Vec<Value> = app
        .send(browser.get("/v1/terms"))
        .await
        .json::<Value>()
        .get("current")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|t| json!({"document": t["document"], "version": t["version"]}))
        .collect();
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/signup",
                &json!({"email": email, "password": PASSWORD, "accepted_terms": terms}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "signup: {}", r.text());
    app.drain().await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_06_maintenance_jobs_clean_up_and_are_safe_on_two_instances(pool: PgPool) {
    // Two application instances over the same database.
    let first = App::new(pool.clone()).await;
    let second = App::new(pool.clone()).await;

    first.user("alice@example.com").await;
    let mut browser = first.browser();
    let body = browser.login(&first, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    unverified_signup(&first, "bob@example.com").await;
    // A password reset link (one-time token, PWD-07) that is never used.
    let mut stranger = first.browser();
    stranger.csrf(&first).await;
    let r = stranger
        .send(
            &first,
            stranger.post(
                "/v1/password/forgot",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    first.drain().await;

    assert_eq!(count(&pool, "SELECT count(*) FROM sessions").await, 1);
    assert_eq!(count(&pool, "SELECT count(*) FROM users").await, 2);
    assert!(count(&pool, "SELECT count(*) FROM one_time_tokens").await >= 1);

    // Past every lifetime and retention window (session absolute lifetime
    // plus the 30-day retention of ended sessions, verification links,
    // the 7-day unverified-account window).
    let later = Duration::from_secs(400 * 24 * 3600);
    first.advance(later);
    second.advance(later);

    let (a, b) = tokio::join!(
        authn_server::jobs::run_maintenance_once(&first.services),
        authn_server::jobs::run_maintenance_once(&second.services),
    );
    assert_eq!(a.failed, 0, "first instance: {a:?}");
    assert_eq!(b.failed, 0, "second instance: {b:?}");
    assert!(a.removed + b.removed >= 3, "{a:?} {b:?}");

    assert_eq!(count(&pool, "SELECT count(*) FROM sessions").await, 0);
    assert_eq!(
        count(&pool, "SELECT count(*) FROM one_time_tokens").await,
        0
    );
    // Only the verified account is left.
    assert_eq!(count(&pool, "SELECT count(*) FROM users").await, 1);

    // Nothing is left for a later run, and it does not fail either.
    let again = authn_server::jobs::run_maintenance_once(&second.services).await;
    assert_eq!(again.failed, 0, "{again:?}");
    assert_eq!(again.removed, 0, "{again:?}");
}
