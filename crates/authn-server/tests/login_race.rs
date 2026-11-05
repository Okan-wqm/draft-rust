#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-128 audit: a password login reuses the account row it read before
//! the password was verified and re-checks it under the row lock
//! (`LoginPlan::still_matches`). The password credential is a separate
//! row: a password reset (PWD-09), change (PWD-06) or an administrator's
//! `must_change_password` (PWD-12) that commits while the login is between
//! verifying the password and locking the account must not let the login
//! establish a session (or open a challenge) on the strength of the old
//! credential state — the change revoked every session and pending login
//! that existed when it committed, and this one would survive it.
//!
//! Interleaving: the test holds the `users` row (`FOR NO KEY UPDATE`, as
//! the password services do with `FOR UPDATE`), lets the login run until
//! it waits for that lock in `finish_login_in`, changes the credential in
//! the holding transaction and commits.

mod common;

use std::time::Duration;

use authn_core::id::UserId;
use authn_core::secret::SensitiveString;
use authn_store::{NewPasswordHash, UserRepository};
use authn_testkit::http::{TestRequest, TestResponse};
use common::{App, HOST, PASSWORD};
use serde_json::json;
use sqlx::PgPool;

/// Waits until `n` backends of this test database wait for a lock.
async fn wait_for_lock_waiters(pool: &PgPool, n: i64) {
    for _ in 0..500 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        if waiting >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {n} lock waiter(s)");
}

async fn live_sessions(pool: &PgPool, user: UserId) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL) \
              + (SELECT count(*) FROM auth_challenges WHERE user_id = $1 AND consumed_at IS NULL)",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Runs a native password login with [`PASSWORD`] and applies `change` to
/// the credential while the login waits for the account row lock.
async fn login_racing<F>(app: &App, user: UserId, change: F) -> TestResponse
where
    F: for<'c> FnOnce(
        &'c mut sqlx::PgConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'c>>,
{
    let mut holder = app.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE")
        .bind(user)
        .execute(&mut *holder)
        .await
        .unwrap();
    let router = app.router.clone();
    let login = tokio::spawn(async move {
        TestRequest::post("/v1/login/password")
            .json(&json!({"email": "victim@example.com", "password": PASSWORD}))
            .header("x-authn-client", "native")
            .header("host", HOST)
            .send(&router)
            .await
    });
    wait_for_lock_waiters(&app.pool, 1).await;
    change(&mut holder).await;
    holder.commit().await.unwrap();
    login.await.unwrap()
}

fn app_config(c: &mut authn_core::config::AppConfig) {
    // A plain password login completes without a challenge.
    c.protect.risk.enabled = false;
}

/// PWD-09 / PWD-06: the password is replaced (reset or change) while the
/// login with the old one is in flight.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_k128_password_replaced_during_a_login_leaves_no_session(pool: PgPool) {
    let app = App::with(pool, app_config).await;
    let user = app.user("victim@example.com").await;
    // Any other hash: the login only has to notice the replacement.
    let new_hash = SensitiveString::new("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$b3RoZXJoYXNo");
    let pepper = UserRepository::find_password(&app.pool, user)
        .await
        .unwrap()
        .unwrap()
        .pepper_version;
    let response = login_racing(&app, user, move |conn| {
        Box::pin(async move {
            UserRepository::set_password(
                conn,
                user,
                &NewPasswordHash {
                    password_hash: &new_hash,
                    algorithm: "argon2id",
                    pepper_version: pepper,
                },
                false,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        })
    })
    .await;
    assert!(
        !response.status.is_success(),
        "a login verified against the replaced password succeeded: {}",
        response.text()
    );
    assert_eq!(live_sessions(&app.pool, user).await, 0);
}

/// PWD-12: an administrator requires a new password while the login is
/// in flight; the login must not end in a full session.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_12_k128_must_change_set_during_a_login_is_not_skipped(pool: PgPool) {
    let app = App::with(pool, app_config).await;
    let user = app.user("victim@example.com").await;
    let response = login_racing(&app, user, move |conn| {
        Box::pin(async move {
            assert!(
                UserRepository::set_must_change_password(conn, user, true)
                    .await
                    .unwrap()
            );
        })
    })
    .await;
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap_or_default();
    assert_ne!(
        body["status"], "authenticated",
        "must_change_password set during the login was skipped: {body}"
    );
    let sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(sessions, 0);
}
