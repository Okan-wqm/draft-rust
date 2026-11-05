#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-58 wiring (OPS-06, ADM-06, CRY-10): `jobs::spawn` starts the
//! authn-session signing-key listener, so an emergency rotation made by
//! another process (another instance, or the CLI) reaches a serving
//! instance at once instead of after `session.signing_key_cache_ttl`.

mod common;

use std::time::Duration;

use authn_core::ports::Clock;
use authn_store::SigningKeyRepository;
use axum::http::StatusCode;
use common::{App, PASSWORD};
use serde_json::json;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// Two instances on one database; B caches its signing keys for the
/// longest allowed time (5 min) and runs the background jobs. A rotation
/// on a raw connection (as `rotate-signing-key --emergency` does from the
/// CLI) makes B reject the old access token within a few seconds.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_09_k58_serving_instance_drops_a_key_revoked_elsewhere(pool: PgPool) {
    let long_cache = |c: &mut authn_core::config::AppConfig| {
        c.session.signing_key_cache_ttl = Duration::from_secs(300);
    };
    let a = App::with(pool.clone(), long_cache).await;
    let b = App::with(pool.clone(), long_cache).await;
    a.user("alice@example.com").await;

    let mut native = b.native();
    let r = b
        .send(native.post(
            "/v1/login/password",
            &json!({"email": "alice@example.com", "password": PASSWORD}),
        ))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    native.absorb(&r.json());
    // B verifies (and caches) with the active key.
    b.send(native.get("/v1/me"))
        .await
        .assert_status(StatusCode::OK);

    let shutdown = CancellationToken::new();
    let mut jobs = authn_server::jobs::spawn(b.services.clone(), shutdown.clone()).unwrap();
    let mut connected = false;
    for _ in 0..500 {
        if b.services.sessions.signing_key_listener_connected() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(connected, "the signing-key listener did not connect");
    // A (re)connection drops the cache; reload it before the rotation.
    b.send(native.get("/v1/me"))
        .await
        .assert_status(StatusCode::OK);

    let mut conn = pool.acquire().await.unwrap();
    SigningKeyRepository::emergency_rotate(
        &mut conn,
        &a.services.crypto.envelopes,
        a.ports.clock.now(),
    )
    .await
    .unwrap();
    drop(conn);

    let mut rejected = false;
    for _ in 0..50 {
        if b.send(native.get("/v1/me")).await.status == StatusCode::UNAUTHORIZED {
            rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    shutdown.cancel();
    while jobs.join_next().await.is_some() {}
    assert!(
        rejected,
        "B still accepts a token of the revoked key (listener not wired)"
    );
}

/// The listener's backend, if one is listening on this test database.
async fn listener_backend(pool: &PgPool) -> Option<i32> {
    sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity \
         WHERE datname = current_database() AND query ILIKE 'LISTEN%' \
           AND pid <> pg_backend_pid() \
         ORDER BY backend_start DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// K-58 wiring audit (fail-open check): when the listener's database
/// connection is killed (failover, idle-connection reaper, network), the
/// listener reconnects and re-subscribes; a later emergency rotation still
/// reaches the serving instance through a notification — faster than the
/// 5 s cache lifetime the cache falls back to while disconnected, so the
/// test fails if invalidation silently stopped.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_09_k58_listener_survives_a_killed_connection(pool: PgPool) {
    let long_cache = |c: &mut authn_core::config::AppConfig| {
        c.session.signing_key_cache_ttl = Duration::from_secs(300);
    };
    let a = App::with(pool.clone(), long_cache).await;
    let b = App::with(pool.clone(), long_cache).await;
    a.user("alice@example.com").await;
    let mut native = b.native();
    let r = b
        .send(native.post(
            "/v1/login/password",
            &json!({"email": "alice@example.com", "password": PASSWORD}),
        ))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    native.absorb(&r.json());

    let shutdown = CancellationToken::new();
    let mut jobs = authn_server::jobs::spawn(b.services.clone(), shutdown.clone()).unwrap();
    let mut first = None;
    for _ in 0..500 {
        first = listener_backend(&pool).await;
        if first.is_some() && b.services.sessions.signing_key_listener_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let first = first.expect("the signing-key listener did not connect");

    // Kill the LISTEN connection; wait for a new one.
    let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(first)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(killed);
    let mut second = None;
    for _ in 0..1_000 {
        second = listener_backend(&pool).await.filter(|pid| *pid != first);
        if second.is_some() && b.services.sessions.signing_key_listener_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(second.is_some(), "the listener did not reconnect");

    // Fresh cache, then a rotation made elsewhere.
    b.send(native.get("/v1/me"))
        .await
        .assert_status(StatusCode::OK);
    let started = std::time::Instant::now();
    let mut conn = pool.acquire().await.unwrap();
    SigningKeyRepository::emergency_rotate(
        &mut conn,
        &a.services.crypto.envelopes,
        a.ports.clock.now(),
    )
    .await
    .unwrap();
    drop(conn);
    let mut rejected = false;
    while started.elapsed() < Duration::from_secs(3) {
        if b.send(native.get("/v1/me")).await.status == StatusCode::UNAUTHORIZED {
            rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    shutdown.cancel();
    // Shutdown is prompt: the listener stops with the other jobs.
    tokio::time::timeout(Duration::from_secs(10), async {
        while jobs.join_next().await.is_some() {}
    })
    .await
    .expect("background jobs did not stop");
    assert!(
        rejected,
        "after a reconnection the instance still accepts a token of the revoked key"
    );
    assert!(
        !b.services.sessions.signing_key_listener_connected(),
        "the listener still reports a connection after shutdown"
    );
}
