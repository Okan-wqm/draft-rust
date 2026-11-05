#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-107: external audit anchors. The server records a `scheduled`
//! checkpoint of the chain head once per `audit.checkpoint_interval`
//! (leader-safe across instances) and logs it; `verify-audit-chain
//! --anchor <seq>:<hash>` accepts it.

mod common;

use std::time::Duration;

use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, SecurityEvent, SecurityEventKind};
use common::App;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

async fn record_events(app: &App, n: usize) {
    for _ in 0..n {
        app.services
            .audit
            .sink()
            .record(
                SecurityEvent::new(
                    SecurityEventKind::LoginSucceeded,
                    authn_core::ports::Clock::now(app.ports.clock.as_ref()),
                )
                .with_actor(Actor::System)
                .with_subject(UserId::generate()),
            )
            .await
            .unwrap();
    }
}

async fn scheduled(pool: &PgPool) -> Vec<(i64, Vec<u8>)> {
    sqlx::query_as(
        "SELECT seq, hash FROM audit_chain_checkpoints WHERE reason = 'scheduled' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_107_running_server_jobs_produce_an_external_anchor(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    record_events(&app, 3).await;
    // The background jobs of `serve` (no explicit call): an anchor appears.
    let stop = CancellationToken::new();
    let mut jobs = authn_server::jobs::spawn(app.services.clone(), stop.clone()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let anchors = loop {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT seq, reason FROM audit_chain_checkpoints WHERE reason <> 'chain_key_switch'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        if !rows.is_empty() || tokio::time::Instant::now() > deadline {
            break rows;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    stop.cancel();
    while jobs.join_next().await.is_some() {}
    assert!(
        !anchors.is_empty(),
        "no audit checkpoint was created by the running server"
    );
    assert!(
        anchors.iter().all(|(_, reason)| reason == "scheduled"),
        "{anchors:?}"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_107_one_scheduled_checkpoint_per_interval_across_instances(pool: PgPool) {
    // Two instances on the same database (same fake clock).
    let a = App::new(pool.clone()).await;
    let b = App::new(pool.clone()).await;
    b.ports
        .clock
        .set(authn_core::ports::Clock::now(a.ports.clock.as_ref()));
    record_events(&a, 2).await;

    // Concurrent runs of the hourly check on both instances.
    let (ra, rb) = tokio::join!(
        authn_server::jobs::create_audit_checkpoint(&a.services),
        authn_server::jobs::create_audit_checkpoint(&b.services),
    );
    let created: Vec<_> = [ra.unwrap(), rb.unwrap()].into_iter().flatten().collect();
    assert_eq!(created.len(), 1, "{created:?}");
    let first = created[0];
    assert_eq!(scheduled(&pool).await.len(), 1);

    // Later checks within the interval write nothing, even with new events.
    record_events(&a, 2).await;
    a.advance(Duration::from_secs(23 * 3600));
    b.ports
        .clock
        .set(authn_core::ports::Clock::now(a.ports.clock.as_ref()));
    for app in [&a, &b] {
        assert_eq!(
            authn_server::jobs::create_audit_checkpoint(&app.services)
                .await
                .unwrap(),
            None
        );
    }
    // Once the interval has passed: exactly one new anchor, at the moved
    // head, however many instances check.
    a.advance(Duration::from_secs(3600));
    b.ports
        .clock
        .set(authn_core::ports::Clock::now(a.ports.clock.as_ref()));
    let (ra, rb) = tokio::join!(
        authn_server::jobs::create_audit_checkpoint(&a.services),
        authn_server::jobs::create_audit_checkpoint(&b.services),
    );
    let created: Vec<_> = [ra.unwrap(), rb.unwrap()].into_iter().flatten().collect();
    assert_eq!(created.len(), 1, "{created:?}");
    let second = created[0];
    assert!(second.seq > first.seq);
    assert_eq!(scheduled(&pool).await.len(), 2);

    // The anchor verifies the chain from that point (verify-audit-chain
    // --anchor).
    let keys = a.services.audit.chain_keys();
    let report = authn_audit::verify_chain_from(&pool, keys, first)
        .await
        .unwrap();
    assert!(report.is_intact(), "{report:?}");
    let report = authn_audit::verify_chain(&pool, keys).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_107_empty_chain_has_nothing_to_anchor(pool: PgPool) {
    // A freshly migrated database: no event, nothing to anchor (a
    // checkpoint at seq 0 would point at no event).
    let clock = authn_testkit::FakeClock::new();
    let created =
        authn_audit::create_scheduled_checkpoint(&pool, &clock, Duration::from_secs(3600))
            .await
            .unwrap();
    assert_eq!(created, None);
    assert!(scheduled(&pool).await.is_empty());
    assert!(authn_audit::create_checkpoint(&pool, &clock).await.is_err());
}
