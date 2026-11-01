#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Transactional outbox and worker (AUD-06).

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_audit::outbox::{OutboxDepth, SealedPayload};
use authn_audit::{
    HandlerError, NewOutboxMessage, OutboxHandler, OutboxHandlers, OutboxMessage, OutboxRepository,
    OutboxWorker,
};
use authn_core::config::audit::OutboxConfig;
use authn_core::error::AuthError;
use authn_core::id::{OrgId, OutboxMessageId};
use authn_core::ports::{Clock, DomainEvent, DomainEventKind, EventPublisher};
use authn_testkit::FakeClock;
use common::Harness;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    Succeed,
    Retry,
    RetryAfter(Duration),
    Permanent,
    Panic,
    Hang,
}

struct TestHandler {
    behaviour: Mutex<Behaviour>,
    calls: Mutex<HashMap<OutboxMessageId, Vec<u32>>>,
    sealed_seen: Mutex<Vec<Vec<u8>>>,
    dead: Mutex<Vec<OutboxMessageId>>,
}

impl TestHandler {
    fn new(behaviour: Behaviour) -> Arc<Self> {
        Arc::new(Self {
            behaviour: Mutex::new(behaviour),
            calls: Mutex::new(HashMap::new()),
            sealed_seen: Mutex::new(Vec::new()),
            dead: Mutex::new(Vec::new()),
        })
    }

    fn set(&self, behaviour: Behaviour) {
        *self.behaviour.lock().unwrap() = behaviour;
    }

    fn calls(&self) -> HashMap<OutboxMessageId, Vec<u32>> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl OutboxHandler for TestHandler {
    async fn handle(&self, message: &OutboxMessage) -> Result<(), HandlerError> {
        self.calls
            .lock()
            .unwrap()
            .entry(message.id)
            .or_default()
            .push(message.attempts);
        if let Some(sealed) = &message.sealed_payload {
            self.sealed_seen
                .lock()
                .unwrap()
                .push(sealed.as_bytes().to_vec());
        }
        let behaviour = *self.behaviour.lock().unwrap();
        match behaviour {
            Behaviour::Succeed => Ok(()),
            Behaviour::Retry => Err(HandlerError::retry("receiver unavailable")),
            Behaviour::RetryAfter(d) => Err(HandlerError::retry_after("slow down", d)),
            Behaviour::Permanent => Err(HandlerError::permanent("malformed")),
            Behaviour::Panic => panic!("handler bug"),
            Behaviour::Hang => {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(())
            }
        }
    }

    async fn on_dead_letter(&self, message: &OutboxMessage) -> Result<(), AuthError> {
        self.dead.lock().unwrap().push(message.id);
        Ok(())
    }
}

fn config() -> OutboxConfig {
    OutboxConfig {
        max_attempts: 3,
        ..OutboxConfig::default()
    }
}

fn worker(
    pool: &PgPool,
    clock: &Arc<FakeClock>,
    handler: Arc<TestHandler>,
    config: OutboxConfig,
) -> OutboxWorker {
    let handlers = OutboxHandlers::new().register("test", handler).unwrap();
    OutboxWorker::new(
        pool.clone(),
        clock.clone() as Arc<dyn Clock>,
        handlers,
        config,
    )
}

async fn enqueue(
    pool: &PgPool,
    clock: &FakeClock,
    topic: &str,
    sealed: Option<&[u8]>,
    max_attempts: u32,
) -> OutboxMessageId {
    let id = OutboxMessageId::generate();
    let mut conn = pool.acquire().await.unwrap();
    let inserted = OutboxRepository::enqueue(
        &mut conn,
        &NewOutboxMessage {
            id,
            topic: topic.to_owned(),
            org_id: None,
            payload: json!({"n": 1}),
            sealed_payload: sealed.map(|s| SealedPayload::new(s.to_vec())),
            max_attempts,
            available_at: clock.now(),
            created_at: clock.now(),
        },
    )
    .await
    .unwrap();
    assert!(inserted);
    id
}

#[derive(sqlx::FromRow, Debug)]
struct Row {
    status: String,
    attempts: i32,
    available_at: OffsetDateTime,
    sealed_payload: Option<Vec<u8>>,
    last_error: Option<String>,
    delivered_at: Option<OffsetDateTime>,
    locked_by: Option<String>,
}

async fn row(pool: &PgPool, id: OutboxMessageId) -> Row {
    sqlx::query_as(
        "SELECT status, attempts, available_at, sealed_payload, last_error, delivered_at, \
         locked_by FROM outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_publish_writes_to_the_outbox_in_the_callers_transaction(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let publisher = h.service.event_publisher();
    let org = common::create_org(&pool).await;
    let mut event = DomainEvent::new(
        DomainEventKind::MemberAdded,
        h.now(),
        json!({"role": "admin"}),
    );
    event.org_id = Some(org);

    let mut tx = pool.begin().await.unwrap();
    publisher.publish(&mut tx, event.clone()).await.unwrap();
    tx.rollback().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "rolled back with the business change");

    let mut tx = pool.begin().await.unwrap();
    publisher.publish(&mut tx, event.clone()).await.unwrap();
    // Idempotent: the same event published twice is enqueued once.
    publisher.publish(&mut tx, event.clone()).await.unwrap();
    tx.commit().await.unwrap();
    let rows: Vec<(uuid::Uuid, String, Option<OrgId>, Value, String)> =
        sqlx::query_as("SELECT id, topic, org_id, payload, status FROM outbox")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    let (id, topic, org_id, payload, status) = rows.into_iter().next().unwrap();
    assert_eq!(id, event.id.as_uuid());
    assert_eq!(topic, "domain_event");
    assert_eq!(org_id, Some(org));
    assert_eq!(payload["kind"], "member.added");
    assert_eq!(payload["data"]["role"], "admin");
    assert_eq!(status, "pending");

    // Oversized events are refused (producer bug), nothing is written.
    let huge = DomainEvent::new(
        DomainEventKind::UserUpdated,
        h.now(),
        json!({"blob": "x".repeat(70 * 1024)}),
    );
    let mut tx = pool.begin().await.unwrap();
    assert!(publisher.publish(&mut tx, huge).await.is_err());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_worker_delivers_and_wipes_the_sealed_payload(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Succeed);
    let w = worker(&pool, &clock, handler.clone(), config());
    let id = enqueue(&pool, &clock, "test.email", Some(b"sealed-secret"), 3).await;

    let report = w.run_once().await.unwrap();
    assert_eq!((report.claimed, report.delivered), (1, 1));
    let r = row(&pool, id).await;
    assert_eq!(r.status, "delivered");
    assert_eq!(r.sealed_payload, None, "secret part wiped after delivery");
    assert_eq!(r.delivered_at, Some(clock.now()));
    assert_eq!(r.locked_by, None);
    assert_eq!(
        handler.sealed_seen.lock().unwrap().as_slice(),
        &[b"sealed-secret".to_vec()]
    );
    assert_eq!(handler.calls()[&id], vec![1]);
    // Delivered messages are never handed out again.
    assert_eq!(w.run_once().await.unwrap().claimed, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_failures_back_off_exponentially_then_dead_letter(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Retry);
    let cfg = config();
    let w = worker(&pool, &clock, handler.clone(), cfg);
    let id = enqueue(&pool, &clock, "test.webhook", Some(b"sealed"), 3).await;

    // Attempt 1 fails: retry in [base/2, base].
    assert_eq!(w.run_once().await.unwrap().retried, 1);
    let r = row(&pool, id).await;
    assert_eq!((r.status.as_str(), r.attempts), ("pending", 1));
    assert_eq!(r.last_error.as_deref(), Some("receiver unavailable"));
    let delay = r.available_at - clock.now();
    assert!(
        delay >= cfg.backoff_base / 2 && delay <= cfg.backoff_base,
        "{delay}"
    );
    // Not due yet.
    assert_eq!(w.run_once().await.unwrap().claimed, 0);

    // Attempt 2: delay doubles.
    clock.advance(cfg.backoff_base);
    assert_eq!(w.run_once().await.unwrap().retried, 1);
    let r = row(&pool, id).await;
    let delay = r.available_at - clock.now();
    assert!(
        delay >= cfg.backoff_base && delay <= cfg.backoff_base * 2,
        "{delay}"
    );

    // Attempt 3 is the last one: dead letter, secret wiped, hook called once.
    clock.advance(cfg.backoff_base * 2);
    let report = w.run_once().await.unwrap();
    assert_eq!(report.dead, 1);
    let r = row(&pool, id).await;
    assert_eq!((r.status.as_str(), r.attempts), ("dead", 3));
    assert_eq!(r.sealed_payload, None);
    assert_eq!(handler.dead.lock().unwrap().as_slice(), &[id]);
    assert_eq!(handler.calls()[&id], vec![1, 2, 3]);
    clock.advance(Duration::from_secs(86_400));
    assert_eq!(
        w.run_once().await.unwrap().claimed,
        0,
        "dead letters stay put"
    );
    let depth = OutboxRepository::depth(&pool).await.unwrap();
    assert_eq!(
        depth,
        OutboxDepth {
            pending: 0,
            processing: 0,
            dead: 1
        }
    );

    // Operators may requeue a dead letter with a fresh budget.
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        OutboxRepository::requeue_dead(&mut conn, id, clock.now())
            .await
            .unwrap()
    );
    handler.set(Behaviour::Succeed);
    assert_eq!(w.run_once().await.unwrap().delivered, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_permanent_errors_and_retry_after_are_honoured(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Permanent);
    let w = worker(&pool, &clock, handler.clone(), config());
    let id = enqueue(&pool, &clock, "test", None, 10).await;
    assert_eq!(w.run_once().await.unwrap().dead, 1);
    assert_eq!(row(&pool, id).await.status, "dead");
    assert_eq!(handler.dead.lock().unwrap().len(), 1);

    handler.set(Behaviour::RetryAfter(Duration::from_secs(900)));
    let id = enqueue(&pool, &clock, "test", None, 10).await;
    w.run_once().await.unwrap();
    let r = row(&pool, id).await;
    assert_eq!(r.available_at - clock.now(), time::Duration::seconds(900));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_concurrent_workers_deliver_each_message_exactly_once(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Succeed);
    let cfg = OutboxConfig {
        batch_size: 7,
        ..config()
    };
    let mut ids = Vec::new();
    for _ in 0..120 {
        ids.push(enqueue(&pool, &clock, "test.bulk", None, 3).await);
    }
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let w = worker(&pool, &clock, handler.clone(), cfg);
        tasks.push(tokio::spawn(async move {
            let mut delivered = 0;
            loop {
                let report = w.run_once().await.unwrap();
                delivered += report.delivered;
                if report.claimed == 0 {
                    break delivered;
                }
            }
        }));
    }
    let mut total = 0;
    for task in tasks {
        total += task.await.unwrap();
    }
    assert_eq!(total, 120);
    let calls = handler.calls();
    assert_eq!(calls.len(), 120);
    assert!(
        calls.values().all(|attempts| attempts == &vec![1]),
        "duplicate delivery"
    );
    for id in ids {
        assert_eq!(row(&pool, id).await.status, "delivered");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_expired_lease_of_a_crashed_worker_is_reclaimed(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Succeed);
    let cfg = config();
    let id = enqueue(&pool, &clock, "test", None, 3).await;
    // A worker claimed the message and died.
    sqlx::query(
        "UPDATE outbox SET status = 'processing', attempts = 1, locked_by = 'crashed', \
         locked_until = $2 WHERE id = $1",
    )
    .bind(id)
    .bind(clock.now() + cfg.lease)
    .execute(&pool)
    .await
    .unwrap();
    let w = worker(&pool, &clock, handler.clone(), cfg);
    assert_eq!(w.run_once().await.unwrap().claimed, 0, "lease still valid");
    clock.advance(cfg.lease);
    assert_eq!(w.run_once().await.unwrap().delivered, 1, "at least once");
    assert_eq!(handler.calls()[&id], vec![2]);

    // The final attempt's lease expired: dead letter without another call.
    let id = enqueue(&pool, &clock, "test", None, 3).await;
    sqlx::query(
        "UPDATE outbox SET status = 'processing', attempts = 3, locked_by = 'crashed', \
         locked_until = $2 WHERE id = $1",
    )
    .bind(id)
    .bind(clock.now())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(w.run_once().await.unwrap().dead, 1);
    assert!(!handler.calls().contains_key(&id));
    assert_eq!(
        row(&pool, id).await.last_error.as_deref(),
        Some("attempts exhausted")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_topics_without_a_handler_are_left_for_other_workers(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Succeed);
    let w = worker(&pool, &clock, handler.clone(), config());
    let foreign = enqueue(&pool, &clock, "notification.email", None, 3).await;
    let lookalike = enqueue(&pool, &clock, "testing", None, 3).await;
    let own = enqueue(&pool, &clock, "test.x", None, 3).await;
    let report = w.run_once().await.unwrap();
    assert_eq!(report.claimed, 1);
    assert_eq!(row(&pool, own).await.status, "delivered");
    assert_eq!(row(&pool, foreign).await.status, "pending");
    assert_eq!(row(&pool, lookalike).await.status, "pending");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_handler_panics_and_timeouts_are_retried(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Panic);
    let cfg = OutboxConfig {
        lease: Duration::from_secs(5),
        ..config()
    };
    let w = worker(&pool, &clock, handler.clone(), cfg);
    let id = enqueue(&pool, &clock, "test", None, 3).await;
    assert_eq!(w.run_once().await.unwrap().retried, 1);
    assert_eq!(
        row(&pool, id).await.last_error.as_deref(),
        Some("handler panicked")
    );

    handler.set(Behaviour::Hang);
    clock.advance(Duration::from_secs(3600));
    let started = std::time::Instant::now();
    assert_eq!(w.run_once().await.unwrap().retried, 1);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "bounded by the lease"
    );
    assert_eq!(
        row(&pool, id).await.last_error.as_deref(),
        Some("handler timed out")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_old_messages_are_purged(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Succeed);
    let w = worker(&pool, &clock, handler.clone(), config());
    let delivered = enqueue(&pool, &clock, "test", None, 3).await;
    w.run_once().await.unwrap();
    handler.set(Behaviour::Permanent);
    let dead = enqueue(&pool, &clock, "test", None, 3).await;
    w.run_once().await.unwrap();
    let pending = enqueue(&pool, &clock, "notification.sms", None, 3).await;
    let deleted = OutboxRepository::purge(
        &pool,
        clock.now() + Duration::from_secs(1),
        clock.now() + Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(deleted, 2);
    let left: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM outbox")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, vec![pending.as_uuid()]);
    let _ = (delivered, dead);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_worker_run_loop_stops_gracefully(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let handler = TestHandler::new(Behaviour::Succeed);
    let cfg = OutboxConfig {
        poll_interval: Duration::from_millis(100),
        ..config()
    };
    let w = worker(&pool, &clock, handler.clone(), cfg);
    let id = enqueue(&pool, &clock, "test", None, 3).await;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(w.run(async move {
        let _ = rx.await;
    }));
    for _ in 0..50 {
        if row(&pool, id).await.status == "delivered" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(row(&pool, id).await.status, "delivered");
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

/// Advances the shared clock past the lease while handling the first
/// message of a batch (a slow receiver).
struct SlowFirst {
    clock: Arc<FakeClock>,
    advance: Duration,
    calls: Mutex<Vec<(OutboxMessageId, String)>>,
    me: Mutex<String>,
}

#[async_trait]
impl OutboxHandler for SlowFirst {
    async fn handle(&self, message: &OutboxMessage) -> Result<(), HandlerError> {
        let me = self.me.lock().unwrap().clone();
        let first = {
            let mut calls = self.calls.lock().unwrap();
            calls.push((message.id, me));
            calls.len() == 1
        };
        if first {
            self.clock.advance(self.advance);
        }
        Ok(())
    }
}

/// Security review: messages of a batch wait for a concurrency slot; one
/// whose claim-time lease expired meanwhile (and that another worker may
/// already have re-claimed) used to be handled anyway — concurrent
/// duplicate processing. The lease is now renewed before handling, and an
/// expired one is left for re-claim.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_message_whose_lease_expired_in_the_batch_is_not_handled(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let clock = h.ports.clock.clone();
    let config = OutboxConfig {
        concurrency: 1,
        batch_size: 10,
        ..config()
    };
    let handler = Arc::new(SlowFirst {
        clock: clock.clone(),
        advance: config.lease + Duration::from_secs(1),
        calls: Mutex::new(Vec::new()),
        me: Mutex::new("a".into()),
    });
    let first = enqueue(&pool, &clock, "test.slow", None, 3).await;
    let second = enqueue(&pool, &clock, "test.slow", None, 3).await;
    let handlers = OutboxHandlers::new()
        .register("test", handler.clone())
        .unwrap();
    let worker_a = OutboxWorker::new(
        pool.clone(),
        clock.clone() as Arc<dyn Clock>,
        handlers.clone(),
        config,
    )
    .with_worker_id("worker-a");
    let report = worker_a.run_once().await.unwrap();
    assert_eq!(report.claimed, 2);
    assert_eq!(report.delivered, 1);
    assert_eq!(report.lost_leases, 1, "{report:?}");
    assert_eq!(handler.calls.lock().unwrap().len(), 1);

    // Another worker re-claims the expired message and handles it once.
    *handler.me.lock().unwrap() = "b".into();
    let worker_b = OutboxWorker::new(
        pool.clone(),
        clock.clone() as Arc<dyn Clock>,
        handlers,
        config,
    )
    .with_worker_id("worker-b");
    let report = worker_b.run_once().await.unwrap();
    assert_eq!((report.claimed, report.delivered), (1, 1), "{report:?}");
    let calls = handler.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let ids: std::collections::HashSet<_> = calls.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, [first, second].into_iter().collect());
    assert_eq!(calls[1].1, "b");
    for id in [first, second] {
        assert_eq!(row(&pool, id).await.status, "delivered");
    }
}
