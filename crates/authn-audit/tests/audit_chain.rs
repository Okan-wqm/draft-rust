#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Audit sink, hash chain, verification, pseudonymisation and retention
//! (AUD-01, AUD-02, AUD-03, AUD-05) against real PostgreSQL.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use authn_audit::{
    ChainAnchor, ChainProblem, PgAuditSink, create_checkpoint, purge_before, purge_expired,
    verify_chain, verify_chain_from,
};
use authn_core::domain::Locale;
use authn_core::http::RequestContext;
use authn_core::id::{RequestId, SessionId, UserId};
use authn_core::ports::{Actor, AuditSink, SecurityEvent, SecurityEventKind};
use common::{Harness, create_org, create_user};
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

const DAY: Duration = Duration::from_secs(86_400);

fn ctx(ip: &str, ua: &str) -> RequestContext {
    RequestContext {
        request_id: RequestId::generate(),
        client_ip: ip.parse().unwrap(),
        peer_ip: ip.parse().unwrap(),
        user_agent: Some(ua.to_owned()),
        device_id: None,
        locale: Locale::En,
    }
}

fn login(h: &Harness, user: UserId) -> SecurityEvent {
    SecurityEvent::new(SecurityEventKind::LoginSucceeded, h.now())
        .with_context(&ctx("203.0.113.9", "Mozilla/5.0 (X11)"))
        .with_actor(Actor::User(user))
        .with_subject(user)
        .with_meta("method", "password")
}

async fn record_n(sink: &PgAuditSink, h: &Harness, user: UserId, n: usize) -> Vec<SecurityEvent> {
    let mut out = Vec::new();
    for _ in 0..n {
        let event = login(h, user);
        sink.record(event.clone()).await.unwrap();
        out.push(event);
    }
    out
}

async fn seq_of(pool: &PgPool, event: &SecurityEvent) -> i64 {
    sqlx::query_scalar("SELECT seq FROM audit_events WHERE id = $1")
        .bind(event.id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Runs `sql` with the append-only trigger disabled (simulates an attacker
/// with direct database access).
async fn tamper(pool: &PgPool, sql: &'static str, id: Uuid) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(sql).bind(id).execute(&mut *tx).await.unwrap();
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Every audit table rendered as text (for "never stored" assertions).
async fn dump(pool: &PgPool) -> String {
    let mut out = String::new();
    for table in [
        "SELECT row_to_json(t)::text FROM audit_events t",
        "SELECT row_to_json(t)::text FROM audit_event_pii t",
        "SELECT row_to_json(t)::text FROM audit_subjects t",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(table).fetch_all(pool).await.unwrap();
        out.push_str(&rows.join("\n"));
        out.push('\n');
    }
    out
}

#[derive(sqlx::FromRow)]
struct StoredEvent {
    kind: String,
    outcome: String,
    actor_type: String,
    actor_pseudonym: Option<Uuid>,
    subject_pseudonym: Option<Uuid>,
    org_id: Option<Uuid>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_id: Option<Uuid>,
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_01_record_persists_event_with_pseudonyms_and_pii(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    let org = create_org(&pool).await;
    let session = SessionId::generate();
    let event = login(&h, user)
        .with_org(org)
        .with_resource("session", session);
    sink.record(event.clone()).await.unwrap();

    let stored: StoredEvent = sqlx::query_as(
        "SELECT kind, outcome, actor_type, actor_pseudonym, subject_pseudonym, org_id, \
         resource_type, resource_id, request_id FROM audit_events WHERE id = $1",
    )
    .bind(event.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.kind, "login.succeeded");
    assert_eq!(stored.outcome, "success");
    assert_eq!(stored.actor_type, "user");
    assert_eq!(stored.org_id, Some(org.as_uuid()));
    assert_eq!(stored.resource_type.as_deref(), Some("session"));
    assert_eq!(stored.resource_id, Some(session.to_string()));
    assert_eq!(stored.request_id, event.request_id.map(|r| r.as_uuid()));
    let (actor, subject) = (stored.actor_pseudonym, stored.subject_pseudonym);
    let pseudonym = actor.unwrap();
    assert_eq!(subject, Some(pseudonym));
    assert_ne!(pseudonym, user.as_uuid(), "the chain never holds user ids");
    assert_eq!(
        pseudonym.get_version_num(),
        4,
        "random, time-free pseudonym"
    );

    let mapped: Uuid =
        sqlx::query_scalar("SELECT user_id FROM audit_subjects WHERE pseudonym = $1")
            .bind(pseudonym)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(mapped, user.as_uuid());
    let (owner, ip, ua): (Option<Uuid>, Option<IpAddr>, Option<String>) =
        sqlx::query_as("SELECT pseudonym, ip, user_agent FROM audit_event_pii WHERE event_id = $1")
            .bind(event.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(owner, Some(pseudonym));
    assert_eq!(ip, Some("203.0.113.9".parse().unwrap()));
    assert_eq!(ua.as_deref(), Some("Mozilla/5.0 (X11)"));

    let report = verify_chain(&pool).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
    assert_eq!(report.events_verified, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_01_record_in_tx_commits_and_rolls_back_with_the_caller(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;

    let rolled_back = login(&h, user);
    let mut tx = pool.begin().await.unwrap();
    sink.record_in_tx(&mut tx, rolled_back.clone())
        .await
        .unwrap();
    tx.rollback().await.unwrap();

    let committed = login(&h, user);
    let mut tx = pool.begin().await.unwrap();
    sink.record_in_tx(&mut tx, committed.clone()).await.unwrap();
    tx.commit().await.unwrap();

    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM audit_events ORDER BY seq")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(ids, vec![committed.id.as_uuid()]);
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_01_record_survives_a_failed_business_transaction(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    // The business transaction fails and rolls back …
    let mut business = pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user)
        .execute(&mut *business)
        .await
        .unwrap();
    // … while the failure is audited in its own transaction.
    let failed = SecurityEvent::new(SecurityEventKind::LoginFailed, h.now())
        .with_subject(user)
        .failed("wrong_password");
    sink.record(failed.clone()).await.unwrap();
    business.rollback().await.unwrap();

    let (outcome, reason): (String, Option<String>) =
        sqlx::query_as("SELECT outcome, reason FROM audit_events WHERE id = $1")
            .bind(failed.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outcome, "failure");
    assert_eq!(reason.as_deref(), Some("wrong_password"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_01_every_security_event_kind_is_recordable_and_duplicates_are_ignored(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    for kind in SecurityEventKind::ALL {
        let event = SecurityEvent::new(*kind, h.now()).with_actor(Actor::User(user));
        sink.record(event.clone()).await.unwrap();
        // An idempotent retry of the same event is not appended twice.
        sink.record(event).await.unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, i64::try_from(SecurityEventKind::ALL.len()).unwrap());
    let report = verify_chain(&pool).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_concurrent_writers_never_fork_the_chain(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let users = [
        create_user(&pool).await,
        create_user(&pool).await,
        create_user(&pool).await,
    ];
    const WRITERS: usize = 48;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(WRITERS));
    let mut tasks = Vec::new();
    for i in 0..WRITERS {
        let sink = h.service.sink();
        let pool = pool.clone();
        let barrier = barrier.clone();
        let event = login(&h, users[i % users.len()]);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            if i % 2 == 0 {
                sink.record(event).await
            } else {
                let mut tx = pool.begin().await.unwrap();
                sink.record_in_tx(&mut tx, event).await?;
                tx.commit().await.map_err(authn_core::AuthError::from)
            }
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let (count, distinct_prev): (i64, i64) =
        sqlx::query_as("SELECT count(*), count(DISTINCT prev_hash) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, i64::try_from(WRITERS).unwrap());
    assert_eq!(distinct_prev, count, "two events share a predecessor: fork");
    let report = verify_chain(&pool).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
    assert_eq!(report.events_verified, u64::try_from(WRITERS).unwrap());
    // One pseudonym per user even under concurrent first use.
    let subjects: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_subjects")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(subjects, 3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_append_only_trigger_refuses_update_delete_and_truncate(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let events = record_n(&h.service.sink(), &h, user, 1).await;
    for sql in [
        "UPDATE audit_events SET kind = 'logout' WHERE id = $1",
        "DELETE FROM audit_events WHERE id = $1",
    ] {
        let err = sqlx::query(sql)
            .bind(events[0].id)
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("42501"),
            "{sql}"
        );
    }
    assert!(
        sqlx::query("TRUNCATE audit_events CASCADE")
            .execute(&pool)
            .await
            .is_err()
    );
    // The purge hatch only admits rows older than the declared instant.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('authn.audit_purge_before', '2000-01-01T00:00:00Z', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        sqlx::query("DELETE FROM audit_events WHERE id = $1")
            .bind(events[0].id)
            .execute(&mut *tx)
            .await
            .is_err()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_modified_event_is_detected(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let events = record_n(&h.service.sink(), &h, user, 5).await;
    assert!(verify_chain(&pool).await.unwrap().is_intact());
    tamper(
        &pool,
        "UPDATE audit_events SET outcome = 'failure' WHERE id = $1",
        events[2].id.as_uuid(),
    )
    .await;
    let report = verify_chain(&pool).await.unwrap();
    let broken = report.broken.unwrap();
    assert_eq!(broken.problem, ChainProblem::HashMismatch);
    assert_eq!(broken.seq, seq_of(&pool, &events[2]).await);
    assert_eq!(report.events_verified, 2);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_deleted_or_reinserted_event_is_detected(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let events = record_n(&h.service.sink(), &h, user, 4).await;
    let third = seq_of(&pool, &events[2]).await;
    tamper(
        &pool,
        "DELETE FROM audit_events WHERE id = $1",
        events[1].id.as_uuid(),
    )
    .await;
    let broken = verify_chain(&pool).await.unwrap().broken.unwrap();
    assert_eq!(broken.problem, ChainProblem::PrevHashMismatch);
    assert_eq!(broken.seq, third);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_truncated_tail_is_detected_by_head_and_external_anchor(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let events = record_n(&h.service.sink(), &h, user, 3).await;
    let anchor = create_checkpoint(&pool, h.ports.clock.as_ref())
        .await
        .unwrap();
    assert_eq!(anchor.seq, seq_of(&pool, &events[2]).await);
    assert!(verify_chain(&pool).await.unwrap().is_intact());

    tamper(
        &pool,
        "DELETE FROM audit_events WHERE id = $1",
        events[2].id.as_uuid(),
    )
    .await;
    let broken = verify_chain(&pool).await.unwrap().broken.unwrap();
    assert!(
        matches!(
            broken.problem,
            ChainProblem::CheckpointMismatch | ChainProblem::HeadMismatch
        ),
        "{broken:?}"
    );
    // Even if the attacker also rewinds the head and removes the checkpoint,
    // the externally kept anchor exposes the truncation.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM audit_chain_checkpoints")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE audit_chain_head SET last_seq = e.seq, last_hash = e.hash \
         FROM audit_events e WHERE e.id = $1",
    )
    .bind(events[1].id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        verify_chain(&pool).await.unwrap().is_intact(),
        "internally consistent"
    );
    let report = verify_chain_from(&pool, anchor).await.unwrap();
    assert!(!report.is_intact(), "{report:?}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_verify_from_anchor_checks_the_anchor_and_later_events(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 3).await;
    let anchor = create_checkpoint(&pool, h.ports.clock.as_ref())
        .await
        .unwrap();
    record_n(&h.service.sink(), &h, user, 2).await;
    let report = verify_chain_from(&pool, anchor).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
    assert_eq!(report.events_verified, 2);
    let forged = ChainAnchor {
        seq: anchor.seq,
        hash: [9; 32],
    };
    assert_eq!(
        verify_chain_from(&pool, forged)
            .await
            .unwrap()
            .broken
            .unwrap()
            .problem,
        ChainProblem::AnchorMismatch
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_tampered_personal_data_is_detected(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let events = record_n(&h.service.sink(), &h, user, 2).await;
    sqlx::query("UPDATE audit_event_pii SET ip = '198.51.100.1' WHERE event_id = $1")
        .bind(events[0].id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        verify_chain(&pool).await.unwrap().broken.unwrap().problem,
        ChainProblem::PiiDigestMismatch
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_03_secrets_and_personal_data_never_reach_the_database(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let secrets = [
        "hunter2-Password!",
        "Kq3vX9_2mZ-8pLw0aBcD1eFgH2iJkLmN3oPqRsTuV4w",
        "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxIn0.c2ln",
        "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
        "victim@example.org",
        "482913",
        "+905551234567",
        "10.20.30.40",
        "Ayşe Yılmaz",
    ];
    let mut event = SecurityEvent::new(SecurityEventKind::PasswordResetRequested, h.now())
        .with_subject(user)
        .with_resource("token", secrets[1])
        .failed("user said hunter2-Password!");
    event = event
        .with_meta("password", secrets[0])
        .with_meta("detail", secrets[1])
        .with_meta("jwt_like", secrets[2])
        .with_meta("whs", secrets[3])
        .with_meta("contact", secrets[4])
        .with_meta("otp_value", secrets[5])
        .with_meta("number", secrets[6])
        .with_meta("origin", secrets[7])
        .with_meta("display", secrets[8])
        .with_meta("nested", json!({"deep": {"token": secrets[1]}}))
        .with_meta("Free Text Key", "x")
        .with_meta("method", "email_link");
    h.service.sink().record(event.clone()).await.unwrap();

    let stored = dump(&pool).await;
    for secret in secrets {
        assert!(!stored.contains(secret), "{secret} leaked: {stored}");
    }
    // User ids appear only in the (deletable) mapping table.
    let events_and_pii: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM audit_events t \
         UNION ALL SELECT row_to_json(p)::text FROM audit_event_pii p",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!events_and_pii.join("\n").contains(&user.to_string()));
    let (reason, metadata, resource_id): (Option<String>, Value, Option<String>) =
        sqlx::query_as("SELECT reason, metadata, resource_id FROM audit_events WHERE id = $1")
            .bind(event.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason.as_deref(), Some("invalid_reason"));
    assert_eq!(resource_id.as_deref(), Some("[REDACTED]"));
    assert_eq!(metadata["method"], "email_link");
    assert_eq!(metadata["password"], "[REDACTED]");
    assert_eq!(metadata["redacted_entries"], 1);
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_03_user_ids_in_resource_and_metadata_are_pseudonymised(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let admin = create_user(&pool).await;
    let member = create_user(&pool).await;
    let org = create_org(&pool).await;
    let unrelated = Uuid::now_v7();
    let event = SecurityEvent::new(SecurityEventKind::MemberRemoved, h.now())
        .with_actor(Actor::User(admin))
        .with_subject(member)
        .with_org(org)
        .with_resource("user", member)
        .with_meta("removed_user_id", member.to_string())
        .with_meta("membership_id", unrelated.to_string());
    h.service.sink().record(event.clone()).await.unwrap();

    let events: Vec<String> = sqlx::query_scalar("SELECT row_to_json(t)::text FROM audit_events t")
        .fetch_all(&pool)
        .await
        .unwrap();
    let text = events.join("\n");
    assert!(!text.contains(&member.to_string()), "{text}");
    assert!(!text.contains(&admin.to_string()), "{text}");
    assert!(
        text.contains(&unrelated.to_string()),
        "non-user ids are kept"
    );
    let (subject, resource_id, metadata): (Uuid, String, Value) = sqlx::query_as(
        "SELECT subject_pseudonym, resource_id, metadata FROM audit_events WHERE id = $1",
    )
    .bind(event.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(resource_id, subject.to_string());
    assert_eq!(metadata["removed_user_id"], subject.to_string());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_03_impersonation_records_the_real_actor(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let admin = create_user(&pool).await;
    let user = create_user(&pool).await;
    let mut event = SecurityEvent::new(SecurityEventKind::PasswordChanged, h.now())
        .with_context(&ctx("198.51.100.77", "AdminConsole/1"))
        .with_actor(Actor::User(user))
        .with_subject(user);
    event.impersonator = Some(admin);
    h.service.sink().record(event.clone()).await.unwrap();
    let (actor, impersonator, pii_owner): (Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT e.actor_pseudonym, e.impersonator_pseudonym, p.pseudonym FROM audit_events e \
         JOIN audit_event_pii p ON p.event_id = e.id WHERE e.id = $1",
    )
    .bind(event.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let admin_pseudonym: Uuid =
        sqlx::query_scalar("SELECT pseudonym FROM audit_subjects WHERE user_id = $1")
            .bind(admin)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(impersonator, admin_pseudonym);
    assert_ne!(actor, admin_pseudonym);
    // The request came from the admin: it is the admin's personal data.
    assert_eq!(pii_owner, admin_pseudonym);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_pseudonymize_subject_removes_pii_and_keeps_the_chain_intact(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    let other = create_user(&pool).await;
    record_n(&sink, &h, user, 3).await;
    record_n(&sink, &h, other, 2).await;

    let mut tx = pool.begin().await.unwrap();
    sink.pseudonymize_subject(&mut tx, user).await.unwrap();
    // Recording the deletion event afterwards in the same transaction must
    // not re-link the user.
    sink.record_in_tx(
        &mut tx,
        SecurityEvent::new(SecurityEventKind::AccountDeleted, h.now())
            .with_context(&ctx("203.0.113.9", "Mozilla/5.0 (X11)"))
            .with_actor(Actor::User(user))
            .with_subject(user),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mapping: Option<Uuid> =
        sqlx::query_scalar("SELECT pseudonym FROM audit_subjects WHERE user_id = $1")
            .bind(user)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(mapping, None);
    let (events, pii): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM audit_events), (SELECT count(*) FROM audit_event_pii)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(events, 6, "events stay");
    assert_eq!(pii, 2, "only the other user's personal data remains");
    let report = verify_chain(&pool).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
    assert!(!dump(&pool).await.contains(&user.to_string()));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_hard_deleted_user_is_unlinkable_and_never_remapped(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    record_n(&sink, &h, user, 2).await;
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        authn_store::UserRepository::delete(&mut conn, user)
            .await
            .unwrap()
    );
    drop(conn);
    // An event still referring to the deleted id gets a one-off pseudonym
    // and stores no personal data.
    let late = login(&h, user);
    sink.record(late.clone()).await.unwrap();
    let (subjects, pii): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM audit_subjects), (SELECT count(*) FROM audit_event_pii)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((subjects, pii), (0, 0));
    let pseudonyms: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT subject_pseudonym FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        pseudonyms.len(),
        2,
        "the late event is not linkable to the old ones"
    );
    assert!(verify_chain(&pool).await.unwrap().is_intact());
    assert!(!dump(&pool).await.contains(&user.to_string()));

    // Soft-deleted accounts (status `deleted`) are treated the same.
    let soft = create_user(&pool).await;
    sqlx::query(
        "UPDATE users SET status = 'deleted', email = NULL, email_normalized = NULL WHERE id = $1",
    )
    .bind(soft)
    .execute(&pool)
    .await
    .unwrap();
    sink.record(login(&h, soft)).await.unwrap();
    let mapped: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_subjects WHERE user_id = $1")
        .bind(soft)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(mapped, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_retention_purge_deletes_old_prefix_with_checkpoint(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    let old = record_n(&sink, &h, user, 5).await;
    h.ports.clock.advance(DAY * 500);
    let recent = record_n(&sink, &h, user, 3).await;
    let last_old = seq_of(&pool, &old[4]).await;

    let report = purge_expired(&pool, h.ports.clock.as_ref(), DAY * 400)
        .await
        .unwrap();
    assert_eq!(report.events_deleted, 5);
    let checkpoint = report.checkpoint.unwrap();
    assert_eq!(checkpoint.seq, last_old);

    let remaining: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM audit_events ORDER BY seq")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(
        remaining,
        recent.iter().map(|e| e.id.as_uuid()).collect::<Vec<_>>()
    );
    let pii: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_event_pii")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pii, 3, "personal data of purged events is gone");
    let (reason, hash): (String, Vec<u8>) =
        sqlx::query_as("SELECT reason, hash FROM audit_chain_checkpoints WHERE seq = $1")
            .bind(checkpoint.seq)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason, "retention_purge");
    assert_eq!(hash, checkpoint.hash.to_vec());
    let verified = verify_chain(&pool).await.unwrap();
    assert!(verified.is_intact(), "{verified:?}");
    assert_eq!(verified.start, checkpoint);
    assert_eq!(verified.events_verified, 3);

    // Nothing left to purge; new events still chain onto the checkpointed
    // history.
    let again = purge_expired(&pool, h.ports.clock.as_ref(), DAY * 400)
        .await
        .unwrap();
    assert_eq!(again.events_deleted, 0);
    record_n(&sink, &h, user, 1).await;
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_retention_purge_never_leaves_holes_and_batches(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    let start = h.now();
    let e1 = login(&h, user);
    sink.record(e1.clone()).await.unwrap();
    // A young event recorded before a back-dated one blocks the purge of
    // everything after it.
    let mut young = login(&h, user);
    young.occurred_at = start + DAY * 600;
    sink.record(young.clone()).await.unwrap();
    let mut backdated = login(&h, user);
    backdated.occurred_at = start + DAY;
    sink.record(backdated.clone()).await.unwrap();

    let report = purge_before(&pool, start + DAY * 300, 1, start + DAY * 700)
        .await
        .unwrap();
    assert_eq!(report.events_deleted, 1);
    let remaining: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM audit_events ORDER BY seq")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, vec![young.id.as_uuid(), backdated.id.as_uuid()]);
    assert!(verify_chain(&pool).await.unwrap().is_intact());

    // Batches of one event each: several checkpoints, chain still intact.
    let more = record_n(&sink, &h, user, 0).await;
    assert!(more.is_empty());
    let report = purge_before(&pool, start + DAY * 900, 1, start + DAY * 1000)
        .await
        .unwrap();
    assert_eq!(report.events_deleted, 2);
    let checkpoints: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_chain_checkpoints")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(checkpoints, 3);
    let report = verify_chain(&pool).await.unwrap();
    assert!(report.is_intact(), "{report:?}");
    assert_eq!(report.events_verified, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_retention_purge_refuses_a_tampered_segment(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    let old = record_n(&sink, &h, user, 3).await;
    tamper(
        &pool,
        "UPDATE audit_events SET reason = 'covered_up' WHERE id = $1",
        old[1].id.as_uuid(),
    )
    .await;
    h.ports.clock.advance(DAY * 500);
    assert!(
        purge_expired(&pool, h.ports.clock.as_ref(), DAY * 400)
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 3, "evidence is not purged");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_least_privilege_roles_cannot_rewrite_history(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let events = record_n(&h.service.sink(), &h, user, 1).await;
    let suffix = Uuid::now_v7().simple().to_string();
    let app = format!("authn_app_{}", suffix.get(20..).unwrap());
    let maint = format!("authn_maint_{}", suffix.get(20..).unwrap());
    for role in [&app, &maint] {
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} NOLOGIN")))
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("SELECT authn_audit_apply_least_privilege($1, $2)")
        .bind(&app)
        .bind(&maint)
        .execute(&pool)
        .await
        .unwrap();

    for sql in [
        "UPDATE audit_events SET kind = 'logout'",
        "DELETE FROM audit_events",
    ] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {app}")))
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("SELECT set_config('authn.audit_purge_before', '2100-01-01T00:00:00Z', true)")
            .execute(&mut *tx)
            .await
            .unwrap();
        let err = sqlx::query(sql).execute(&mut *tx).await.unwrap_err();
        assert!(
            err.to_string().contains("permission denied"),
            "{sql}: {err}"
        );
    }

    // The maintenance role may purge through the hatch only.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {maint}")))
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE audit_events SET kind = 'logout'")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    drop(tx);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {maint}")))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SELECT set_config('authn.audit_purge_before', '2100-01-01T00:00:00Z', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let deleted = sqlx::query("DELETE FROM audit_events WHERE id = $1")
        .bind(events[0].id)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(deleted.rows_affected(), 1);
    tx.rollback().await.unwrap();

    for role in [&app, &maint] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role}")))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
            .execute(&pool)
            .await
            .unwrap();
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_empty_chain_verifies_and_timestamps_round_trip(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let report = verify_chain(&pool).await.unwrap();
    assert!(report.is_intact());
    assert_eq!(report.head, ChainAnchor::GENESIS);
    // Nanosecond timestamps are truncated consistently (hash = stored value).
    let user = create_user(&pool).await;
    let mut event = login(&h, user);
    event.occurred_at =
        OffsetDateTime::from_unix_timestamp_nanos(1_800_000_000_123_456_789).unwrap();
    h.service.sink().record(event).await.unwrap();
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

/// Every textual form of `user` that must never appear in the chain or in
/// the personal-data table.
fn id_forms(user: UserId) -> [String; 2] {
    [user.to_string(), user.as_uuid().simple().to_string()]
}

async fn chain_and_pii_text(pool: &PgPool) -> String {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM audit_events t \
         UNION ALL SELECT row_to_json(p)::text FROM audit_event_pii p",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    rows.join("\n")
}

/// Security review: a user id embedded in a longer string (`Debug` output
/// of a typed id, URN, braces, simple form) used to be stored verbatim in
/// the immutable chain, where account deletion can never remove it.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_embedded_user_ids_never_reach_the_chain(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let admin = create_user(&pool).await;
    let user = create_user(&pool).await;
    let event = SecurityEvent::new(SecurityEventKind::MemberRemoved, h.now())
        .with_actor(Actor::User(admin))
        .with_resource("membership", format!("{user:?}"))
        .with_meta("target", format!("{user:?}"))
        .with_meta("urn", format!("urn:uuid:{user}"))
        .with_meta("braced", format!("{{{user}}}"))
        .with_meta("path", format!("users/{user}/sessions"))
        .with_meta("simple", format!("u{}", user.as_uuid().simple()))
        .with_meta(&format!("u_{}", user.as_uuid().simple()), 1)
        .failed(format!("gone_{}", user.as_uuid().simple()));
    h.service.sink().record(event.clone()).await.unwrap();

    let text = chain_and_pii_text(&pool).await;
    for form in id_forms(user) {
        assert!(!text.contains(&form), "{form} leaked: {text}");
    }
    let (reason, resource_id, metadata): (String, String, Value) =
        sqlx::query_as("SELECT reason, resource_id, metadata FROM audit_events WHERE id = $1")
            .bind(event.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason, "invalid_reason");
    assert_eq!(resource_id, "[REDACTED]");
    for key in ["target", "urn", "braced", "path", "simple"] {
        assert_eq!(metadata[key], "[REDACTED]", "{key}");
    }
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

/// Security review: user ids of accounts that no longer exist were kept
/// verbatim when they appeared in metadata or as a `user` resource (only
/// existing users were recognised as user ids).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_references_to_deleted_accounts_are_pseudonymised(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let admin = create_user(&pool).await;
    let gone = create_user(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        authn_store::UserRepository::delete(&mut conn, gone)
            .await
            .unwrap()
    );
    drop(conn);
    let event = SecurityEvent::new(SecurityEventKind::MemberRemoved, h.now())
        .with_actor(Actor::User(admin))
        .with_resource("user", gone)
        .with_meta("removed_user_id", gone.to_string())
        .with_meta("previous_owner", gone.to_string())
        .with_meta("affected", json!({"target_user_ids": [gone.to_string()]}));
    h.service.sink().record(event.clone()).await.unwrap();

    let text = chain_and_pii_text(&pool).await;
    assert!(!text.contains(&gone.to_string()), "{text}");
    let (resource_id, metadata): (String, Value) =
        sqlx::query_as("SELECT resource_id, metadata FROM audit_events WHERE id = $1")
            .bind(event.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    // One consistent one-off pseudonym within the event, not stored anywhere.
    assert_eq!(metadata["removed_user_id"], resource_id.as_str());
    assert_eq!(metadata["previous_owner"], resource_id.as_str());
    assert_eq!(
        metadata["affected"]["target_user_ids"][0],
        resource_id.as_str()
    );
    let mapped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_subjects WHERE pseudonym::text = $1")
            .bind(&resource_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(mapped, 0);
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

/// Security review: only the first 128 distinct UUIDs of an event are
/// checked for being user ids; the rest used to be stored unchecked (a user
/// id among them stayed verbatim). They are redacted now (fail closed).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_identifiers_beyond_the_per_event_limit_are_redacted(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let mut event = SecurityEvent::new(SecurityEventKind::SessionsRevoked, h.now());
    let mut n: u128 = 1;
    for group in 0..5 {
        let mut ids: Vec<String> = Vec::new();
        for _ in 0..32 {
            ids.push(Uuid::from_u128(n).to_string());
            n += 1;
        }
        if group == 4 {
            // Sorts after every small id above.
            *ids.last_mut().unwrap() = user.to_string();
        }
        event = event.with_meta(&format!("batch{group}"), ids);
    }
    h.service.sink().record(event.clone()).await.unwrap();

    let text = chain_and_pii_text(&pool).await;
    assert!(
        !text.contains(&user.to_string()),
        "user id stored unchecked"
    );
    let metadata: Value = sqlx::query_scalar("SELECT metadata FROM audit_events WHERE id = $1")
        .bind(event.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(metadata["batch4"][31], "[REDACTED]");
    // The checked ones are kept (they are no user ids).
    assert_eq!(metadata["batch0"][0], Uuid::from_u128(1).to_string());
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

/// Security review: a user whose account is `deleted` (anonymised row kept)
/// but whose mapping was not removed kept being linked and had new personal
/// data stored, contrary to AUD-05.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_deleted_status_account_is_never_linked_again(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let sink = h.service.sink();
    let user = create_user(&pool).await;
    record_n(&sink, &h, user, 1).await;
    let mapping: Uuid =
        sqlx::query_scalar("SELECT pseudonym FROM audit_subjects WHERE user_id = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE users SET status = 'deleted', email = NULL, email_normalized = NULL WHERE id = $1",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let late = login(&h, user);
    sink.record(late.clone()).await.unwrap();
    let (subject, pii): (Uuid, i64) = sqlx::query_as(
        "SELECT e.subject_pseudonym, (SELECT count(*) FROM audit_event_pii p WHERE p.event_id = e.id) \
         FROM audit_events e WHERE e.id = $1",
    )
    .bind(late.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(subject, mapping, "deleted account linked to its history");
    assert_eq!(pii, 0, "personal data of a deleted account stored");
    assert!(verify_chain(&pool).await.unwrap().is_intact());
}

/// Security review: the least-privilege helper only revoked privileges on
/// `audit_events` / `audit_chain_checkpoints`; an application role that had
/// broader grants before kept e.g. UPDATE on `audit_subjects` (silently
/// re-attributing history) and TRUNCATE on `audit_chain_head`.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_02_least_privilege_helper_revokes_previous_broad_grants(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 1).await;
    let suffix = Uuid::now_v7().simple().to_string();
    let app = format!("authn_app_wide_{}", suffix.get(20..).unwrap());
    let maint = format!("authn_maint_wide_{}", suffix.get(20..).unwrap());
    for role in [&app, &maint] {
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} NOLOGIN")))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "GRANT ALL ON ALL TABLES IN SCHEMA public TO {role}"
        )))
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("SELECT authn_audit_apply_least_privilege($1, $2)")
        .bind(&app)
        .bind(&maint)
        .execute(&pool)
        .await
        .unwrap();

    for (role, sql) in [
        (&app, "UPDATE audit_subjects SET created_at = created_at"),
        (&app, "UPDATE audit_event_pii SET pseudonym = NULL"),
        (&app, "DELETE FROM audit_chain_head"),
        (&app, "TRUNCATE audit_chain_head"),
        (&app, "TRUNCATE audit_subjects CASCADE"),
        (
            &app,
            "INSERT INTO audit_chain_checkpoints (seq, hash, reason) VALUES (0, decode(repeat('00', 32), 'hex'), 'manual')",
        ),
        (&maint, "UPDATE audit_subjects SET created_at = created_at"),
        (&maint, "UPDATE audit_chain_head SET last_seq = 0"),
        (
            &maint,
            "INSERT INTO audit_events (id) VALUES (gen_random_uuid())",
        ),
    ] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {role}")))
            .execute(&mut *tx)
            .await
            .unwrap();
        let err = sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("permission denied"),
            "{role}: {sql}: {err}"
        );
    }

    // The application role can still append (and pseudonymise).
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {app}")))
        .execute(&mut *tx)
        .await
        .unwrap();
    h.service
        .sink()
        .record_in_tx(&mut tx, login(&h, user))
        .await
        .unwrap();
    h.service
        .sink()
        .pseudonymize_subject(&mut tx, user)
        .await
        .unwrap();
    tx.rollback().await.unwrap();

    for role in [&app, &maint] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role}")))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
            .execute(&pool)
            .await
            .unwrap();
    }
}
