#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Keyed audit hash chain (AUD-02, K-77) against real PostgreSQL.
//!
//! The attacker model: full write access to the database (triggers can be
//! disabled, every table rewritten), but no access to `crypto.hmac_root_key`.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use authn_audit::chain::{ChainRecord, GENESIS_HASH};
use authn_audit::{ChainKeys, ChainProblem, ChainReport, PgAuditSink, verify_chain};
use authn_core::config::audit::{AuditChainConfig, AuditConfig};
use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, SecurityEvent, SecurityEventKind};
use authn_crypto::kdf::KeyRing;
use common::{Harness, create_user};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

fn ring() -> KeyRing {
    KeyRing::from_config(&authn_testkit::config::test_config().crypto).unwrap()
}

fn keys_v(version: u16) -> ChainKeys {
    ChainKeys::from_config(
        &ring(),
        &AuditChainConfig {
            key_version: version,
            legacy_until_seq: None,
        },
    )
    .unwrap()
}

fn config_v(version: u16) -> AuditConfig {
    AuditConfig {
        chain: AuditChainConfig {
            key_version: version,
            legacy_until_seq: None,
        },
        ..AuditConfig::default()
    }
}

fn login(h: &Harness, user: UserId) -> SecurityEvent {
    SecurityEvent::new(SecurityEventKind::LoginSucceeded, h.now())
        .with_actor(Actor::User(user))
        .with_subject(user)
        .with_meta("method", "password")
}

async fn record_n(sink: &PgAuditSink, h: &Harness, user: UserId, n: usize) {
    for _ in 0..n {
        sink.record(login(h, user)).await.unwrap();
    }
}

async fn verify(pool: &PgPool, keys: &ChainKeys) -> ChainReport {
    verify_chain(pool, keys).await.unwrap()
}

fn problem(report: &ChainReport) -> (i64, ChainProblem) {
    let broken = report.broken.expect("chain must be broken");
    (broken.seq, broken.problem)
}

#[derive(sqlx::FromRow)]
struct Row {
    seq: i64,
    id: Uuid,
    occurred_at: OffsetDateTime,
    recorded_at: OffsetDateTime,
    kind: String,
    outcome: String,
    reason: Option<String>,
    actor_type: String,
    actor_pseudonym: Option<Uuid>,
    actor_ref: Option<Uuid>,
    impersonator_pseudonym: Option<Uuid>,
    subject_pseudonym: Option<Uuid>,
    org_id: Option<Uuid>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_id: Option<Uuid>,
    metadata: sqlx::types::Json<Value>,
    pii_digest: Option<Vec<u8>>,
    hash: Vec<u8>,
    chain_key_version: Option<i16>,
}

impl Row {
    fn record(&self) -> ChainRecord {
        ChainRecord {
            id: self.id,
            occurred_at: self.occurred_at,
            recorded_at: self.recorded_at,
            kind: self.kind.clone(),
            outcome: self.outcome.clone(),
            reason: self.reason.clone(),
            actor_type: self.actor_type.clone(),
            actor_pseudonym: self.actor_pseudonym,
            actor_ref: self.actor_ref,
            impersonator_pseudonym: self.impersonator_pseudonym,
            subject_pseudonym: self.subject_pseudonym,
            org_id: self.org_id,
            resource_type: self.resource_type.clone(),
            resource_id: self.resource_id.clone(),
            request_id: self.request_id,
            metadata: self.metadata.0.as_object().unwrap().clone(),
            pii_digest: self.pii_digest.as_deref().map(|d| d.try_into().unwrap()),
        }
    }
}

async fn rows(pool: &PgPool) -> Vec<Row> {
    sqlx::query_as(
        "SELECT seq, id, occurred_at, recorded_at, kind, outcome, reason, actor_type, \
         actor_pseudonym, actor_ref, impersonator_pseudonym, subject_pseudonym, org_id, \
         resource_type, resource_id, request_id, metadata, pii_digest, hash, chain_key_version \
         FROM audit_events ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// How the forger re-hashes the rows it rewrites.
#[derive(Clone, Copy)]
enum Rehash<'a> {
    /// The unkeyed rule (SHA-256), keeping the stored key version.
    Sha256KeepVersion,
    /// The unkeyed rule, marking the rows as legacy (`chain_key_version`
    /// NULL) — the downgrade a forger without the key would try.
    Sha256AsLegacy,
    /// HMAC with a key the forger guessed or obtained.
    Hmac(&'a authn_crypto::kdf::HmacKey, i16),
}

/// The attacker: turns the event at `from_seq` into a failed login and
/// recomputes every hash from there to the head (append-only trigger
/// disabled), then rewinds the head onto the forged chain.
async fn forge(pool: &PgPool, from_seq: i64, rehash: Rehash<'_>) {
    let all = rows(pool).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only")
        .execute(&mut *tx)
        .await
        .unwrap();
    let mut prev = GENESIS_HASH;
    let mut last_version = None;
    for row in &all {
        if row.seq < from_seq {
            prev = row.hash.as_slice().try_into().unwrap();
            last_version = row.chain_key_version;
            continue;
        }
        let mut record = row.record();
        if row.seq == from_seq {
            record.kind = "login.failed".into();
            record.outcome = "failure".into();
        }
        let (hash, version) = match rehash {
            Rehash::Sha256KeepVersion => (record.hash(&prev).unwrap(), row.chain_key_version),
            Rehash::Sha256AsLegacy => (record.hash(&prev).unwrap(), None),
            Rehash::Hmac(key, v) => (record.keyed_hash(key, &prev).unwrap(), Some(v)),
        };
        sqlx::query(
            "UPDATE audit_events SET kind = $2, outcome = $3, prev_hash = $4, hash = $5, \
             chain_key_version = $6 WHERE seq = $1",
        )
        .bind(row.seq)
        .bind(&record.kind)
        .bind(&record.outcome)
        .bind(prev.as_slice())
        .bind(hash.as_slice())
        .bind(version)
        .execute(&mut *tx)
        .await
        .unwrap();
        prev = hash;
        last_version = version;
    }
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_chain_head SET last_hash = $1, key_version = $2 WHERE id")
        .bind(prev.as_slice())
        .bind(last_version)
        .execute(&mut *tx)
        .await
        .unwrap();
    // The forger also fixes up every checkpoint it can see.
    sqlx::query(
        "UPDATE audit_chain_checkpoints c SET hash = e.hash FROM audit_events e WHERE e.seq = c.seq",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn switch_checkpoints(pool: &PgPool) -> Vec<(i64, i16)> {
    sqlx::query_as(
        "SELECT seq, key_version FROM audit_chain_checkpoints \
         WHERE reason = 'chain_key_switch' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn versions(pool: &PgPool) -> Vec<Option<i16>> {
    rows(pool)
        .await
        .into_iter()
        .map(|r| r.chain_key_version)
        .collect()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_new_events_are_hmac_chained_and_the_switch_is_checkpointed(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 3).await;

    assert_eq!(versions(&pool).await, vec![Some(1); 3]);
    assert_eq!(switch_checkpoints(&pool).await, vec![(1, 1)]);
    let head_version: Option<i16> =
        sqlx::query_scalar("SELECT key_version FROM audit_chain_head WHERE id")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(head_version, Some(1));

    // The stored hash is HMAC-SHA-256 under key v1, not SHA-256.
    let stored = rows(&pool).await;
    let key = ring().audit_chain_keys().unwrap().version(1).unwrap();
    let first = &stored[0];
    assert_eq!(
        first.hash,
        first.record().keyed_hash(&key, &GENESIS_HASH).unwrap()
    );
    assert_ne!(first.hash, first.record().hash(&GENESIS_HASH).unwrap());

    let report = verify(&pool, h.keys()).await;
    assert!(report.is_intact(), "{report:?}");
    assert_eq!(report.events_verified, 3);
    assert_eq!(report.legacy_events, 0);
    assert_eq!(report.keyed_from_seq, Some(1));
    assert_eq!(report.head_key_version, Some(1));
}

/// The baseline the fix is measured against: with the unkeyed (pre-K-77)
/// scheme, the very same forgery produces a chain that verifies.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_forgery_succeeds_against_the_old_unkeyed_scheme(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let legacy = PgAuditSink::new(pool.clone(), h.clock());
    record_n(&legacy, &h, user, 4).await;
    assert_eq!(versions(&pool).await, vec![None; 4]);
    assert!(verify(&pool, h.keys()).await.is_intact());

    forge(&pool, 2, Rehash::Sha256KeepVersion).await;
    let forged = rows(&pool).await;
    assert_eq!(forged[1].kind, "login.failed", "history was rewritten");
    let report = verify(&pool, h.keys()).await;
    assert!(
        report.is_intact(),
        "the unkeyed chain cannot tell a recomputed chain from the original: {report:?}"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_forger_without_the_key_cannot_recompute_the_chain(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 4).await;
    assert!(verify(&pool, h.keys()).await.is_intact());

    forge(&pool, 2, Rehash::Sha256KeepVersion).await;
    assert_eq!(rows(&pool).await[1].kind, "login.failed");
    assert_eq!(
        problem(&verify(&pool, h.keys()).await),
        (2, ChainProblem::HashMismatch)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_forger_with_a_wrong_key_cannot_recompute_the_chain(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 3).await;

    // A key derived from another root (e.g. a guessed or a test root).
    let wrong = KeyRing::derive(&[0x5a; 32])
        .unwrap()
        .audit_chain_keys()
        .unwrap()
        .version(1)
        .unwrap();
    forge(&pool, 1, Rehash::Hmac(&wrong, 1)).await;
    assert_eq!(
        problem(&verify(&pool, h.keys()).await),
        (1, ChainProblem::HashMismatch)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_verifier_with_the_wrong_key_rejects_a_genuine_chain(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 2).await;
    let wrong = ChainKeys::new(
        KeyRing::derive(&[0x11; 32])
            .unwrap()
            .audit_chain_keys()
            .unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(
        problem(&verify(&pool, &wrong).await),
        (1, ChainProblem::HashMismatch)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_downgrading_keyed_events_to_the_unkeyed_rule_is_detected(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 4).await;

    // Rewriting from the middle: an unkeyed event after a keyed one.
    forge(&pool, 3, Rehash::Sha256AsLegacy).await;
    assert_eq!(
        problem(&verify(&pool, h.keys()).await),
        (3, ChainProblem::KeyDowngrade)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_rewriting_the_whole_chain_as_legacy_is_detected(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 3).await;

    // Every event rewritten in the unkeyed form; the switch checkpoint
    // (which the forger cannot recompute) still marks seq 1 as keyed.
    forge(&pool, 1, Rehash::Sha256AsLegacy).await;
    assert_eq!(
        problem(&verify(&pool, h.keys()).await),
        (1, ChainProblem::UnkeyedEvent)
    );

    // The forger also deletes the switch checkpoint: the database alone no
    // longer shows that the chain was keyed (the report flags the unkeyed
    // events) — the operator's pin outside the database does.
    sqlx::query("DELETE FROM audit_chain_checkpoints WHERE reason = 'chain_key_switch'")
        .execute(&pool)
        .await
        .unwrap();
    let unpinned = verify(&pool, h.keys()).await;
    assert!(unpinned.is_intact(), "{unpinned:?}");
    assert_eq!(unpinned.legacy_events, 3);
    assert_eq!(unpinned.keyed_from_seq, None);
    let pinned = h.keys().clone().with_legacy_until_seq(Some(0));
    assert_eq!(
        problem(&verify(&pool, &pinned).await),
        (1, ChainProblem::UnkeyedEvent)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_legacy_and_keyed_mixed_chain_verifies(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    // Before the upgrade: unkeyed events.
    let legacy = PgAuditSink::new(pool.clone(), h.clock());
    record_n(&legacy, &h, user, 3).await;
    assert!(switch_checkpoints(&pool).await.is_empty());

    // The upgraded server starts: the switch event is the first keyed one.
    let activation = h.service.activate_chain_key().await.unwrap();
    assert_eq!(activation.from_version, None);
    assert_eq!(activation.to_version, 1);
    let switch = activation.switch.unwrap();
    assert_eq!(switch.seq, 4);
    let kind: String = sqlx::query_scalar("SELECT kind FROM audit_events WHERE seq = 4")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kind, "audit.chain_key_rotated");
    assert_eq!(switch_checkpoints(&pool).await, vec![(4, 1)]);
    // Idempotent.
    assert_eq!(h.service.activate_chain_key().await.unwrap().switch, None);
    record_n(&h.service.sink(), &h, user, 2).await;
    assert_eq!(
        versions(&pool).await,
        vec![None, None, None, Some(1), Some(1), Some(1)]
    );

    let report = verify(&pool, h.keys()).await;
    assert!(report.is_intact(), "{report:?}");
    assert_eq!(report.events_verified, 6);
    assert_eq!(report.legacy_events, 3);
    assert_eq!(report.keyed_from_seq, Some(4));
    // The operator's pin: exactly the legacy prefix.
    let pinned = h.keys().clone().with_legacy_until_seq(Some(3));
    assert!(verify(&pool, &pinned).await.is_intact());
    let too_strict = h.keys().clone().with_legacy_until_seq(Some(2));
    assert_eq!(
        problem(&verify(&pool, &too_strict).await),
        (3, ChainProblem::UnkeyedEvent)
    );

    // An unkeyed writer can no longer extend the chain.
    assert!(legacy.record(login(&h, user)).await.is_err());
    assert_eq!(versions(&pool).await.len(), 6);

    // Rewriting the legacy prefix breaks the first keyed event: the keyed
    // part protects everything before it too.
    forge(&pool, 2, Rehash::Sha256KeepVersion).await;
    assert_eq!(
        problem(&verify(&pool, h.keys()).await),
        (4, ChainProblem::HashMismatch)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_key_rotation_applies_to_new_events_and_old_ones_still_verify(pool: PgPool) {
    let v1 = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&v1.service.sink(), &v1, user, 2).await;

    // Rotation: the configuration moves to version 2.
    let v2 = Harness::with_config(pool.clone(), &config_v(2));
    let activation = v2.service.activate_chain_key().await.unwrap();
    assert_eq!(activation.from_version, Some(1));
    assert_eq!(activation.to_version, 2);
    assert_eq!(activation.switch.unwrap().seq, 3);
    record_n(&v2.service.sink(), &v2, user, 1).await;
    // An instance still configured with version 1 (rolling restart) never
    // writes below the head's version.
    record_n(&v1.service.sink(), &v1, user, 1).await;
    assert_eq!(
        versions(&pool).await,
        vec![Some(1), Some(1), Some(2), Some(2), Some(2)]
    );
    assert_eq!(switch_checkpoints(&pool).await, vec![(1, 1), (3, 2)]);
    assert_eq!(v1.service.activate_chain_key().await.unwrap().switch, None);

    // Old events keep verifying: every version is derivable.
    for keys in [keys_v(1), keys_v(2), keys_v(7)] {
        let report = verify(&pool, &keys).await;
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.head_key_version, Some(2));
    }

    // Someone holding only the retired v1 key (e.g. leaked) appends a v1
    // event after the rotation: refused as a downgrade.
    let leaked = ring().audit_chain_keys().unwrap().version(1).unwrap();
    let mut forged = rows(&pool).await.pop().unwrap();
    forged.id = Uuid::now_v7();
    let prev: [u8; 32] = forged.hash.as_slice().try_into().unwrap();
    let hash = forged.record().keyed_hash(&leaked, &prev).unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO audit_events (id, occurred_at, recorded_at, kind, outcome, actor_type, \
         actor_pseudonym, subject_pseudonym, metadata, prev_hash, hash, chain_key_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 1)",
    )
    .bind(forged.id)
    .bind(forged.occurred_at)
    .bind(forged.recorded_at)
    .bind(&forged.kind)
    .bind(&forged.outcome)
    .bind(&forged.actor_type)
    .bind(forged.actor_pseudonym)
    .bind(forged.subject_pseudonym)
    .bind(&forged.metadata)
    .bind(prev.as_slice())
    .bind(hash.as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE audit_chain_head SET last_seq = (SELECT max(seq) FROM audit_events), \
         last_hash = $1 WHERE id",
    )
    .bind(hash.as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        problem(&verify(&pool, &keys_v(2)).await),
        (6, ChainProblem::KeyDowngrade)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_removed_key_switch_checkpoint_is_detected(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 2).await;
    let v2 = Harness::with_config(pool.clone(), &config_v(2));
    record_n(&v2.service.sink(), &v2, user, 1).await;
    assert_eq!(switch_checkpoints(&pool).await, vec![(1, 1), (3, 2)]);

    sqlx::query("DELETE FROM audit_chain_checkpoints WHERE seq = 3")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        problem(&verify(&pool, h.keys()).await),
        (3, ChainProblem::KeySwitchUnrecorded)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_head_key_version_is_verified(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 2).await;
    sqlx::query("UPDATE audit_chain_head SET key_version = NULL WHERE id")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        problem(&verify(&pool, h.keys()).await).1,
        ChainProblem::HeadMismatch
    );
    // A head reset to unkeyed does not let an unkeyed writer downgrade the
    // chain either: the verifier still sees the unkeyed event after the
    // keyed ones.
    let legacy = PgAuditSink::new(pool.clone(), h.clock());
    legacy.record(login(&h, user)).await.unwrap();
    assert_eq!(
        problem(&verify(&pool, h.keys()).await),
        (3, ChainProblem::KeyDowngrade)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_retention_purge_verifies_keyed_segments(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 3).await;
    h.ports
        .clock
        .advance(std::time::Duration::from_secs(86_400 * 500));
    record_n(&h.service.sink(), &h, user, 1).await;

    // A forged segment is never purged away.
    forge(&pool, 2, Rehash::Sha256KeepVersion).await;
    assert!(
        authn_audit::purge_expired(
            &pool,
            h.keys(),
            h.ports.clock.as_ref(),
            std::time::Duration::from_secs(86_400 * 400),
        )
        .await
        .is_err()
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 4);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_genuine_keyed_chain_survives_retention_purge(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 3).await;
    h.ports
        .clock
        .advance(std::time::Duration::from_secs(86_400 * 500));
    record_n(&h.service.sink(), &h, user, 2).await;
    let report = authn_audit::purge_expired(
        &pool,
        h.keys(),
        h.ports.clock.as_ref(),
        std::time::Duration::from_secs(86_400 * 400),
    )
    .await
    .unwrap();
    assert_eq!(report.events_deleted, 3);
    let verified = verify(&pool, h.keys()).await;
    assert!(verified.is_intact(), "{verified:?}");
    assert_eq!(verified.events_verified, 2);
}

/// A `MakeWriter` collecting everything logged.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_chain_key_never_appears_in_logs_or_debug(pool: PgPool) {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(captured.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let legacy = PgAuditSink::new(pool.clone(), h.clock());
    record_n(&legacy, &h, user, 1).await;
    h.service.activate_chain_key().await.unwrap();
    record_n(&h.service.sink(), &h, user, 2).await;
    let v2 = Harness::with_config(pool.clone(), &config_v(2));
    v2.service.activate_chain_key().await.unwrap();
    assert!(verify(&pool, v2.keys()).await.is_intact());
    forge(&pool, 2, Rehash::Sha256KeepVersion).await;
    assert!(!verify(&pool, v2.keys()).await.is_intact());

    let mut text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("audit chain key version switched"),
        "the switch is logged: {text}"
    );
    text.push_str(&format!(
        "{:?}{:?}{:?}{:?}",
        h.keys(),
        h.service.sink(),
        h.service,
        ring().audit_chain_keys().unwrap()
    ));
    let family = ring().audit_chain_keys().unwrap();
    let base = *ring()
        .key(authn_crypto::kdf::KeyPurpose::AuditChain)
        .unwrap()
        .expose();
    let mut secrets = vec![base];
    for v in 1..=2 {
        secrets.push(*family.version(v).unwrap().expose());
    }
    for secret in secrets {
        let hex = authn_audit::canonical::hex(&secret);
        let b64 = data_encoding_base64(&secret);
        assert!(!text.contains(&hex), "key (hex) leaked");
        assert!(!text.contains(&b64), "key (base64) leaked");
        assert!(!text.contains(&format!("{secret:?}")), "key (bytes) leaked");
    }
}

fn data_encoding_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The `chain_key_switch` trigger function runs with the rights of the
/// table owner (SECURITY DEFINER). Its name lookup must not reach the
/// caller's temporary schema: otherwise the least-privilege application
/// role plants a temporary `audit_chain_checkpoints` table whose trigger
/// then runs arbitrary SQL as the owner (here: a checkpoint the role may not
/// insert itself).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_switch_trigger_cannot_be_hijacked_through_pg_temp(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 1).await;
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
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

    let mut tx = pool.begin().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {app}")))
        .execute(&mut *tx)
        .await
        .unwrap();
    // The application role cannot insert checkpoints itself.
    sqlx::query("SAVEPOINT direct")
        .execute(&mut *tx)
        .await
        .unwrap();
    let direct = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {schema}.audit_chain_checkpoints (seq, hash, reason, created_at) \
         VALUES (999, '\\x00', 'manual', now())"
    )))
    .execute(&mut *tx)
    .await;
    assert!(direct.is_err(), "app role must not insert checkpoints");
    sqlx::query("ROLLBACK TO SAVEPOINT direct")
        .execute(&mut *tx)
        .await
        .unwrap();
    for sql in [
        "CREATE TEMP TABLE audit_chain_checkpoints (seq bigint PRIMARY KEY, hash bytea, reason text, \
         key_version smallint, created_at timestamptz)"
            .to_owned(),
        format!(
            "CREATE FUNCTION pg_temp.k77_hijack() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN INSERT INTO {schema}.audit_chain_checkpoints (seq, hash, reason, created_at) \
             VALUES (NEW.seq + 1000000, NEW.hash, 'manual', NEW.created_at); RETURN NEW; END $$"
        ),
        "CREATE TRIGGER k77_hijack BEFORE INSERT ON pg_temp.audit_chain_checkpoints \
         FOR EACH ROW EXECUTE FUNCTION pg_temp.k77_hijack()"
            .to_owned(),
        "UPDATE audit_chain_head SET last_seq = last_seq + 1, key_version = 2 WHERE id".to_owned(),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let (hijacked, recorded): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FILTER (WHERE reason = 'manual'), \
         count(*) FILTER (WHERE reason = 'chain_key_switch' AND key_version = 2) \
         FROM {schema}.audit_chain_checkpoints"
    )))
    .fetch_one(&mut *tx)
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
    assert_eq!(
        hijacked, 0,
        "code of the app role ran with the owner's rights"
    );
    assert_eq!(recorded, 1, "the switch is recorded in the real table");
}

/// `chain_key_version` is not part of the hashed record. The event at an
/// external anchor is trusted by its hash, so its version column must be
/// authenticated by re-hashing it; otherwise a forger marks the anchor event
/// unkeyed and continues the chain after it with the unkeyed rule.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_anchor_event_key_version_is_authenticated(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    record_n(&h.service.sink(), &h, user, 4).await;
    let anchor_row = rows(&pool).await.into_iter().nth(1).unwrap();
    let anchor = authn_audit::ChainAnchor {
        seq: anchor_row.seq,
        hash: anchor_row.hash.as_slice().try_into().unwrap(),
    };
    assert!(
        authn_audit::verify_chain_from(&pool, h.keys(), anchor)
            .await
            .unwrap()
            .is_intact()
    );

    // The forger rewrites everything after the anchor in the unkeyed form,
    // marks the anchor event itself as unkeyed and drops the switch
    // checkpoints.
    forge(&pool, anchor.seq + 1, Rehash::Sha256AsLegacy).await;
    let mut tx = pool.begin().await.unwrap();
    for sql in [
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only",
        "UPDATE audit_events SET chain_key_version = NULL WHERE seq <= 2",
        "ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only",
        "DELETE FROM audit_chain_checkpoints WHERE reason = 'chain_key_switch'",
    ] {
        sqlx::query(sql).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();

    let report = authn_audit::verify_chain_from(&pool, h.keys(), anchor)
        .await
        .unwrap();
    assert_eq!(
        problem(&report),
        (anchor.seq, ChainProblem::AnchorMismatch),
        "{report:?}"
    );
}

/// A pinned `legacy_until_seq = N` says that the first keyed event is
/// `N + 1`: a chain that ends at or before `N` lost its whole keyed part.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_77_pinned_legacy_prefix_detects_a_truncated_keyed_part(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let user = create_user(&pool).await;
    let legacy = PgAuditSink::new(pool.clone(), h.clock());
    record_n(&legacy, &h, user, 2).await;
    h.service.activate_chain_key().await.unwrap();
    record_n(&h.service.sink(), &h, user, 2).await;
    let pinned = h.keys().clone().with_legacy_until_seq(Some(2));
    assert!(verify(&pool, &pinned).await.is_intact());

    // The forger deletes every keyed event and rewinds the head onto the
    // last unkeyed one.
    let last_legacy = rows(&pool).await.into_iter().nth(1).unwrap();
    let mut tx = pool.begin().await.unwrap();
    for sql in [
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only",
        "DELETE FROM audit_events WHERE seq > 2",
        "ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only",
        "DELETE FROM audit_chain_checkpoints WHERE seq > 2",
    ] {
        sqlx::query(sql).execute(&mut *tx).await.unwrap();
    }
    sqlx::query(
        "UPDATE audit_chain_head SET last_seq = $1, last_hash = $2, key_version = NULL WHERE id",
    )
    .bind(last_legacy.seq)
    .bind(&last_legacy.hash)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        problem(&verify(&pool, &pinned).await),
        (2, ChainProblem::HeadMismatch)
    );
}
