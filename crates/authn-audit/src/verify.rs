//! Chain verification (AUD-02) — the engine behind the
//! `verify-audit-chain` CLI command and the admin endpoint (ADM-07).
//!
//! * [`verify_chain`] — full verification: from the latest retention
//!   checkpoint (or the genesis hash) to the chain head.
//! * [`verify_chain_from`] — from an externally kept [`ChainAnchor`] (a
//!   checkpoint the operator exported, e.g. from the logs).
//!
//! Every event is re-hashed from its stored columns; the verifier checks the
//! `prev_hash` links, the stored hashes, every checkpoint inside the range,
//! the chain head, and the digest of every personal-data row that still
//! exists.
//!
//! Keyed chain (K-77): keyed events are checked with their version's chain
//! key ([`ChainKeys`]), legacy events (`chain_key_version IS NULL`) with
//! the unkeyed rule. A forger without the key could only fall back to the
//! unkeyed rule, so the verifier refuses every fallback it can see:
//!
//! * an unkeyed event, or a lower key version, after a keyed event
//!   ([`ChainProblem::KeyDowngrade`]);
//! * an unkeyed event at or after the first `chain_key_switch` checkpoint,
//!   or after the operator's pinned `audit.chain.legacy_until_seq`
//!   ([`ChainProblem::UnkeyedEvent`]) — the pin, kept outside the database,
//!   also catches a forger who rewrote *every* event into the unkeyed form
//!   and deleted the switch checkpoint;
//! * a change of key version without its `chain_key_switch` checkpoint
//!   ([`ChainProblem::KeySwitchUnrecorded`]);
//! * a head whose key version differs from the last event's.
//!
//! [`ChainReport::legacy_events`] tells how many unkeyed events were
//! accepted. Verification runs in one `REPEATABLE READ` read-only transaction
//! (a consistent snapshot even while events are appended).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use authn_core::error::AuthError;
use serde_json::Value;
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::canonical::hex;
use crate::chain::{self, ChainRecord, GENESIS_HASH};
use crate::keys::{self, ChainKeys, KeyCache};

const BATCH: i64 = 1000;

/// A trusted position of the chain: `(seq, hash)` of one event.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    /// Sequence number of the event (`0` = before the first event).
    pub seq: i64,
    /// Hash of that event (32 zero bytes for `seq = 0`).
    pub hash: [u8; 32],
}

impl ChainAnchor {
    /// The anchor before the first event.
    pub const GENESIS: Self = Self {
        seq: 0,
        hash: GENESIS_HASH,
    };

    /// Hash as lowercase hex (for logs and exports).
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hex(&self.hash)
    }
}

impl std::fmt::Debug for ChainAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainAnchor({}, {})", self.seq, self.hash_hex())
    }
}

/// What is wrong at a position of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainProblem {
    /// `prev_hash` does not equal the previous event's hash (event deleted,
    /// inserted or reordered).
    PrevHashMismatch,
    /// The stored hash does not match the recomputed hash (event modified).
    HashMismatch,
    /// The stored row cannot be canonicalized (modified to an invalid value).
    Malformed,
    /// A checkpoint does not match the event at its position, or its event
    /// is missing.
    CheckpointMismatch,
    /// The chain head does not point at the last event (events removed from
    /// the end, or head modified).
    HeadMismatch,
    /// The event at the anchor's position does not have the anchor's hash.
    AnchorMismatch,
    /// A personal-data row does not match the event's `pii_digest`.
    PiiDigestMismatch,
    /// An unkeyed event, or an older key version, after a keyed event
    /// (K-77: a forger falling back to a rule it can compute).
    KeyDowngrade,
    /// An unkeyed event where only keyed events may be (after the first
    /// `chain_key_switch` checkpoint or the pinned
    /// `audit.chain.legacy_until_seq`, K-77).
    UnkeyedEvent,
    /// The key version changes without a `chain_key_switch` checkpoint at
    /// the first event of the new version (K-77).
    KeySwitchUnrecorded,
}

impl ChainProblem {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::HashMismatch => "hash_mismatch",
            Self::Malformed => "malformed",
            Self::CheckpointMismatch => "checkpoint_mismatch",
            Self::HeadMismatch => "head_mismatch",
            Self::AnchorMismatch => "anchor_mismatch",
            Self::PiiDigestMismatch => "pii_digest_mismatch",
            Self::KeyDowngrade => "key_downgrade",
            Self::UnkeyedEvent => "unkeyed_event",
            Self::KeySwitchUnrecorded => "key_switch_unrecorded",
        }
    }
}

/// The first defect found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainBreak {
    /// Sequence number where the defect was found.
    pub seq: i64,
    /// The defect.
    pub problem: ChainProblem,
}

/// Result of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Where verification started.
    pub start: ChainAnchor,
    /// Last event verified successfully (or `start`).
    pub last_verified: ChainAnchor,
    /// Number of events verified successfully.
    pub events_verified: u64,
    /// The chain head as stored.
    pub head: ChainAnchor,
    /// The first defect, if any.
    pub broken: Option<ChainBreak>,
    /// Unkeyed (legacy SHA-256) events among the verified ones (K-77).
    pub legacy_events: u64,
    /// Sequence number of the first keyed event verified (K-77).
    pub keyed_from_seq: Option<i64>,
    /// Key version recorded at the chain head (`None` = unkeyed).
    pub head_key_version: Option<u16>,
}

impl ChainReport {
    /// Whether no defect was found.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.broken.is_none()
    }
}

/// Columns of [`ChainRow`] (static SQL).
macro_rules! chain_row_select {
    () => {
        "SELECT e.seq, e.id, e.occurred_at, e.recorded_at, e.kind, e.outcome, e.reason, \
         e.actor_type, e.actor_pseudonym, e.actor_ref, e.impersonator_pseudonym, \
         e.subject_pseudonym, e.org_id, e.resource_type, e.resource_id, e.request_id, \
         e.metadata, e.pii_digest, e.prev_hash, e.hash, e.chain_key_version, \
         p.ip AS pii_ip, p.user_agent AS pii_user_agent, p.salt AS pii_salt \
         FROM audit_events e LEFT JOIN audit_event_pii p ON p.event_id = e.id"
    };
}

#[derive(sqlx::FromRow)]
struct ChainRow {
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
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
    pii_ip: Option<IpAddr>,
    pii_user_agent: Option<String>,
    pii_salt: Option<Vec<u8>>,
    chain_key_version: Option<i16>,
}

impl ChainRow {
    fn record(&self) -> Option<ChainRecord> {
        let Value::Object(metadata) = self.metadata.0.clone() else {
            return None;
        };
        let pii_digest = match &self.pii_digest {
            Some(bytes) => Some(chain::hash_from_slice(bytes)?),
            None => None,
        };
        Some(ChainRecord {
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
            metadata,
            pii_digest,
        })
    }
}

/// Reads the chain head and its key version.
pub(crate) async fn read_head(
    conn: &mut PgConnection,
) -> Result<(ChainAnchor, Option<i16>), AuthError> {
    let (seq, hash, key_version): (i64, Vec<u8>, Option<i16>) =
        sqlx::query_as("SELECT last_seq, last_hash, key_version FROM audit_chain_head WHERE id")
            .fetch_one(&mut *conn)
            .await?;
    let hash = chain::hash_from_slice(&hash)
        .ok_or_else(|| AuthError::internal("audit chain head hash is malformed"))?;
    Ok((ChainAnchor { seq, hash }, key_version))
}

/// Where the stored chain starts: the newest checkpoint *before* the oldest
/// remaining event (written by the retention purge), or genesis.
pub(crate) async fn retention_start(conn: &mut PgConnection) -> Result<ChainAnchor, AuthError> {
    let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, hash FROM audit_chain_checkpoints \
         WHERE seq < coalesce((SELECT min(seq) FROM audit_events), \
                              (SELECT last_seq + 1 FROM audit_chain_head WHERE id)) \
         ORDER BY seq DESC LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        None => Ok(ChainAnchor::GENESIS),
        Some((seq, hash)) => Ok(ChainAnchor {
            seq,
            hash: chain::hash_from_slice(&hash)
                .ok_or_else(|| AuthError::internal("audit checkpoint hash is malformed"))?,
        }),
    }
}

/// Full verification from the latest retention checkpoint (or genesis).
pub async fn verify_chain(pool: &PgPool, keys: &ChainKeys) -> Result<ChainReport, AuthError> {
    let mut tx = begin_snapshot(pool).await?;
    let start = retention_start(&mut tx).await?;
    let report = verify_range(&mut tx, keys, start, None, true).await?;
    tx.commit().await?;
    log_report(&report);
    Ok(report)
}

/// Verification starting after an externally kept anchor.
///
/// Anchors older than the latest retention purge cannot be verified (their
/// successors were deleted): take a new anchor after each purge (the purge
/// logs its checkpoint).
pub async fn verify_chain_from(
    pool: &PgPool,
    keys: &ChainKeys,
    anchor: ChainAnchor,
) -> Result<ChainReport, AuthError> {
    let mut tx = begin_snapshot(pool).await?;
    let report = verify_range(&mut tx, keys, anchor, None, true).await?;
    tx.commit().await?;
    log_report(&report);
    Ok(report)
}

async fn begin_snapshot(
    pool: &PgPool,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, AuthError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

fn log_report(report: &ChainReport) {
    match report.broken {
        None if report.legacy_events > 0 => tracing::warn!(
            events = report.events_verified,
            legacy_events = report.legacy_events,
            keyed_from_seq = report.keyed_from_seq,
            head_seq = report.head.seq,
            head_hash = %report.head.hash_hex(),
            "audit chain verified; it contains unkeyed (legacy SHA-256) events: pin audit.chain.legacy_until_seq"
        ),
        None => tracing::info!(
            events = report.events_verified,
            head_seq = report.head.seq,
            head_hash = %report.head.hash_hex(),
            "audit chain verified"
        ),
        Some(b) => tracing::error!(
            seq = b.seq,
            problem = b.problem.as_str(),
            events = report.events_verified,
            "audit chain verification FAILED"
        ),
    }
}

/// What is known about the key version of the event before the current one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrevVersion {
    /// The previous event is gone (retention purge): no downgrade or switch
    /// check for the first event.
    Unknown,
    /// Genesis or an unkeyed event.
    Legacy,
    /// A keyed event of this version.
    Keyed(u16),
}

impl PrevVersion {
    fn from_db(version: Option<i16>) -> Option<Self> {
        match version {
            None => Some(Self::Legacy),
            Some(v) => keys::version_from_db(v).map(Self::Keyed),
        }
    }
}

struct Checkpoint {
    hash: Vec<u8>,
    key_switch: bool,
}

struct RangeRules<'a> {
    keys: &'a ChainKeys,
    cache: KeyCache,
    checkpoints: BTreeMap<i64, Checkpoint>,
    /// Unkeyed events with a larger `seq` are refused.
    legacy_limit: Option<i64>,
}

/// Verifies the events after `start` up to `until` (inclusive; `None` = to
/// the end). With `check_head`, the head must point at the last event.
pub(crate) async fn verify_range(
    conn: &mut PgConnection,
    keys: &ChainKeys,
    start: ChainAnchor,
    until: Option<i64>,
    check_head: bool,
) -> Result<ChainReport, AuthError> {
    let (head, head_version) = read_head(conn).await?;
    let mut report = ChainReport {
        start,
        last_verified: start,
        events_verified: 0,
        head,
        broken: None,
        legacy_events: 0,
        keyed_from_seq: None,
        head_key_version: head_version.and_then(keys::version_from_db),
    };

    // The event at the anchor itself must carry the anchor's hash (when it
    // still exists).
    let mut prev_version = PrevVersion::Legacy;
    let mut cache = KeyCache::default();
    if start.seq > 0 {
        let at_anchor: Option<ChainRow> =
            sqlx::query_as(concat!(chain_row_select!(), " WHERE e.seq = $1"))
                .bind(start.seq)
                .fetch_optional(&mut *conn)
                .await?;
        prev_version = PrevVersion::Unknown;
        if let Some(row) = at_anchor {
            // The anchor vouches for the event's hash only. Its key version
            // is not part of the hashed record, so it is authenticated by
            // re-hashing the event under that version (K-77): a forger
            // cannot mark a keyed anchor event as unkeyed to continue the
            // chain after it with the unkeyed rule.
            match anchor_version(&row, &start, keys, &mut cache)? {
                Some(version) => prev_version = version,
                None => {
                    report.broken = Some(ChainBreak {
                        seq: start.seq,
                        problem: ChainProblem::AnchorMismatch,
                    });
                    return Ok(report);
                }
            }
        }
    }

    let checkpoints: BTreeMap<i64, Checkpoint> = sqlx::query_as::<_, (i64, Vec<u8>, String)>(
        "SELECT seq, hash, reason FROM audit_chain_checkpoints \
             WHERE seq > $1 AND ($2::bigint IS NULL OR seq <= $2) ORDER BY seq",
    )
    .bind(start.seq)
    .bind(until)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|(seq, hash, reason)| {
        (
            seq,
            Checkpoint {
                hash,
                key_switch: reason == "chain_key_switch",
            },
        )
    })
    .collect();
    // No unkeyed event at or after the first key switch the database has
    // ever recorded, nor after the operator's pin.
    let first_switch: Option<i64> = sqlx::query_scalar(
        "SELECT min(seq) FROM audit_chain_checkpoints WHERE reason = 'chain_key_switch'",
    )
    .fetch_one(&mut *conn)
    .await?;
    let legacy_limit = match (first_switch.map(|s| s - 1), keys.legacy_until_seq()) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let mut rules = RangeRules {
        keys,
        cache,
        checkpoints,
        legacy_limit,
    };
    let mut matched_checkpoints = BTreeSet::new();

    let mut prev = start;
    loop {
        let rows: Vec<ChainRow> = sqlx::query_as(concat!(
            chain_row_select!(),
            " WHERE e.seq > $1 AND ($2::bigint IS NULL OR e.seq <= $2) ORDER BY e.seq LIMIT $3"
        ))
        .bind(prev.seq)
        .bind(until)
        .bind(BATCH)
        .fetch_all(&mut *conn)
        .await?;
        let fetched = rows.len();
        for row in rows {
            let version = match check_row(&row, &prev, prev_version, &mut rules)? {
                Ok(version) => version,
                Err(problem) => {
                    report.broken = Some(ChainBreak {
                        seq: row.seq,
                        problem,
                    });
                    return Ok(report);
                }
            };
            if rules.checkpoints.contains_key(&row.seq) {
                matched_checkpoints.insert(row.seq);
            }
            match version {
                PrevVersion::Keyed(_) => {
                    report.keyed_from_seq.get_or_insert(row.seq);
                }
                _ => report.legacy_events += 1,
            }
            prev_version = version;
            let hash = chain::hash_from_slice(&row.hash).unwrap_or(GENESIS_HASH);
            prev = ChainAnchor { seq: row.seq, hash };
            report.last_verified = prev;
            report.events_verified += 1;
        }
        if i64::try_from(fetched).unwrap_or(i64::MAX) < BATCH {
            break;
        }
    }

    // A checkpoint pointing at an event that no longer exists.
    if let Some(missing) = rules
        .checkpoints
        .keys()
        .copied()
        .find(|seq| !matched_checkpoints.contains(seq))
    {
        report.broken = Some(ChainBreak {
            seq: missing,
            problem: ChainProblem::CheckpointMismatch,
        });
        return Ok(report);
    }

    if check_head {
        let head_matches_version = report.events_verified == 0
            || match prev_version {
                PrevVersion::Legacy => head_version.is_none(),
                PrevVersion::Keyed(v) => report.head_key_version == Some(v),
                PrevVersion::Unknown => true,
            };
        // A pinned legacy prefix ending at N means the first keyed event is
        // N + 1 (K-77): a chain ending at or before N lost its keyed part.
        let keyed_part_missing = keys
            .legacy_until_seq()
            .is_some_and(|pin| pin > 0 && head.seq <= pin);
        if head.seq != prev.seq
            || head.hash != prev.hash
            || !head_matches_version
            || keyed_part_missing
        {
            report.broken = Some(ChainBreak {
                seq: head.seq,
                problem: ChainProblem::HeadMismatch,
            });
        }
    }
    Ok(report)
}

/// The key version of the event at an anchor, when the event carries the
/// anchor's hash and that hash is the one its stored columns give under
/// its stored version; `None` otherwise.
fn anchor_version(
    row: &ChainRow,
    anchor: &ChainAnchor,
    keys: &ChainKeys,
    cache: &mut KeyCache,
) -> Result<Option<PrevVersion>, AuthError> {
    if !authn_crypto::ct::constant_time_eq(&row.hash, &anchor.hash) {
        return Ok(None);
    }
    let (Some(version), Some(record), Some(prev_hash)) = (
        PrevVersion::from_db(row.chain_key_version),
        row.record(),
        chain::hash_from_slice(&row.prev_hash),
    ) else {
        return Ok(None);
    };
    let expected = match version {
        PrevVersion::Keyed(v) => record.keyed_hash(cache.get(keys, v)?, &prev_hash),
        _ => record.hash(&prev_hash),
    };
    Ok(match expected {
        Ok(expected) if authn_crypto::ct::constant_time_eq(&expected, &anchor.hash) => {
            Some(version)
        }
        _ => None,
    })
}

/// Checks one event; `Ok(Ok(version))` when it verifies.
fn check_row(
    row: &ChainRow,
    prev: &ChainAnchor,
    prev_version: PrevVersion,
    rules: &mut RangeRules<'_>,
) -> Result<Result<PrevVersion, ChainProblem>, AuthError> {
    if row.prev_hash.as_slice() != prev.hash.as_slice() {
        return Ok(Err(ChainProblem::PrevHashMismatch));
    }
    let Some(version) = PrevVersion::from_db(row.chain_key_version) else {
        return Ok(Err(ChainProblem::Malformed));
    };
    match (version, prev_version) {
        (PrevVersion::Legacy, PrevVersion::Keyed(_)) => {
            return Ok(Err(ChainProblem::KeyDowngrade));
        }
        (PrevVersion::Keyed(v), PrevVersion::Keyed(p)) if v < p => {
            return Ok(Err(ChainProblem::KeyDowngrade));
        }
        (PrevVersion::Legacy, _) if rules.legacy_limit.is_some_and(|limit| row.seq > limit) => {
            return Ok(Err(ChainProblem::UnkeyedEvent));
        }
        _ => {}
    }
    let Some(record) = row.record() else {
        return Ok(Err(ChainProblem::Malformed));
    };
    let expected = match version {
        PrevVersion::Keyed(v) => {
            let key = rules.cache.get(rules.keys, v)?;
            record.keyed_hash(key, &prev.hash)
        }
        _ => record.hash(&prev.hash),
    };
    let Ok(expected) = expected else {
        return Ok(Err(ChainProblem::Malformed));
    };
    if !authn_crypto::ct::constant_time_eq(&row.hash, &expected) {
        return Ok(Err(ChainProblem::HashMismatch));
    }
    let checkpoint = rules.checkpoints.get(&row.seq);
    if let Some(checkpoint) = checkpoint
        && checkpoint.hash.as_slice() != expected.as_slice()
    {
        return Ok(Err(ChainProblem::CheckpointMismatch));
    }
    let switched = match (version, prev_version) {
        (PrevVersion::Keyed(_), PrevVersion::Legacy) => true,
        (PrevVersion::Keyed(v), PrevVersion::Keyed(p)) => v != p,
        _ => false,
    };
    if switched && !checkpoint.is_some_and(|c| c.key_switch) {
        return Ok(Err(ChainProblem::KeySwitchUnrecorded));
    }
    if let Some(salt) = &row.pii_salt {
        let Some(stored) = record.pii_digest else {
            return Ok(Err(ChainProblem::PiiDigestMismatch));
        };
        match chain::pii_digest(salt, row.pii_ip, row.pii_user_agent.as_deref()) {
            Ok(digest) if digest == stored => {}
            _ => return Ok(Err(ChainProblem::PiiDigestMismatch)),
        }
    }
    Ok(Ok(version))
}
