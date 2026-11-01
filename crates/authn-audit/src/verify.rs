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
//! exists. Verification runs in one `REPEATABLE READ` read-only transaction
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
}

impl ChainReport {
    /// Whether no defect was found.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.broken.is_none()
    }
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

/// Reads the chain head.
pub(crate) async fn read_head(conn: &mut PgConnection) -> Result<ChainAnchor, AuthError> {
    let (seq, hash): (i64, Vec<u8>) =
        sqlx::query_as("SELECT last_seq, last_hash FROM audit_chain_head WHERE id")
            .fetch_one(&mut *conn)
            .await?;
    let hash = chain::hash_from_slice(&hash)
        .ok_or_else(|| AuthError::internal("audit chain head hash is malformed"))?;
    Ok(ChainAnchor { seq, hash })
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
pub async fn verify_chain(pool: &PgPool) -> Result<ChainReport, AuthError> {
    let mut tx = begin_snapshot(pool).await?;
    let start = retention_start(&mut tx).await?;
    let report = verify_range(&mut tx, start, None, true).await?;
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
    anchor: ChainAnchor,
) -> Result<ChainReport, AuthError> {
    let mut tx = begin_snapshot(pool).await?;
    let report = verify_range(&mut tx, anchor, None, true).await?;
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

/// Verifies the events after `start` up to `until` (inclusive; `None` = to
/// the end). With `check_head`, the head must point at the last event.
pub(crate) async fn verify_range(
    conn: &mut PgConnection,
    start: ChainAnchor,
    until: Option<i64>,
    check_head: bool,
) -> Result<ChainReport, AuthError> {
    let head = read_head(conn).await?;
    let mut report = ChainReport {
        start,
        last_verified: start,
        events_verified: 0,
        head,
        broken: None,
    };

    // The event at the anchor itself must carry the anchor's hash (when it
    // still exists).
    if start.seq > 0 {
        let at_anchor: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT hash FROM audit_events WHERE seq = $1")
                .bind(start.seq)
                .fetch_optional(&mut *conn)
                .await?;
        if let Some(hash) = at_anchor
            && hash.as_slice() != start.hash.as_slice()
        {
            report.broken = Some(ChainBreak {
                seq: start.seq,
                problem: ChainProblem::AnchorMismatch,
            });
            return Ok(report);
        }
    }

    let checkpoints: BTreeMap<i64, Vec<u8>> = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT seq, hash FROM audit_chain_checkpoints WHERE seq > $1 AND ($2::bigint IS NULL OR seq <= $2) ORDER BY seq",
    )
    .bind(start.seq)
    .bind(until)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let mut matched_checkpoints = BTreeSet::new();

    let mut prev = start;
    loop {
        let rows: Vec<ChainRow> = sqlx::query_as(
            "SELECT e.seq, e.id, e.occurred_at, e.recorded_at, e.kind, e.outcome, e.reason, \
             e.actor_type, e.actor_pseudonym, e.actor_ref, e.impersonator_pseudonym, \
             e.subject_pseudonym, e.org_id, e.resource_type, e.resource_id, e.request_id, \
             e.metadata, e.pii_digest, e.prev_hash, e.hash, \
             p.ip AS pii_ip, p.user_agent AS pii_user_agent, p.salt AS pii_salt \
             FROM audit_events e LEFT JOIN audit_event_pii p ON p.event_id = e.id \
             WHERE e.seq > $1 AND ($2::bigint IS NULL OR e.seq <= $2) \
             ORDER BY e.seq LIMIT $3",
        )
        .bind(prev.seq)
        .bind(until)
        .bind(BATCH)
        .fetch_all(&mut *conn)
        .await?;
        let fetched = rows.len();
        for row in rows {
            if let Some(problem) = check_row(&row, &prev, &checkpoints) {
                report.broken = Some(ChainBreak {
                    seq: row.seq,
                    problem,
                });
                return Ok(report);
            }
            if checkpoints.contains_key(&row.seq) {
                matched_checkpoints.insert(row.seq);
            }
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
    if let Some(missing) = checkpoints
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

    if check_head && (head.seq != prev.seq || head.hash != prev.hash) {
        report.broken = Some(ChainBreak {
            seq: head.seq,
            problem: ChainProblem::HeadMismatch,
        });
    }
    Ok(report)
}

fn check_row(
    row: &ChainRow,
    prev: &ChainAnchor,
    checkpoints: &BTreeMap<i64, Vec<u8>>,
) -> Option<ChainProblem> {
    if row.prev_hash.as_slice() != prev.hash.as_slice() {
        return Some(ChainProblem::PrevHashMismatch);
    }
    let Some(record) = row.record() else {
        return Some(ChainProblem::Malformed);
    };
    let Ok(expected) = record.hash(&prev.hash) else {
        return Some(ChainProblem::Malformed);
    };
    if row.hash.as_slice() != expected.as_slice() {
        return Some(ChainProblem::HashMismatch);
    }
    if let Some(checkpoint) = checkpoints.get(&row.seq)
        && checkpoint.as_slice() != expected.as_slice()
    {
        return Some(ChainProblem::CheckpointMismatch);
    }
    if let Some(salt) = &row.pii_salt {
        let Some(stored) = record.pii_digest else {
            return Some(ChainProblem::PiiDigestMismatch);
        };
        match chain::pii_digest(salt, row.pii_ip, row.pii_user_agent.as_deref()) {
            Ok(digest) if digest == stored => {}
            _ => return Some(ChainProblem::PiiDigestMismatch),
        }
    }
    None
}
