//! Retention purge and checkpoints (AUD-05, OPS-06).
//!
//! `audit_events` is append-only; the only way to delete is the documented
//! escape hatch of migration 0009: inside a transaction that first runs
//! `SET LOCAL authn.audit_purge_before = '<timestamptz>'`, rows *older* than
//! that instant may be deleted. Each purge transaction:
//!
//! 1. takes a transaction-scoped advisory lock (one purge at a time),
//! 2. picks a **prefix** of the chain (by `seq`) whose events are all older
//!    than the cutoff — never a hole in the middle,
//! 3. re-verifies that prefix (a tampered segment is never laundered away;
//!    the purge refuses and logs instead),
//! 4. records a `retention_purge` checkpoint `(seq, hash)` of the last
//!    deleted event — the new verification start — and deletes the prefix
//!    (personal-data rows go with it by cascade).
//!
//! The checkpoint is also logged so operators can keep it outside the
//! database as an anchor for [`crate::verify::verify_chain_from`].
//!
//! When the application role has no `DELETE` on `audit_events` (recommended,
//! see `authn_audit_apply_least_privilege` in migration 1700), run the purge
//! with a pool of the maintenance role.

use std::time::Duration;

use authn_core::error::AuthError;
use authn_core::ports::Clock;
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::chain;
use crate::keys::ChainKeys;
use crate::verify::{self, ChainAnchor};

/// Advisory lock key of the purge (`'authn-audit-purge'` as a constant).
const PURGE_LOCK_KEY: i64 = 0x6175_6469_7470_7572;
/// Events deleted per transaction.
pub const DEFAULT_PURGE_BATCH: i64 = 10_000;

/// Outcome of a purge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    /// Events deleted.
    pub events_deleted: u64,
    /// The newest retention checkpoint written, if anything was deleted.
    pub checkpoint: Option<ChainAnchor>,
}

/// Why a purge stopped without deleting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PurgeError {
    /// The segment to delete does not verify; nothing was deleted.
    #[error("audit chain segment does not verify (seq {seq}: {problem})")]
    ChainBroken {
        /// Where.
        seq: i64,
        /// What.
        problem: &'static str,
    },
}

/// Deletes events older than `now - retention` (AUD-05). Never deletes
/// the newest event of the chain while younger events exist after it.
pub async fn purge_expired(
    pool: &PgPool,
    keys: &ChainKeys,
    clock: &dyn Clock,
    retention: Duration,
) -> Result<PurgeReport, AuthError> {
    let before = clock.now() - retention;
    purge_before(pool, keys, before, DEFAULT_PURGE_BATCH, clock.now()).await
}

/// Deletes the chain prefix whose events all occurred before `before`, in
/// transactions of at most `batch` events. The segment is verified with
/// `keys` first (K-77).
pub async fn purge_before(
    pool: &PgPool,
    keys: &ChainKeys,
    before: OffsetDateTime,
    batch: i64,
    now: OffsetDateTime,
) -> Result<PurgeReport, AuthError> {
    let batch = batch.clamp(1, 1_000_000);
    let cutoff_text = before
        .format(&Rfc3339)
        .map_err(|e| AuthError::internal("purge cutoff not formattable").with_source(e))?;
    let mut report = PurgeReport {
        events_deleted: 0,
        checkpoint: None,
    };
    loop {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(PURGE_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let start = verify::retention_start(&mut tx).await?;
        // Last event of the purgeable prefix: everything before the first
        // event that is still within retention, capped by the batch size.
        let cutoff: Option<i64> = sqlx::query_scalar(
            "SELECT max(seq) FROM (\
               SELECT seq FROM audit_events \
               WHERE seq > $1 \
                 AND seq < coalesce((SELECT min(seq) FROM audit_events WHERE occurred_at >= $2), 9223372036854775807) \
               ORDER BY seq LIMIT $3) AS prefix",
        )
        .bind(start.seq)
        .bind(before)
        .bind(batch)
        .fetch_one(&mut *tx)
        .await?;
        let Some(cutoff) = cutoff else {
            tx.commit().await?;
            break;
        };

        let segment = verify::verify_range(&mut tx, keys, start, Some(cutoff), false).await?;
        if let Some(broken) = segment.broken {
            tx.rollback().await?;
            tracing::error!(
                seq = broken.seq,
                problem = broken.problem.as_str(),
                "audit retention purge refused: chain segment does not verify"
            );
            return Err(
                AuthError::internal("audit chain broken; purge refused").with_source(
                    PurgeError::ChainBroken {
                        seq: broken.seq,
                        problem: broken.problem.as_str(),
                    },
                ),
            );
        }
        let anchor = segment.last_verified;
        if anchor.seq != cutoff {
            return Err(AuthError::internal("audit purge segment ended early"));
        }

        sqlx::query("SELECT set_config('authn.audit_purge_before', $1, true)")
            .bind(&cutoff_text)
            .execute(&mut *tx)
            .await?;
        let deleted = sqlx::query("DELETE FROM audit_events WHERE seq > $1 AND seq <= $2")
            .bind(start.seq)
            .bind(cutoff)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        sqlx::query(
            "INSERT INTO audit_chain_checkpoints (seq, hash, reason, created_at) \
             VALUES ($1, $2, 'retention_purge', $3) ON CONFLICT (seq) DO NOTHING",
        )
        .bind(anchor.seq)
        .bind(anchor.hash.as_slice())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        tracing::info!(
            checkpoint_seq = anchor.seq,
            checkpoint_hash = %anchor.hash_hex(),
            events_deleted = deleted,
            "audit retention purge checkpoint"
        );
        report.events_deleted += deleted;
        report.checkpoint = Some(anchor);
        if deleted < u64::try_from(batch).unwrap_or(u64::MAX) {
            break;
        }
    }
    Ok(report)
}

/// Advisory lock key of the scheduled checkpoint (`'authn-audit-ckpt'`).
const CHECKPOINT_LOCK_KEY: i64 = 0x6175_6469_7463_6b70;

/// Records a `manual` checkpoint at the current chain head and returns it
/// (`rust-authentication audit-checkpoint`, K-107). Export the printed /
/// logged `seq:hash` to a system outside this database: it detects later
/// truncation or rewriting of the chain
/// ([`crate::verify::verify_chain_from`]).
///
/// Needs `SELECT` on `audit_chain_head` and `INSERT` on
/// `audit_chain_checkpoints`: the maintenance role (migration 1701).
pub async fn create_checkpoint(pool: &PgPool, clock: &dyn Clock) -> Result<ChainAnchor, AuthError> {
    let mut tx = pool.begin().await?;
    let Some((anchor, _)) = insert_head_checkpoint(&mut tx, "manual", clock.now()).await? else {
        return Err(AuthError::internal(
            "the audit chain is empty; nothing to anchor",
        ));
    };
    tx.commit().await?;
    tracing::info!(
        checkpoint_seq = anchor.seq,
        checkpoint_hash = %anchor.hash_hex(),
        anchor = %format!("{}:{}", anchor.seq, anchor.hash_hex()),
        "audit chain checkpoint"
    );
    Ok(anchor)
}

/// The scheduled external anchor (K-107): records a `scheduled` checkpoint
/// at the chain head unless one was recorded less than `interval` ago, and
/// logs it (`anchor = "<seq>:<hash>"`, the `verify-audit-chain --anchor`
/// format) so the log pipeline carries it off the database host.
///
/// Safe on several instances: a transaction-scoped advisory lock
/// serialises the check and the insert, so the instances together write at
/// most one checkpoint per interval however often each of them calls this.
/// Returns the new checkpoint, or `None` when none was due (or the head did
/// not move since the last checkpoint at that `seq`).
pub async fn create_scheduled_checkpoint(
    pool: &PgPool,
    clock: &dyn Clock,
    interval: Duration,
) -> Result<Option<ChainAnchor>, AuthError> {
    let now = clock.now();
    let interval = time::Duration::try_from(interval)
        .map_err(|_| AuthError::internal("audit checkpoint interval out of range"))?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CHECKPOINT_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    let last: Option<OffsetDateTime> = sqlx::query_scalar(
        "SELECT max(created_at) FROM audit_chain_checkpoints WHERE reason = 'scheduled'",
    )
    .fetch_one(&mut *tx)
    .await?;
    if last.is_some_and(|last| last > now - interval) {
        tx.commit().await?;
        return Ok(None);
    }
    let created = insert_head_checkpoint(&mut tx, "scheduled", now).await?;
    tx.commit().await?;
    // An empty chain has nothing to anchor; a head that did not move since
    // another checkpoint is already anchored by it (try again next time).
    let Some((anchor, true)) = created else {
        return Ok(None);
    };
    tracing::info!(
        checkpoint_seq = anchor.seq,
        checkpoint_hash = %anchor.hash_hex(),
        anchor = %format!("{}:{}", anchor.seq, anchor.hash_hex()),
        "audit chain scheduled checkpoint; keep this anchor outside the database"
    );
    Ok(Some(anchor))
}

/// Inserts a checkpoint of the committed chain head; `None` for an empty
/// chain, otherwise the anchor and whether a new row was written (`false`:
/// a checkpoint at that `seq` exists already). The head row and the event
/// it points at are written in the same transaction, so a plain read (no
/// row lock: the maintenance role has no `UPDATE` on the head) always sees
/// a matching pair.
async fn insert_head_checkpoint(
    tx: &mut sqlx::PgConnection,
    reason: &'static str,
    now: OffsetDateTime,
) -> Result<Option<(ChainAnchor, bool)>, AuthError> {
    let (seq, hash): (i64, Vec<u8>) =
        sqlx::query_as("SELECT last_seq, last_hash FROM audit_chain_head WHERE id")
            .fetch_one(&mut *tx)
            .await?;
    if seq == 0 {
        return Ok(None);
    }
    let hash = chain::hash_from_slice(&hash)
        .ok_or_else(|| AuthError::internal("audit chain head hash is malformed"))?;
    let inserted = sqlx::query(
        "INSERT INTO audit_chain_checkpoints (seq, hash, reason, created_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (seq) DO NOTHING",
    )
    .bind(seq)
    .bind(hash.as_slice())
    .bind(reason)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    Ok(Some((ChainAnchor { seq, hash }, inserted)))
}
