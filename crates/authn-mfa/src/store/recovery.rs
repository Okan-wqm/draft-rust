//! `recovery_codes` (MFA-04): keyed hashes only, single use enforced by one
//! atomic `UPDATE … WHERE used_at IS NULL RETURNING`.

use std::net::IpAddr;

use authn_core::id::{RecoveryCodeBatchId, UserId};
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

/// Counts of a user's recovery codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RecoveryStatus {
    pub(crate) remaining: u32,
    pub(crate) total: u32,
    pub(crate) generated_at: Option<OffsetDateTime>,
}

/// Replaces the user's codes with a new batch (MFA-04: regeneration
/// invalidates every old code, used or not).
pub(crate) async fn replace(
    conn: &mut PgConnection,
    user: UserId,
    batch: RecoveryCodeBatchId,
    hashes: &[[u8; 32]],
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user)
        .execute(&mut *conn)
        .await?;
    for hash in hashes {
        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, batch_id, code_hash, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(batch)
        .bind(hash.as_slice())
        .bind(now)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Consumes the unused code with this hash. Of any number of concurrent
/// callers at most one gets `true` (ARC-06).
pub(crate) async fn consume(
    conn: &mut PgConnection,
    user: UserId,
    hash: &[u8; 32],
    now: OffsetDateTime,
    ip: Option<IpAddr>,
) -> Result<bool, StoreError> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE recovery_codes SET used_at = $3, used_ip = $4 \
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING id",
    )
    .bind(user)
    .bind(hash.as_slice())
    .bind(now)
    .bind(ip)
    .fetch_optional(conn)
    .await?;
    Ok(row.is_some())
}

/// Remaining / total codes and the generation time.
pub(crate) async fn status<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<RecoveryStatus, StoreError> {
    let (remaining, total, generated_at): (i64, i64, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE used_at IS NULL), count(*), max(created_at) \
         FROM recovery_codes WHERE user_id = $1",
    )
    .bind(user)
    .fetch_one(executor)
    .await?;
    Ok(RecoveryStatus {
        remaining: u32::try_from(remaining).map_err(|_| StoreError::Corrupt("count"))?,
        total: u32::try_from(total).map_err(|_| StoreError::Corrupt("count"))?,
        generated_at,
    })
}

/// Deletes every code of `user`.
pub(crate) async fn delete_all(conn: &mut PgConnection, user: UserId) -> Result<u64, StoreError> {
    let result = sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user)
        .execute(conn)
        .await?;
    Ok(result.rows_affected())
}
