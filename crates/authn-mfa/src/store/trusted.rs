//! `trusted_devices` (MFA-09): only `SHA-256(token)` is stored; revocation
//! marks rows (kept for the user's device list history until purged).

use std::net::IpAddr;

use authn_core::id::{TrustedDeviceId, UserId};
use authn_crypto::token::TokenHash;
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

/// A trusted-device row (the token hash is never returned).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct TrustedDeviceRow {
    pub(crate) id: TrustedDeviceId,
    pub(crate) device_name: Option<String>,
    pub(crate) created_ip: Option<IpAddr>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) last_used_at: Option<OffsetDateTime>,
}

/// Input of [`insert`].
pub(crate) struct NewTrustedDevice<'a> {
    pub(crate) id: TrustedDeviceId,
    pub(crate) user: UserId,
    pub(crate) token_hash: &'a TokenHash,
    pub(crate) device_name: Option<&'a str>,
    pub(crate) user_agent: Option<&'a str>,
    pub(crate) created_ip: Option<IpAddr>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
}

/// Inserts a trusted device.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    new: &NewTrustedDevice<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO trusted_devices (id, user_id, token_hash, device_name, user_agent, \
         created_ip, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(new.id)
    .bind(new.user)
    .bind(new.token_hash.as_bytes().as_slice())
    .bind(new.device_name)
    .bind(new.user_agent)
    .bind(new.created_ip)
    .bind(new.created_at)
    .bind(new.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Checks that the device is active for `user` with this exact token and
/// records the use. All conditions are in one statement.
pub(crate) async fn touch_active(
    conn: &mut PgConnection,
    user: UserId,
    id: TrustedDeviceId,
    token_hash: &TokenHash,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE trusted_devices SET last_used_at = $4 WHERE id = $1 AND user_id = $2 \
         AND token_hash = $3 AND revoked_at IS NULL AND expires_at > $4",
    )
    .bind(id)
    .bind(user)
    .bind(token_hash.as_bytes().as_slice())
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// The user's active devices, newest first.
pub(crate) async fn list_active<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
    now: OffsetDateTime,
) -> Result<Vec<TrustedDeviceRow>, StoreError> {
    Ok(sqlx::query_as::<_, TrustedDeviceRow>(
        "SELECT id, device_name, created_ip, created_at, expires_at, last_used_at \
         FROM trusted_devices WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2 \
         ORDER BY created_at DESC, id DESC",
    )
    .bind(user)
    .bind(now)
    .fetch_all(executor)
    .await?)
}

/// The user's unrevoked devices (expired ones included), oldest first —
/// for the personal data export (ACC-10).
pub(crate) async fn list_unrevoked<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<Vec<TrustedDeviceRow>, StoreError> {
    Ok(sqlx::query_as::<_, TrustedDeviceRow>(
        "SELECT id, device_name, created_ip, created_at, expires_at, last_used_at \
         FROM trusted_devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at, id",
    )
    .bind(user)
    .fetch_all(executor)
    .await?)
}

/// Revokes one device of `user`.
pub(crate) async fn revoke(
    conn: &mut PgConnection,
    user: UserId,
    id: TrustedDeviceId,
    reason: &str,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE trusted_devices SET revoked_at = $3, revoked_reason = $4 \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(user)
    .bind(now)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Revokes every active device of `user`.
pub(crate) async fn revoke_all(
    conn: &mut PgConnection,
    user: UserId,
    reason: &str,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "UPDATE trusted_devices SET revoked_at = $2, revoked_reason = $3 \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user)
    .bind(now)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

/// Revokes the oldest active devices so that at most `keep` remain.
pub(crate) async fn revoke_oldest_beyond(
    conn: &mut PgConnection,
    user: UserId,
    keep: i64,
    reason: &str,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "UPDATE trusted_devices SET revoked_at = $3, revoked_reason = $4 WHERE id IN ( \
         SELECT id FROM trusted_devices WHERE user_id = $1 AND revoked_at IS NULL \
         AND expires_at > $3 ORDER BY created_at DESC, id DESC OFFSET $2)",
    )
    .bind(user)
    .bind(keep)
    .bind(now)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

/// Deletes up to `limit` rows that expired or were revoked before `before`
/// (OPS-06).
pub(crate) async fn purge(
    conn: &mut PgConnection,
    before: OffsetDateTime,
    limit: u32,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "DELETE FROM trusted_devices WHERE id IN (SELECT id FROM trusted_devices \
         WHERE expires_at < $1 OR revoked_at < $1 ORDER BY expires_at LIMIT $2 \
         FOR UPDATE SKIP LOCKED)",
    )
    .bind(before)
    .bind(i64::from(limit))
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}
