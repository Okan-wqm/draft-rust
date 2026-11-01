//! `mfa_user_settings`: the user's MFA preference and the per-user failure
//! window / temporary lock (MFA-03, migration `1300`).
//!
//! [`lock`] creates the row on demand and row-locks it; every verification
//! and every factor change of a user runs under this lock, so concurrent
//! requests of one user are serialized.

use std::time::Duration;

use authn_core::id::UserId;
use authn_core::ports::RateLimitPolicy;
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

/// The settings row.
#[derive(Debug, Clone, PartialEq, Eq, Default, sqlx::FromRow)]
pub(crate) struct SettingsRow {
    pub(crate) mfa_enabled: bool,
    pub(crate) failed_attempts: i32,
    pub(crate) failure_window_start: Option<OffsetDateTime>,
    pub(crate) locked_until: Option<OffsetDateTime>,
}

impl SettingsRow {
    /// The per-user lock end, when locked at `now`.
    pub(crate) fn locked_at(&self, now: OffsetDateTime) -> Option<OffsetDateTime> {
        self.locked_until.filter(|until| *until > now)
    }
}

/// Reads the row without locking (`None` when it does not exist yet).
pub(crate) async fn find<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<Option<SettingsRow>, StoreError> {
    Ok(sqlx::query_as::<_, SettingsRow>(
        "SELECT mfa_enabled, failed_attempts, failure_window_start, locked_until \
         FROM mfa_user_settings WHERE user_id = $1",
    )
    .bind(user)
    .fetch_optional(executor)
    .await?)
}

/// Creates the row if missing and row-locks it for the rest of the
/// caller's transaction. Fails with a foreign-key violation for unknown
/// users.
pub(crate) async fn lock(conn: &mut PgConnection, user: UserId) -> Result<SettingsRow, StoreError> {
    sqlx::query(
        "INSERT INTO mfa_user_settings (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user)
    .execute(&mut *conn)
    .await?;
    Ok(sqlx::query_as::<_, SettingsRow>(
        "SELECT mfa_enabled, failed_attempts, failure_window_start, locked_until \
         FROM mfa_user_settings WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user)
    .fetch_one(conn)
    .await?)
}

/// Sets the user's MFA preference.
pub(crate) async fn set_enabled(
    conn: &mut PgConnection,
    user: UserId,
    enabled: bool,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE mfa_user_settings SET mfa_enabled = $2 WHERE user_id = $1")
        .bind(user)
        .bind(enabled)
        .execute(conn)
        .await?;
    Ok(())
}

/// Counts a failed verification in the user's fixed window
/// (`policy.limit` per `policy.period`). When the limit is reached the user
/// is locked for `lockout` and the window restarts. Returns the lock end
/// when this failure engaged the lock. The row must be locked ([`lock`]).
pub(crate) async fn record_failure(
    conn: &mut PgConnection,
    user: UserId,
    current: &SettingsRow,
    now: OffsetDateTime,
    policy: RateLimitPolicy,
    lockout: Duration,
) -> Result<Option<OffsetDateTime>, StoreError> {
    let in_window = current
        .failure_window_start
        .is_some_and(|start| start <= now && (now - start) < policy.period);
    let (start, count) = if in_window {
        (
            current.failure_window_start,
            current.failed_attempts.saturating_add(1),
        )
    } else {
        (Some(now), 1)
    };
    let limit = i32::try_from(policy.limit).unwrap_or(i32::MAX);
    let (start, count, locked_until) = if count >= limit {
        let until = time::Duration::try_from(lockout)
            .ok()
            .and_then(|d| now.checked_add(d))
            .ok_or(StoreError::Corrupt("lockout duration out of range"))?;
        (None, 0, Some(until))
    } else {
        (start, count, current.locked_until)
    };
    sqlx::query(
        "UPDATE mfa_user_settings SET failed_attempts = $2, failure_window_start = $3, \
         locked_until = $4 WHERE user_id = $1",
    )
    .bind(user)
    .bind(count)
    .bind(start)
    .bind(locked_until)
    .execute(conn)
    .await?;
    Ok(if start.is_none() { locked_until } else { None })
}

/// Clears the failure window after a successful verification.
pub(crate) async fn reset_failures(
    conn: &mut PgConnection,
    user: UserId,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE mfa_user_settings SET failed_attempts = 0, failure_window_start = NULL \
         WHERE user_id = $1",
    )
    .bind(user)
    .execute(conn)
    .await?;
    Ok(())
}

/// Resets the row to defaults (admin MFA reset, ADM-03).
pub(crate) async fn reset(conn: &mut PgConnection, user: UserId) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE mfa_user_settings SET mfa_enabled = false, preferred_factor = NULL, \
         failed_attempts = 0, failure_window_start = NULL, locked_until = NULL WHERE user_id = $1",
    )
    .bind(user)
    .execute(conn)
    .await?;
    Ok(())
}
