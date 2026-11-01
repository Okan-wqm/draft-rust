//! `mfa_factors` (TOTP, SMS and e-mail factors).
//!
//! Writes take `&mut PgConnection` (the caller's transaction, ARC-06);
//! row locks (`FOR UPDATE`) are taken wherever a read decides a write.

use std::fmt;

use authn_core::domain::FactorKind;
use authn_core::id::{FactorId, UserId};
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

macro_rules! factor_columns {
    () => {
        "id, user_id, kind, status, label, secret_ciphertext, totp_digits, totp_period, \
         last_used_step, phone_e164, email, failed_attempts, locked_until, created_at, \
         confirmed_at, last_used_at"
    };
}

/// Lifecycle status of a factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FactorStatus {
    /// Enrollment started, not confirmed yet.
    Pending,
    /// Usable.
    Active,
}

impl FactorStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }

    fn parse(text: &str) -> Result<Option<Self>, StoreError> {
        match text {
            "pending" => Ok(Some(Self::Pending)),
            "active" => Ok(Some(Self::Active)),
            // Not written by this version; such rows are ignored.
            "disabled" => Ok(None),
            _ => Err(StoreError::Corrupt("unknown mfa factor status")),
        }
    }
}

/// A factor row.
#[derive(Clone)]
pub(crate) struct FactorRecord {
    pub(crate) id: FactorId,
    pub(crate) user_id: UserId,
    pub(crate) kind: FactorKind,
    pub(crate) status: FactorStatus,
    pub(crate) label: Option<String>,
    pub(crate) secret_ciphertext: Option<Vec<u8>>,
    pub(crate) totp_digits: Option<i16>,
    pub(crate) totp_period: Option<i16>,
    pub(crate) last_used_step: Option<i64>,
    pub(crate) phone_e164: Option<String>,
    pub(crate) failed_attempts: i32,
    pub(crate) locked_until: Option<OffsetDateTime>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) confirmed_at: Option<OffsetDateTime>,
    pub(crate) last_used_at: Option<OffsetDateTime>,
}

impl fmt::Debug for FactorRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FactorRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("failed_attempts", &self.failed_attempts)
            .field("locked_until", &self.locked_until)
            .finish_non_exhaustive()
    }
}

impl FactorRecord {
    /// Whether the factor is temporarily locked at `now` (MFA-03).
    pub(crate) fn is_locked(&self, now: OffsetDateTime) -> bool {
        self.locked_until.is_some_and(|until| until > now)
    }
}

#[derive(sqlx::FromRow)]
struct FactorRow {
    id: FactorId,
    user_id: UserId,
    kind: FactorKind,
    status: String,
    label: Option<String>,
    secret_ciphertext: Option<Vec<u8>>,
    totp_digits: Option<i16>,
    totp_period: Option<i16>,
    last_used_step: Option<i64>,
    phone_e164: Option<String>,
    #[allow(dead_code)] // selected for completeness; the account address is used
    email: Option<String>,
    failed_attempts: i32,
    locked_until: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    confirmed_at: Option<OffsetDateTime>,
    last_used_at: Option<OffsetDateTime>,
}

impl FactorRow {
    fn into_record(self) -> Result<Option<FactorRecord>, StoreError> {
        let Some(status) = FactorStatus::parse(&self.status)? else {
            return Ok(None);
        };
        Ok(Some(FactorRecord {
            id: self.id,
            user_id: self.user_id,
            kind: self.kind,
            status,
            label: self.label,
            secret_ciphertext: self.secret_ciphertext,
            totp_digits: self.totp_digits,
            totp_period: self.totp_period,
            last_used_step: self.last_used_step,
            phone_e164: self.phone_e164,
            failed_attempts: self.failed_attempts,
            locked_until: self.locked_until,
            created_at: self.created_at,
            confirmed_at: self.confirmed_at,
            last_used_at: self.last_used_at,
        }))
    }
}

fn records(rows: Vec<FactorRow>) -> Result<Vec<FactorRecord>, StoreError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(record) = row.into_record()? {
            out.push(record);
        }
    }
    Ok(out)
}

/// Input of [`insert`].
pub(crate) struct NewFactor<'a> {
    pub(crate) id: FactorId,
    pub(crate) user_id: UserId,
    pub(crate) kind: FactorKind,
    pub(crate) label: Option<&'a str>,
    pub(crate) secret_ciphertext: Option<&'a [u8]>,
    pub(crate) totp_digits: Option<i16>,
    pub(crate) totp_period: Option<i16>,
    pub(crate) phone_e164: Option<&'a str>,
    pub(crate) created_at: OffsetDateTime,
}

/// Inserts a pending factor.
pub(crate) async fn insert(conn: &mut PgConnection, new: &NewFactor<'_>) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO mfa_factors (id, user_id, kind, status, label, secret_ciphertext, \
         totp_digits, totp_period, phone_e164, created_at, updated_at) \
         VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7, $8, $9, $9)",
    )
    .bind(new.id)
    .bind(new.user_id)
    .bind(new.kind)
    .bind(new.label)
    .bind(new.secret_ciphertext)
    .bind(new.totp_digits)
    .bind(new.totp_period)
    .bind(new.phone_e164)
    .bind(new.created_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Every pending / active factor of a user, oldest first.
pub(crate) async fn list<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<Vec<FactorRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        factor_columns!(),
        " FROM mfa_factors WHERE user_id = $1 AND status <> 'disabled' ORDER BY created_at, id"
    );
    let rows = sqlx::query_as::<_, FactorRow>(sql)
        .bind(user)
        .fetch_all(executor)
        .await?;
    records(rows)
}

/// Row-locks one factor of `user` (`None` for unknown or foreign ids).
pub(crate) async fn lock(
    conn: &mut PgConnection,
    user: UserId,
    id: FactorId,
) -> Result<Option<FactorRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        factor_columns!(),
        " FROM mfa_factors WHERE id = $1 AND user_id = $2 AND status <> 'disabled' FOR UPDATE"
    );
    let row = sqlx::query_as::<_, FactorRow>(sql)
        .bind(id)
        .bind(user)
        .fetch_optional(conn)
        .await?;
    match row {
        Some(row) => row.into_record(),
        None => Ok(None),
    }
}

/// Row-locks the active factors of one kind, most recently used first.
pub(crate) async fn lock_active_of_kind(
    conn: &mut PgConnection,
    user: UserId,
    kind: FactorKind,
) -> Result<Vec<FactorRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        factor_columns!(),
        " FROM mfa_factors WHERE user_id = $1 AND kind = $2 AND status = 'active' \
         ORDER BY last_used_at DESC NULLS LAST, created_at DESC, id FOR UPDATE"
    );
    let rows = sqlx::query_as::<_, FactorRow>(sql)
        .bind(user)
        .bind(kind)
        .fetch_all(conn)
        .await?;
    records(rows)
}

/// The active factors of one kind without locking (pre-checks).
pub(crate) async fn active_of_kind<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
    kind: FactorKind,
) -> Result<Vec<FactorRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        factor_columns!(),
        " FROM mfa_factors WHERE user_id = $1 AND kind = $2 AND status = 'active' \
         ORDER BY last_used_at DESC NULLS LAST, created_at DESC, id"
    );
    let rows = sqlx::query_as::<_, FactorRow>(sql)
        .bind(user)
        .bind(kind)
        .fetch_all(executor)
        .await?;
    records(rows)
}

/// Pending / active factors of `user` (the per-user limit counts both).
pub(crate) async fn count_live(conn: &mut PgConnection, user: UserId) -> Result<i64, StoreError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM mfa_factors WHERE user_id = $1 AND status <> 'disabled'",
    )
    .bind(user)
    .fetch_one(conn)
    .await?;
    Ok(count)
}

/// Activates a pending factor. `last_used_step` records the TOTP step of
/// the confirmation code so it cannot be replayed at the next login.
pub(crate) async fn activate(
    conn: &mut PgConnection,
    id: FactorId,
    now: OffsetDateTime,
    last_used_step: Option<i64>,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE mfa_factors SET status = 'active', confirmed_at = $2, last_used_at = $2, \
         last_used_step = $3, failed_attempts = 0, locked_until = NULL \
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(id)
    .bind(now)
    .bind(last_used_step)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Records a successful use: clears the failure counter and, for TOTP,
/// advances `last_used_step` — only forwards (MFA-02). Returns `false` when
/// the step is not newer than the stored one (a concurrent use won).
pub(crate) async fn record_use(
    conn: &mut PgConnection,
    id: FactorId,
    now: OffsetDateTime,
    step: Option<i64>,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE mfa_factors SET last_used_at = $2, failed_attempts = 0, locked_until = NULL, \
         last_used_step = COALESCE($3, last_used_step) \
         WHERE id = $1 AND status = 'active' \
         AND ($3::bigint IS NULL OR last_used_step IS NULL OR last_used_step < $3)",
    )
    .bind(id)
    .bind(now)
    .bind(step)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Counts a failed verification of one factor; at `max_attempts` the
/// factor is locked until `lock_until` and the counter restarts (MFA-03).
/// Returns the lock end when this failure engaged the lock.
pub(crate) async fn record_failure(
    conn: &mut PgConnection,
    id: FactorId,
    max_attempts: i32,
    lock_until: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, StoreError> {
    let (locked,): (bool,) = sqlx::query_as(
        "UPDATE mfa_factors SET \
         locked_until = CASE WHEN failed_attempts + 1 >= $2 THEN $3 ELSE locked_until END, \
         failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END \
         WHERE id = $1 RETURNING (failed_attempts = 0 AND locked_until = $3)",
    )
    .bind(id)
    .bind(max_attempts)
    .bind(lock_until)
    .fetch_one(conn)
    .await?;
    Ok(locked.then_some(lock_until))
}

/// Deletes one factor of `user`; returns whether it existed.
pub(crate) async fn delete(
    conn: &mut PgConnection,
    user: UserId,
    id: FactorId,
) -> Result<bool, StoreError> {
    let result = sqlx::query("DELETE FROM mfa_factors WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user)
        .execute(conn)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes the user's pending factors of `kind` (a new enrollment replaces
/// an abandoned one).
pub(crate) async fn delete_pending_of_kind(
    conn: &mut PgConnection,
    user: UserId,
    kind: FactorKind,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "DELETE FROM mfa_factors WHERE user_id = $1 AND kind = $2 AND status = 'pending'",
    )
    .bind(user)
    .bind(kind)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

/// Deletes every factor of `user` (admin MFA reset, ADM-03).
pub(crate) async fn delete_all(conn: &mut PgConnection, user: UserId) -> Result<u64, StoreError> {
    let result = sqlx::query("DELETE FROM mfa_factors WHERE user_id = $1")
        .bind(user)
        .execute(conn)
        .await?;
    Ok(result.rows_affected())
}

/// Deletes up to `limit` pending factors created before `before` (OPS-06).
pub(crate) async fn purge_pending(
    conn: &mut PgConnection,
    before: OffsetDateTime,
    limit: u32,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "DELETE FROM mfa_factors WHERE id IN (SELECT id FROM mfa_factors \
         WHERE status = 'pending' AND created_at < $1 ORDER BY created_at LIMIT $2 \
         FOR UPDATE SKIP LOCKED)",
    )
    .bind(before)
    .bind(i64::from(limit))
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}
