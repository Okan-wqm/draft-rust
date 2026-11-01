//! Base repository for the shared `users` and `password_credentials` tables.
//!
//! Ownership: authn-store owns these tables and the CRUD below. Business
//! rules live elsewhere: the account state machine (ACC-06) in
//! authn-account, hashing and password policy in authn-crypto /
//! authn-password. Additional queries on these tables are added here through
//! a contract change request.
//!
//! Methods take any executor (`&PgPool`, `&mut PgConnection`, `&mut *tx`)
//! for reads and `&mut PgConnection` for writes, so writes always happen in
//! an explicit transaction chosen by the caller.
//!
//! Registered read-only exception (contracts §5): authn-audit resolves
//! user ids to pseudonyms with one statement that joins `users.id` /
//! `users.status` with its own `audit_subjects` table.

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::id::UserId;
use authn_core::secret::SensitiveString;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

use crate::error::StoreError;

/// Name of the unique constraint on `users.email_normalized`.
pub const EMAIL_UNIQUE_CONSTRAINT: &str = "users_email_normalized_key";

/// Column list of [`UserRecord`], usable inside `concat!` so every query
/// stays a `&'static str` (sqlx 0.9 rejects dynamic SQL strings).
macro_rules! user_columns {
    () => {
        "id, email, email_normalized, email_verified_at, status, status_reason, \
         status_changed_at, locked_until, is_platform_admin, is_break_glass, last_login_at, \
         created_at, updated_at"
    };
}

/// A row of `users`.
///
/// Addresses are returned as stored strings (see `EmailAddress` docs for why
/// they are not re-parsed on read).
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UserRecord {
    /// Id.
    pub id: UserId,
    /// Canonical address; `None` only for deleted accounts.
    pub email: Option<String>,
    /// Lowercased address used for uniqueness.
    pub email_normalized: Option<String>,
    /// When the address was verified.
    pub email_verified_at: Option<OffsetDateTime>,
    /// Lifecycle status.
    pub status: AccountStatus,
    /// Reason code of the last status change.
    pub status_reason: Option<String>,
    /// When the status last changed.
    pub status_changed_at: OffsetDateTime,
    /// End of a temporary lock.
    pub locked_until: Option<OffsetDateTime>,
    /// Platform administrator.
    pub is_platform_admin: bool,
    /// Break-glass account (ADM-05).
    pub is_break_glass: bool,
    /// Last successful login.
    pub last_login_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last update.
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRecord")
            .field("id", &self.id)
            .field(
                "email",
                &self.email.as_deref().map(authn_core::redact::mask_email),
            )
            .field("status", &self.status)
            .field("is_platform_admin", &self.is_platform_admin)
            .finish_non_exhaustive()
    }
}

impl UserRecord {
    /// Whether the e-mail address is verified.
    #[must_use]
    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
}

/// Which accounts a maintenance job claims with
/// [`UserRepository::claim_next`] (OPS-06).
///
/// The instants come from the injected `Clock` (ARC-04), never from the
/// database's `now()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserClaim {
    /// `pending_verification` accounts whose address was never verified and
    /// that were created strictly before the instant (ACC-05 purge).
    UnverifiedCreatedBefore(OffsetDateTime),
    /// `locked` accounts whose `locked_until` is at or before the instant
    /// (ACC-06 automatic unlock).
    LockExpiredAt(OffsetDateTime),
}

/// Input of [`UserRepository::create`].
#[derive(Debug, Clone)]
pub struct NewUser {
    /// New id (UUIDv7).
    pub id: UserId,
    /// Validated address.
    pub email: EmailAddress,
    /// Initial status (normally `pending_verification`).
    pub status: AccountStatus,
    /// Creation time from the injected clock.
    pub created_at: OffsetDateTime,
}

/// A stored password hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordCredentialRecord {
    /// Owner.
    pub user_id: UserId,
    /// PHC / legacy hash string (sensitive: enables offline cracking).
    pub password_hash: SensitiveString,
    /// Hash scheme identifier.
    pub algorithm: String,
    /// Pepper version (`None` for imported legacy hashes).
    pub pepper_version: Option<u32>,
    /// `must_change_password` flag (PWD-12).
    pub must_change: bool,
    /// Last change by the user (not updated by transparent rehashing).
    pub changed_at: OffsetDateTime,
}

/// Input of [`UserRepository::set_password`] / [`UserRepository::rehash_password`].
#[derive(Debug, Clone)]
pub struct NewPasswordHash<'a> {
    /// PHC / legacy hash string.
    pub password_hash: &'a SensitiveString,
    /// Hash scheme identifier (`argon2id`, `bcrypt`, …).
    pub algorithm: &'a str,
    /// Pepper version (`None` only for imported legacy hashes).
    pub pepper_version: Option<u32>,
}

#[derive(sqlx::FromRow)]
struct PasswordRow {
    user_id: UserId,
    password_hash: String,
    algorithm: String,
    pepper_version: Option<i32>,
    must_change: bool,
    changed_at: OffsetDateTime,
}

impl TryFrom<PasswordRow> for PasswordCredentialRecord {
    type Error = StoreError;

    fn try_from(row: PasswordRow) -> Result<Self, Self::Error> {
        let pepper_version = row
            .pepper_version
            .map(u32::try_from)
            .transpose()
            .map_err(|_| StoreError::Corrupt("negative pepper_version"))?;
        Ok(Self {
            user_id: row.user_id,
            password_hash: SensitiveString::new(row.password_hash),
            algorithm: row.algorithm,
            pepper_version,
            must_change: row.must_change,
            changed_at: row.changed_at,
        })
    }
}

fn pepper_to_db(version: Option<u32>) -> Result<Option<i32>, StoreError> {
    version
        .map(i32::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt("pepper_version out of range"))
}

/// Queries on `users` and `password_credentials`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRepository;

impl UserRepository {
    /// Inserts a user. A duplicate normalized address fails with
    /// `StoreError::UniqueViolation { constraint: "users_email_normalized_key" }`.
    pub async fn create(conn: &mut PgConnection, new: &NewUser) -> Result<UserRecord, StoreError> {
        let sql = concat!(
            "INSERT INTO users (id, email, email_normalized, status, status_changed_at, \
             created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5, $5) RETURNING ",
            user_columns!()
        );
        let record = sqlx::query_as::<_, UserRecord>(sql)
            .bind(new.id)
            .bind(new.email.as_str())
            .bind(new.email.normalized())
            .bind(new.status)
            .bind(new.created_at)
            .fetch_one(conn)
            .await?;
        Ok(record)
    }

    /// Finds a user by id.
    pub async fn find_by_id<'e>(
        executor: impl PgExecutor<'e>,
        id: UserId,
    ) -> Result<Option<UserRecord>, StoreError> {
        let sql = concat!("SELECT ", user_columns!(), " FROM users WHERE id = $1");
        Ok(sqlx::query_as::<_, UserRecord>(sql)
            .bind(id)
            .fetch_optional(executor)
            .await?)
    }

    /// Loads every user of `ids` in one query (`WHERE id = ANY($1)`),
    /// ordered by id. Unknown ids are skipped and duplicates are returned
    /// once, so the result may be shorter than `ids`. Meant for page-sized
    /// batches (e.g. a member list, ORG-02) instead of one `find_by_id` per
    /// row; read-only.
    pub async fn find_many<'e>(
        executor: impl PgExecutor<'e>,
        ids: &[UserId],
    ) -> Result<Vec<UserRecord>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = concat!(
            "SELECT ",
            user_columns!(),
            " FROM users WHERE id = ANY($1) ORDER BY id"
        );
        Ok(sqlx::query_as::<_, UserRecord>(sql)
            .bind(ids)
            .fetch_all(executor)
            .await?)
    }

    /// Claims the next user matching `claim` for a maintenance job (OPS-06):
    /// the oldest matching row whose id is not in `skip` is returned
    /// row-locked (`FOR UPDATE SKIP LOCKED`), so several instances running
    /// the same job never process the same account, and a row held by a
    /// concurrent request is skipped instead of waited for.
    ///
    /// Must run inside the caller's transaction: the lock is what makes the
    /// claim exclusive, and it is released when that transaction ends. Put
    /// the ids already handled (or deliberately skipped) by this run in
    /// `skip` so a row that is left unchanged is not claimed again.
    pub async fn claim_next(
        conn: &mut PgConnection,
        claim: UserClaim,
        skip: &[UserId],
    ) -> Result<Option<UserRecord>, StoreError> {
        let (sql, at) = match claim {
            UserClaim::UnverifiedCreatedBefore(before) => (
                concat!(
                    "SELECT ",
                    user_columns!(),
                    " FROM users WHERE status = 'pending_verification' \
                     AND email_verified_at IS NULL AND created_at < $1 \
                     AND NOT (id = ANY($2)) \
                     ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED"
                ),
                before,
            ),
            UserClaim::LockExpiredAt(now) => (
                concat!(
                    "SELECT ",
                    user_columns!(),
                    " FROM users WHERE status = 'locked' AND locked_until <= $1 \
                     AND NOT (id = ANY($2)) \
                     ORDER BY locked_until, id LIMIT 1 FOR UPDATE SKIP LOCKED"
                ),
                now,
            ),
        };
        Ok(sqlx::query_as::<_, UserRecord>(sql)
            .bind(at)
            .bind(skip)
            .fetch_optional(conn)
            .await?)
    }

    /// Finds a user by normalized address (ACC-03). Callers on
    /// unauthenticated paths must keep timing uniform whether or not a row
    /// is found (CRY-05).
    pub async fn find_by_email<'e>(
        executor: impl PgExecutor<'e>,
        email: &EmailAddress,
    ) -> Result<Option<UserRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            user_columns!(),
            " FROM users WHERE email_normalized = $1"
        );
        Ok(sqlx::query_as::<_, UserRecord>(sql)
            .bind(email.normalized())
            .fetch_optional(executor)
            .await?)
    }

    /// Loads and row-locks a user for a read-modify-write in the caller's
    /// transaction.
    pub async fn lock_for_update(
        conn: &mut PgConnection,
        id: UserId,
    ) -> Result<Option<UserRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            user_columns!(),
            " FROM users WHERE id = $1 FOR UPDATE"
        );
        Ok(sqlx::query_as::<_, UserRecord>(sql)
            .bind(id)
            .fetch_optional(conn)
            .await?)
    }

    /// Compare-and-set status change: succeeds only if the current status is
    /// `expected`. Returns whether a row changed. Transition legality is
    /// decided by authn-account before calling this.
    pub async fn update_status(
        conn: &mut PgConnection,
        id: UserId,
        expected: AccountStatus,
        new_status: AccountStatus,
        reason: Option<&str>,
        locked_until: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE users SET status = $3, status_reason = $4, locked_until = $5, \
             status_changed_at = $6 WHERE id = $1 AND status = $2",
        )
        .bind(id)
        .bind(expected)
        .bind(new_status)
        .bind(reason)
        .bind(locked_until)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Marks the address verified (idempotent; keeps the first timestamp).
    pub async fn mark_email_verified(
        conn: &mut PgConnection,
        id: UserId,
        at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE users SET email_verified_at = COALESCE(email_verified_at, $2) WHERE id = $1",
        )
        .bind(id)
        .bind(at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Replaces the address (ACC-07). `verified_at` is the verification time
    /// of the new address.
    pub async fn update_email(
        conn: &mut PgConnection,
        id: UserId,
        email: &EmailAddress,
        verified_at: Option<OffsetDateTime>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE users SET email = $2, email_normalized = $3, email_verified_at = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(email.as_str())
        .bind(email.normalized())
        .bind(verified_at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Records a successful login.
    pub async fn record_login(
        conn: &mut PgConnection,
        id: UserId,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET last_login_at = $2 WHERE id = $1")
            .bind(id)
            .bind(at)
            .execute(conn)
            .await?;
        Ok(())
    }

    /// Hard-deletes a user; every user-owned row is removed by
    /// `ON DELETE CASCADE` and audit pseudonyms become unlinkable (ACC-09,
    /// AUD-05).
    pub async fn delete(conn: &mut PgConnection, id: UserId) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(conn)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// The user's password credential, if any.
    pub async fn find_password<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
    ) -> Result<Option<PasswordCredentialRecord>, StoreError> {
        let row: Option<PasswordRow> = sqlx::query_as(
            "SELECT user_id, password_hash, algorithm, pepper_version, must_change, changed_at \
             FROM password_credentials WHERE user_id = $1",
        )
        .bind(user)
        .fetch_optional(executor)
        .await?;
        row.map(PasswordCredentialRecord::try_from).transpose()
    }

    /// Sets (adds or replaces) the password chosen by the user or an admin:
    /// updates `changed_at` and clears `must_change` unless requested.
    pub async fn set_password(
        conn: &mut PgConnection,
        user: UserId,
        hash: &NewPasswordHash<'_>,
        must_change: bool,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO password_credentials \
               (user_id, password_hash, algorithm, pepper_version, must_change, changed_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $6) \
             ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, \
               algorithm = EXCLUDED.algorithm, pepper_version = EXCLUDED.pepper_version, \
               must_change = EXCLUDED.must_change, changed_at = EXCLUDED.changed_at",
        )
        .bind(user)
        .bind(hash.password_hash.expose())
        .bind(hash.algorithm)
        .bind(pepper_to_db(hash.pepper_version)?)
        .bind(must_change)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Transparent upgrade of the stored hash (CRY-03, CRY-04): same
    /// password, new parameters / pepper version. `changed_at` and
    /// `must_change` are untouched. Only replaces the hash that was verified
    /// (`previous_hash`) so a concurrent password change is never
    /// overwritten. Returns whether the row was updated.
    pub async fn rehash_password(
        conn: &mut PgConnection,
        user: UserId,
        previous_hash: &SensitiveString,
        hash: &NewPasswordHash<'_>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE password_credentials SET password_hash = $3, algorithm = $4, pepper_version = $5 \
             WHERE user_id = $1 AND password_hash = $2",
        )
        .bind(user)
        .bind(previous_hash.expose())
        .bind(hash.password_hash.expose())
        .bind(hash.algorithm)
        .bind(pepper_to_db(hash.pepper_version)?)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Sets or clears `must_change_password` (PWD-12, ADM-03, ADM-06).
    pub async fn set_must_change_password(
        conn: &mut PgConnection,
        user: UserId,
        must_change: bool,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("UPDATE password_credentials SET must_change = $2 WHERE user_id = $1")
                .bind(user)
                .bind(must_change)
                .execute(conn)
                .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Removes the password (PWD-11). The caller verifies that another
    /// strong login method remains.
    pub async fn delete_password(
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM password_credentials WHERE user_id = $1")
            .bind(user)
            .execute(conn)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}
