//! SQL for `pending_registrations` (migration `1201`, owned by this crate):
//! every registration with the credentials and profile submitted in it,
//! bound to its own e-mailed link and code and to the registering client's
//! handle (ADR 0002, account pre-hijacking defence).
//!
//! Every query is a runtime-checked `&'static str` with bind parameters.
//! Writes take `&mut PgConnection` so they run in the caller's transaction.

use std::fmt;
use std::net::IpAddr;

use authn_core::domain::{EmailAddress, Locale};
use authn_core::id::{TermsVersionId, UserId};
use authn_core::secret::SensitiveString;
use authn_crypto::password::StoredPasswordHash;
use authn_crypto::token::TokenHash;
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

/// A `pending_registrations` row.
#[derive(Clone, sqlx::FromRow)]
pub(crate) struct RegistrationRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub email: String,
    pub email_normalized: String,
    pub handle_hash: Vec<u8>,
    pub link_hash: Vec<u8>,
    pub link_expires_at: OffsetDateTime,
    pub code_hash: Vec<u8>,
    pub code_expires_at: OffsetDateTime,
    pub code_attempts: i32,
    pub password_attempts: i32,
    pub password_hash: String,
    pub password_algorithm: String,
    pub pepper_version: Option<i32>,
    pub display_name: Option<String>,
    pub locale: Locale,
    pub time_zone: String,
    pub terms_version_ids: Vec<Uuid>,
    pub created_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for RegistrationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("code_attempts", &self.code_attempts)
            .field("password_attempts", &self.password_attempts)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl RegistrationRecord {
    /// Whether `candidate` is this registration's handle (constant time).
    pub(crate) fn handle_matches(&self, candidate: &TokenHash) -> bool {
        stored_hash(&self.handle_hash).is_some_and(|stored| stored == *candidate)
    }

    /// Whether `candidate` is this registration's current link (constant
    /// time).
    pub(crate) fn link_matches(&self, candidate: &TokenHash) -> bool {
        stored_hash(&self.link_hash).is_some_and(|stored| stored == *candidate)
    }

    /// Whether `candidate` is the keyed hash of the current code (constant
    /// time).
    pub(crate) fn code_matches(&self, candidate: &TokenHash) -> bool {
        stored_hash(&self.code_hash).is_some_and(|stored| stored == *candidate)
    }

    /// The submitted password hash in the form `PasswordHasher::verify`
    /// takes.
    pub(crate) fn stored_password(&self) -> Result<StoredPasswordHash, StoreError> {
        Ok(StoredPasswordHash::new(
            &SensitiveString::from(self.password_hash.clone()),
            &self.password_algorithm,
            pepper_from_db(self.pepper_version)?,
        ))
    }

    /// The accepted terms versions.
    pub(crate) fn terms_versions(&self) -> Vec<TermsVersionId> {
        self.terms_version_ids
            .iter()
            .copied()
            .map(TermsVersionId::from_uuid)
            .collect()
    }
}

fn stored_hash(bytes: &[u8]) -> Option<TokenHash> {
    TokenHash::from_slice(bytes).ok()
}

fn pepper_from_db(value: Option<i32>) -> Result<Option<u32>, StoreError> {
    value
        .map(u32::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt("pending_registrations.pepper_version"))
}

fn pepper_to_db(value: Option<u32>) -> Result<Option<i32>, StoreError> {
    value
        .map(i32::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt("pending_registrations.pepper_version"))
}

/// Input of [`RegistrationRepository::insert`].
pub(crate) struct NewRegistration<'a> {
    pub id: Uuid,
    pub user_id: UserId,
    pub email: &'a EmailAddress,
    pub handle_hash: &'a TokenHash,
    pub link_hash: &'a TokenHash,
    pub link_expires_at: OffsetDateTime,
    pub code_hash: &'a TokenHash,
    pub code_expires_at: OffsetDateTime,
    pub password_hash: &'a SensitiveString,
    pub password_algorithm: &'a str,
    pub pepper_version: Option<u32>,
    pub display_name: Option<&'a str>,
    pub locale: Locale,
    pub time_zone: &'a str,
    pub terms_version_ids: &'a [TermsVersionId],
    pub created_ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Fresh link and code of a resend.
pub(crate) struct RotatedSecrets<'a> {
    pub link_hash: &'a TokenHash,
    pub link_expires_at: OffsetDateTime,
    pub code_hash: &'a TokenHash,
    pub code_expires_at: OffsetDateTime,
}

macro_rules! registration_columns {
    () => {
        "id, user_id, email, email_normalized, handle_hash, link_hash, link_expires_at, code_hash, \
         code_expires_at, code_attempts, password_attempts, password_hash, password_algorithm, \
         pepper_version, display_name, locale, time_zone, terms_version_ids, created_ip, \
         user_agent, created_at, expires_at"
    };
}

pub(crate) struct RegistrationRepository;

impl RegistrationRepository {
    pub(crate) async fn insert(
        conn: &mut PgConnection,
        new: &NewRegistration<'_>,
    ) -> Result<(), StoreError> {
        let terms: Vec<Uuid> = new
            .terms_version_ids
            .iter()
            .map(TermsVersionId::as_uuid)
            .collect();
        sqlx::query(
            "INSERT INTO pending_registrations (id, user_id, email, email_normalized, handle_hash, \
               link_hash, link_expires_at, code_hash, code_expires_at, password_hash, \
               password_algorithm, pepper_version, display_name, locale, time_zone, \
               terms_version_ids, created_ip, user_agent, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
               $17, $18, $19, $20)",
        )
        .bind(new.id)
        .bind(new.user_id)
        .bind(new.email.as_str())
        .bind(new.email.normalized())
        .bind(new.handle_hash.as_bytes().as_slice())
        .bind(new.link_hash.as_bytes().as_slice())
        .bind(new.link_expires_at)
        .bind(new.code_hash.as_bytes().as_slice())
        .bind(new.code_expires_at)
        .bind(new.password_hash.expose())
        .bind(new.password_algorithm)
        .bind(pepper_to_db(new.pepper_version)?)
        .bind(new.display_name)
        .bind(new.locale)
        .bind(new.time_zone)
        .bind(&terms)
        .bind(new.created_ip)
        .bind(new.user_agent)
        .bind(new.created_at)
        .bind(new.expires_at)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// The live registration whose current, unexpired link is `link_hash`.
    pub(crate) async fn find_by_link<'e>(
        executor: impl PgExecutor<'e>,
        link_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<Option<RegistrationRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            registration_columns!(),
            " FROM pending_registrations WHERE link_hash = $1 AND link_expires_at > $2 \
             AND expires_at > $2"
        );
        Ok(sqlx::query_as::<_, RegistrationRecord>(sql)
            .bind(link_hash.as_bytes().as_slice())
            .bind(now)
            .fetch_optional(executor)
            .await?)
    }

    /// The live registration whose handle is `handle_hash`.
    pub(crate) async fn find_by_handle<'e>(
        executor: impl PgExecutor<'e>,
        handle_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<Option<RegistrationRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            registration_columns!(),
            " FROM pending_registrations WHERE handle_hash = $1 AND expires_at > $2"
        );
        Ok(sqlx::query_as::<_, RegistrationRecord>(sql)
            .bind(handle_hash.as_bytes().as_slice())
            .bind(now)
            .fetch_optional(executor)
            .await?)
    }

    /// Row-locks a live registration (`FOR UPDATE`) in the caller's
    /// transaction.
    pub(crate) async fn lock(
        conn: &mut PgConnection,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<RegistrationRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            registration_columns!(),
            " FROM pending_registrations WHERE id = $1 AND expires_at > $2 FOR UPDATE"
        );
        Ok(sqlx::query_as::<_, RegistrationRecord>(sql)
            .bind(id)
            .bind(now)
            .fetch_optional(conn)
            .await?)
    }

    /// The newest live registration of `user`.
    pub(crate) async fn newest_live<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Option<RegistrationRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            registration_columns!(),
            " FROM pending_registrations WHERE user_id = $1 AND expires_at > $2 \
             ORDER BY created_at DESC, id DESC LIMIT 1"
        );
        Ok(sqlx::query_as::<_, RegistrationRecord>(sql)
            .bind(user)
            .bind(now)
            .fetch_optional(executor)
            .await?)
    }

    /// Every live registration of `user`, newest first (data export).
    pub(crate) async fn live_for_user<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<RegistrationRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            registration_columns!(),
            " FROM pending_registrations WHERE user_id = $1 AND expires_at > $2 \
             ORDER BY created_at DESC, id DESC"
        );
        Ok(sqlx::query_as::<_, RegistrationRecord>(sql)
            .bind(user)
            .bind(now)
            .fetch_all(executor)
            .await?)
    }

    /// Deletes the oldest registrations of `user` so that at most `keep`
    /// remain. Returns the number deleted.
    pub(crate) async fn trim(
        conn: &mut PgConnection,
        user: UserId,
        keep: i64,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "DELETE FROM pending_registrations WHERE id IN (SELECT id FROM pending_registrations \
             WHERE user_id = $1 ORDER BY created_at DESC, id DESC OFFSET $2)",
        )
        .bind(user)
        .bind(keep)
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }

    /// Replaces the link and code of a registration (resend). The attempt
    /// counters are kept: a resend never grants new guesses.
    pub(crate) async fn rotate(
        conn: &mut PgConnection,
        id: Uuid,
        secrets: &RotatedSecrets<'_>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE pending_registrations SET link_hash = $2, link_expires_at = $3, \
             code_hash = $4, code_expires_at = $5 WHERE id = $1",
        )
        .bind(id)
        .bind(secrets.link_hash.as_bytes().as_slice())
        .bind(secrets.link_expires_at)
        .bind(secrets.code_hash.as_bytes().as_slice())
        .bind(secrets.code_expires_at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Counts a wrong code. Returns the new count.
    pub(crate) async fn record_code_failure(
        conn: &mut PgConnection,
        id: Uuid,
    ) -> Result<i32, StoreError> {
        let (attempts,): (i32,) = sqlx::query_as(
            "UPDATE pending_registrations SET code_attempts = LEAST(code_attempts + 1, 100) \
             WHERE id = $1 RETURNING code_attempts",
        )
        .bind(id)
        .fetch_one(conn)
        .await?;
        Ok(attempts)
    }

    /// Counts a wrong "password you chose" answer. Returns the new count.
    pub(crate) async fn record_password_failure(
        conn: &mut PgConnection,
        id: Uuid,
    ) -> Result<i32, StoreError> {
        let (attempts,): (i32,) = sqlx::query_as(
            "UPDATE pending_registrations SET password_attempts = LEAST(password_attempts + 1, 100) \
             WHERE id = $1 RETURNING password_attempts",
        )
        .bind(id)
        .fetch_one(conn)
        .await?;
        Ok(attempts)
    }

    /// Deletes every registration of `user` (completion, or the account
    /// left verification by another route). Returns the number deleted.
    pub(crate) async fn delete_for_user(
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM pending_registrations WHERE user_id = $1")
            .bind(user)
            .execute(conn)
            .await?;
        Ok(result.rows_affected())
    }

    /// Deletes one registration.
    pub(crate) async fn delete(conn: &mut PgConnection, id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM pending_registrations WHERE id = $1")
            .bind(id)
            .execute(conn)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Deletes up to `limit` expired registrations (ACC-05 cleanup;
    /// `FOR UPDATE SKIP LOCKED`, multi-instance safe).
    pub(crate) async fn delete_expired(
        conn: &mut PgConnection,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "DELETE FROM pending_registrations WHERE id IN (SELECT id FROM pending_registrations \
             WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(now)
        .bind(i64::from(limit))
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }
}
