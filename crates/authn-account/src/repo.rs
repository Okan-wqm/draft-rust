//! SQL for the tables owned by authn-account (`user_profiles`,
//! `terms_versions`, `consents`, `account_deletions`, `email_reservations`)
//! plus the few reads this crate needs on shared tables (documented in
//! `docs/architecture/contract-change-requests.md`).
//!
//! Every query is a runtime-checked `&'static str` with bind parameters.
//! Writes take `&mut PgConnection` so they always run in the caller's
//! transaction.

use std::net::IpAddr;

use authn_core::config::account::TermsDocument;
use authn_core::domain::{AccountStatus, Locale};
use authn_core::id::{DeletionRequestId, OneTimeTokenId, TermsVersionId, UserId};
use authn_store::{StoreError, TokenPurpose};
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

/// A `user_profiles` row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct ProfileRecord {
    pub display_name: Option<String>,
    pub locale: Locale,
    pub time_zone: String,
    pub updated_at: OffsetDateTime,
}

/// Profile values to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileValues<'a> {
    pub display_name: Option<&'a str>,
    pub locale: Locale,
    pub time_zone: &'a str,
}

pub(crate) struct ProfileRepository;

impl ProfileRepository {
    pub(crate) async fn find<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
    ) -> Result<Option<ProfileRecord>, StoreError> {
        Ok(sqlx::query_as::<_, ProfileRecord>(
            "SELECT display_name, locale, time_zone, updated_at FROM user_profiles WHERE user_id = $1",
        )
        .bind(user)
        .fetch_optional(executor)
        .await?)
    }

    pub(crate) async fn upsert(
        conn: &mut PgConnection,
        user: UserId,
        values: &ProfileValues<'_>,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO user_profiles (user_id, display_name, locale, time_zone, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $5) \
             ON CONFLICT (user_id) DO UPDATE SET display_name = EXCLUDED.display_name, \
               locale = EXCLUDED.locale, time_zone = EXCLUDED.time_zone",
        )
        .bind(user)
        .bind(values.display_name)
        .bind(values.locale)
        .bind(values.time_zone)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(())
    }
}

/// A `terms_versions` row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct TermsVersionRecord {
    pub id: TermsVersionId,
    pub document: TermsDocument,
    pub version: String,
    pub url: Option<String>,
    pub published_at: OffsetDateTime,
    pub requires_reacceptance: bool,
}

pub(crate) struct TermsRepository;

impl TermsRepository {
    /// Inserts a version unless `(document, version)` exists. Returns
    /// whether a row was inserted.
    pub(crate) async fn insert_if_missing(
        conn: &mut PgConnection,
        record: &TermsVersionRecord,
        now: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO terms_versions (id, document, version, url, published_at, \
               requires_reacceptance, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (document, version) DO NOTHING",
        )
        .bind(record.id)
        .bind(record.document)
        .bind(&record.version)
        .bind(record.url.as_deref())
        .bind(record.published_at)
        .bind(record.requires_reacceptance)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// The current (latest published, not in the future) version of every
    /// document.
    pub(crate) async fn current<'e>(
        executor: impl PgExecutor<'e>,
        now: OffsetDateTime,
    ) -> Result<Vec<TermsVersionRecord>, StoreError> {
        Ok(sqlx::query_as::<_, TermsVersionRecord>(
            "SELECT DISTINCT ON (document) id, document, version, url, published_at, \
               requires_reacceptance FROM terms_versions WHERE published_at <= $1 \
             ORDER BY document, published_at DESC, created_at DESC, id DESC",
        )
        .bind(now)
        .fetch_all(executor)
        .await?)
    }

    /// A version by document and label.
    pub(crate) async fn find<'e>(
        executor: impl PgExecutor<'e>,
        document: TermsDocument,
        version: &str,
    ) -> Result<Option<TermsVersionRecord>, StoreError> {
        Ok(sqlx::query_as::<_, TermsVersionRecord>(
            "SELECT id, document, version, url, published_at, requires_reacceptance \
             FROM terms_versions WHERE document = $1 AND version = $2",
        )
        .bind(document)
        .bind(version)
        .fetch_optional(executor)
        .await?)
    }
}

/// A consent joined with its document version.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct ConsentRecord {
    pub terms_version_id: TermsVersionId,
    pub document: TermsDocument,
    pub version: String,
    pub accepted_at: OffsetDateTime,
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
}

pub(crate) struct ConsentRepository;

impl ConsentRepository {
    /// Records an acceptance (idempotent per user and version). Returns
    /// whether a new row was written.
    pub(crate) async fn record(
        conn: &mut PgConnection,
        user: UserId,
        version: TermsVersionId,
        at: OffsetDateTime,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO consents (id, user_id, terms_version_id, accepted_at, ip, user_agent) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (user_id, terms_version_id) DO NOTHING",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(user)
        .bind(version)
        .bind(at)
        .bind(ip)
        .bind(user_agent)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Every consent of a user, newest first.
    pub(crate) async fn for_user<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
    ) -> Result<Vec<ConsentRecord>, StoreError> {
        Ok(sqlx::query_as::<_, ConsentRecord>(
            "SELECT c.terms_version_id, t.document, t.version, c.accepted_at, c.ip, c.user_agent \
             FROM consents c JOIN terms_versions t ON t.id = c.terms_version_id \
             WHERE c.user_id = $1 ORDER BY c.accepted_at DESC, t.document",
        )
        .bind(user)
        .fetch_all(executor)
        .await?)
    }
}

/// An `account_deletions` row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct DeletionRecord {
    pub id: DeletionRequestId,
    pub user_id: UserId,
    pub status: String,
    pub requested_at: OffsetDateTime,
    pub scheduled_for: OffsetDateTime,
    pub cancelled_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
    pub previous_status: Option<AccountStatus>,
}

macro_rules! deletion_columns {
    () => {
        "id, user_id, status, requested_at, scheduled_for, cancelled_at, completed_at, previous_status"
    };
}

pub(crate) struct DeletionRepository;

impl DeletionRepository {
    pub(crate) async fn schedule(
        conn: &mut PgConnection,
        user: UserId,
        requested_at: OffsetDateTime,
        scheduled_for: OffsetDateTime,
        previous_status: AccountStatus,
    ) -> Result<DeletionRecord, StoreError> {
        let sql = concat!(
            "INSERT INTO account_deletions (id, user_id, status, requested_at, scheduled_for, \
             previous_status) VALUES ($1, $2, 'scheduled', $3, $4, $5) RETURNING ",
            deletion_columns!()
        );
        Ok(sqlx::query_as::<_, DeletionRecord>(sql)
            .bind(DeletionRequestId::generate())
            .bind(user)
            .bind(requested_at)
            .bind(scheduled_for)
            .bind(previous_status)
            .fetch_one(conn)
            .await?)
    }

    pub(crate) async fn find_scheduled<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
    ) -> Result<Option<DeletionRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            deletion_columns!(),
            " FROM account_deletions WHERE user_id = $1 AND status = 'scheduled'"
        );
        Ok(sqlx::query_as::<_, DeletionRecord>(sql)
            .bind(user)
            .fetch_optional(executor)
            .await?)
    }

    pub(crate) async fn cancel(
        conn: &mut PgConnection,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Option<DeletionRecord>, StoreError> {
        let sql = concat!(
            "UPDATE account_deletions SET status = 'cancelled', cancelled_at = $2 \
             WHERE user_id = $1 AND status = 'scheduled' RETURNING ",
            deletion_columns!()
        );
        Ok(sqlx::query_as::<_, DeletionRecord>(sql)
            .bind(user)
            .bind(now)
            .fetch_optional(conn)
            .await?)
    }

    pub(crate) async fn complete(
        conn: &mut PgConnection,
        id: DeletionRequestId,
        now: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE account_deletions SET status = 'completed', completed_at = $2 \
             WHERE id = $1 AND status = 'scheduled'",
        )
        .bind(id)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Claims one due deletion (multi-instance safe: `FOR UPDATE SKIP
    /// LOCKED`), skipping the ids in `skip` (blocked in this run).
    pub(crate) async fn claim_due(
        conn: &mut PgConnection,
        now: OffsetDateTime,
        skip: &[uuid::Uuid],
    ) -> Result<Option<DeletionRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            deletion_columns!(),
            " FROM account_deletions WHERE status = 'scheduled' AND scheduled_for <= $1 \
             AND NOT (id = ANY($2)) ORDER BY scheduled_for, id LIMIT 1 FOR UPDATE SKIP LOCKED"
        );
        Ok(sqlx::query_as::<_, DeletionRecord>(sql)
            .bind(now)
            .bind(skip)
            .fetch_optional(conn)
            .await?)
    }

    pub(crate) async fn for_user<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
    ) -> Result<Vec<DeletionRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            deletion_columns!(),
            " FROM account_deletions WHERE user_id = $1 ORDER BY requested_at DESC"
        );
        Ok(sqlx::query_as::<_, DeletionRecord>(sql)
            .bind(user)
            .fetch_all(executor)
            .await?)
    }
}

/// An `email_reservations` row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct ReservationRecord {
    pub email_normalized: String,
    pub user_id: UserId,
    pub reserved_until: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

pub(crate) struct ReservationRepository;

impl ReservationRepository {
    /// Reserves `email_normalized` for `user` until `until` (replaces any
    /// earlier reservation of the address).
    pub(crate) async fn reserve(
        conn: &mut PgConnection,
        email_normalized: &str,
        user: UserId,
        until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO email_reservations (email_normalized, user_id, reserved_until, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (email_normalized) DO UPDATE SET \
               user_id = EXCLUDED.user_id, reserved_until = EXCLUDED.reserved_until, \
               created_at = EXCLUDED.created_at",
        )
        .bind(email_normalized)
        .bind(user)
        .bind(until)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// The owner of an active reservation of the address, if any.
    pub(crate) async fn active_owner<'e>(
        executor: impl PgExecutor<'e>,
        email_normalized: &str,
        now: OffsetDateTime,
    ) -> Result<Option<UserId>, StoreError> {
        let row: Option<(UserId,)> = sqlx::query_as(
            "SELECT user_id FROM email_reservations WHERE email_normalized = $1 AND reserved_until > $2",
        )
        .bind(email_normalized)
        .bind(now)
        .fetch_optional(executor)
        .await?;
        Ok(row.map(|(user,)| user))
    }

    /// Releases a reservation held by `user`.
    pub(crate) async fn release(
        conn: &mut PgConnection,
        email_normalized: &str,
        user: UserId,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM email_reservations WHERE email_normalized = $1 AND user_id = $2")
            .bind(email_normalized)
            .bind(user)
            .execute(conn)
            .await?;
        Ok(())
    }

    pub(crate) async fn for_user<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
    ) -> Result<Vec<ReservationRecord>, StoreError> {
        Ok(sqlx::query_as::<_, ReservationRecord>(
            "SELECT email_normalized, user_id, reserved_until, created_at FROM email_reservations \
             WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user)
        .fetch_all(executor)
        .await?)
    }

    pub(crate) async fn delete_expired(
        conn: &mut PgConnection,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "DELETE FROM email_reservations WHERE email_normalized IN (SELECT email_normalized \
             FROM email_reservations WHERE reserved_until <= $1 ORDER BY reserved_until \
             LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(now)
        .bind(i64::from(limit))
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }
}

/// An active `email_change_revert` link (target and expiry only).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct RevertLinkRecord {
    pub target: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// `email_change_revert` rows of `one_time_tokens` — a purpose owned by
/// this crate (contracts §5; registered in the change-request log).
pub(crate) struct RevertLinkRepository;

impl RevertLinkRepository {
    /// Revokes the user's active revert links issued at or after the link
    /// `(created_at, id)` — the links of *later* e-mail changes. Links of
    /// earlier changes are kept (ACC-07: a revert performed from an
    /// intermediate address must not cancel the original owner's revert).
    pub(crate) async fn revoke_issued_since(
        conn: &mut PgConnection,
        user: UserId,
        created_at: OffsetDateTime,
        id: OneTimeTokenId,
        now: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "UPDATE one_time_tokens SET revoked_at = $5 WHERE user_id = $1 AND purpose = $2 \
             AND consumed_at IS NULL AND revoked_at IS NULL AND (created_at, id) >= ($3, $4)",
        )
        .bind(user)
        .bind(TokenPurpose::EmailChangeRevert.as_str())
        .bind(created_at)
        .bind(id)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }

    /// The user's revert links that can still be used.
    pub(crate) async fn active(
        conn: &mut PgConnection,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<RevertLinkRecord>, StoreError> {
        Ok(sqlx::query_as::<_, RevertLinkRecord>(
            "SELECT target, expires_at FROM one_time_tokens WHERE user_id = $1 AND purpose = $2 \
             AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $3",
        )
        .bind(user)
        .bind(TokenPurpose::EmailChangeRevert.as_str())
        .bind(now)
        .fetch_all(conn)
        .await?)
    }
}

/// Reads on shared tables (registered in the change-request log).
pub(crate) struct SharedReads;

/// An active one-time token of an account purpose (export view; the hash is
/// never selected).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct PendingTokenRecord {
    pub purpose: String,
    pub target: Option<String>,
    pub created_ip: Option<IpAddr>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl SharedReads {
    /// Claims one never-verified account created before `created_before`
    /// (ACC-05 purge; `FOR UPDATE SKIP LOCKED`, multi-instance safe),
    /// skipping the ids in `skip`.
    pub(crate) async fn claim_expired_unverified(
        conn: &mut PgConnection,
        created_before: OffsetDateTime,
        skip: &[uuid::Uuid],
    ) -> Result<Option<UserId>, StoreError> {
        let row: Option<(UserId,)> = sqlx::query_as(
            "SELECT id FROM users WHERE status = 'pending_verification' \
             AND email_verified_at IS NULL AND created_at < $1 AND NOT (id = ANY($2)) \
             ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .bind(created_before)
        .bind(skip)
        .fetch_optional(conn)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Claims one account whose temporary lock has ended (ACC-06).
    pub(crate) async fn claim_expired_lock(
        conn: &mut PgConnection,
        now: OffsetDateTime,
        skip: &[uuid::Uuid],
    ) -> Result<Option<UserId>, StoreError> {
        let row: Option<(UserId,)> = sqlx::query_as(
            "SELECT id FROM users WHERE status = 'locked' AND locked_until <= $1 \
             AND NOT (id = ANY($2)) ORDER BY locked_until, id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .bind(now)
        .bind(skip)
        .fetch_optional(conn)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Active tokens of this crate's purposes for the data export (ACC-10).
    pub(crate) async fn pending_account_tokens<'e>(
        executor: impl PgExecutor<'e>,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<PendingTokenRecord>, StoreError> {
        let purposes: Vec<&str> = crate::ACCOUNT_TOKEN_PURPOSES
            .iter()
            .map(|p| p.as_str())
            .collect();
        Ok(sqlx::query_as::<_, PendingTokenRecord>(
            "SELECT purpose, target, created_ip, created_at, expires_at FROM one_time_tokens \
             WHERE user_id = $1 AND purpose = ANY($2) AND consumed_at IS NULL \
             AND revoked_at IS NULL AND expires_at > $3 ORDER BY created_at DESC",
        )
        .bind(user)
        .bind(&purposes)
        .bind(now)
        .fetch_all(executor)
        .await?)
    }
}

/// Serializes work on one e-mail address for the rest of the transaction
/// (registration, e-mail change and revert check-then-write sequences).
pub(crate) async fn lock_email(
    conn: &mut PgConnection,
    email_normalized: &str,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("authn:account:email:{email_normalized}"))
        .execute(conn)
        .await?;
    Ok(())
}

/// Locks several addresses in a deterministic order (no deadlocks between
/// concurrent multi-address operations).
pub(crate) async fn lock_emails(
    conn: &mut PgConnection,
    emails: &[&str],
) -> Result<(), StoreError> {
    let mut sorted: Vec<&str> = emails.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    for email in sorted {
        lock_email(&mut *conn, email).await?;
    }
    Ok(())
}
