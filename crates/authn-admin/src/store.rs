//! SQL of authn-admin.
//!
//! * `admin_action_reasons` is this crate's own table (migration `2200`).
//! * The read-only queries on `users` / `password_credentials` (owned by
//!   authn-store) and the one on `audit_events` (owned by authn-audit) are
//!   registered as read-only exceptions in
//!   `docs/architecture/contract-change-requests.md` (`## authn-admin`).
//!   Every write to another module's table goes through that module's API.

use authn_core::domain::AccountStatus;
use authn_core::id::{EventId, SessionId, UserId};
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

/// A row of the user listing (no secrets).
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct UserRow {
    pub id: UserId,
    pub email: Option<String>,
    pub email_verified_at: Option<OffsetDateTime>,
    pub status: AccountStatus,
    pub is_platform_admin: bool,
    pub is_break_glass: bool,
    pub created_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

/// Validated filters of the user listing.
#[derive(Debug, Clone, Default)]
pub(crate) struct UserFilter {
    pub email_prefix: Option<String>,
    pub status: Option<AccountStatus>,
    pub platform_admin: Option<bool>,
    pub email_verified: Option<bool>,
    pub created_after: Option<OffsetDateTime>,
    pub created_before: Option<OffsetDateTime>,
}

/// Keyset page of users, newest first (`created_at DESC, id DESC`),
/// fetching `limit + 1` rows.
pub(crate) async fn search_users<'e>(
    executor: impl PgExecutor<'e>,
    filter: &UserFilter,
    after: Option<(OffsetDateTime, UserId)>,
    limit: i64,
) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, email, email_verified_at, status, is_platform_admin, is_break_glass, \
                created_at, last_login_at \
         FROM users \
         WHERE ($1::text IS NULL OR starts_with(email_normalized, $1)) \
           AND ($2::text IS NULL OR status = $2) \
           AND ($3::boolean IS NULL OR is_platform_admin = $3) \
           AND ($4::boolean IS NULL OR (email_verified_at IS NOT NULL) = $4) \
           AND ($5::timestamptz IS NULL OR created_at >= $5) \
           AND ($6::timestamptz IS NULL OR created_at < $6) \
           AND ($7::timestamptz IS NULL OR (created_at, id) < ($7, $8)) \
         ORDER BY created_at DESC, id DESC \
         LIMIT $9",
    )
    .bind(filter.email_prefix.as_deref())
    .bind(filter.status)
    .bind(filter.platform_admin)
    .bind(filter.email_verified)
    .bind(filter.created_after)
    .bind(filter.created_before)
    .bind(after.map(|(at, _)| at))
    .bind(after.map(|(_, id)| id))
    .bind(limit)
    .fetch_all(executor)
    .await
}

/// Users with a password last changed before `before` and not yet forced
/// to change it, after `after` in id order (ADM-06 bulk reset).
pub(crate) async fn stale_password_users(
    conn: &mut PgConnection,
    before: OffsetDateTime,
    after: Option<UserId>,
    limit: i64,
) -> Result<Vec<UserId>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT user_id FROM password_credentials \
         WHERE changed_at < $1 AND NOT must_change \
           AND ($2::uuid IS NULL OR user_id > $2) \
         ORDER BY user_id LIMIT $3",
    )
    .bind(before)
    .bind(after)
    .bind(limit)
    .fetch_all(conn)
    .await
}

/// Stores the justification of an audited admin action.
pub(crate) async fn insert_reason(
    conn: &mut PgConnection,
    event: EventId,
    admin: Option<UserId>,
    subject: Option<UserId>,
    action: &str,
    reason: &str,
    at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_action_reasons \
           (event_id, admin_user_id, subject_user_id, action, reason, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(event)
    .bind(admin)
    .bind(subject)
    .bind(action)
    .bind(reason)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Justifications of the given audit events.
pub(crate) async fn reasons_for<'e>(
    executor: impl PgExecutor<'e>,
    events: &[Uuid],
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as("SELECT event_id, reason FROM admin_action_reasons WHERE event_id = ANY($1)")
        .bind(events)
        .fetch_all(executor)
        .await
}

/// The `admin.impersonation_started` event authn-session recorded for an
/// impersonation session (to attach the justification, ADM-08).
pub(crate) async fn impersonation_event<'e>(
    executor: impl PgExecutor<'e>,
    session: SessionId,
) -> Result<Option<EventId>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM audit_events \
         WHERE kind = 'admin.impersonation_started' AND resource_type = 'session' \
           AND resource_id = $1 \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(session.to_string())
    .fetch_optional(executor)
    .await
}
