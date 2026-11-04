//! SQL of authn-admin: only its own table, `admin_action_reasons`
//! (migration `2200`). Every read or write of another module's table goes
//! through that module's API (`UserRepository::{search, stale_passwords,
//! set_admin_flags}` of authn-store; the impersonation event id comes from
//! `SessionIssuer::start_impersonation_audited`). Wave 2B adds its own
//! tables of migration `2201`: `admin_passkey_enrollments` (K-11),
//! `admin_operation_leases` (K-09) and `admin_reason_restrictions` (K-39).

use authn_core::id::{EventId, UserId};
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

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

// --- K-11: break-glass passkey enrollment links (`admin_passkey_enrollments`)

/// Stores a new enrollment link (only the token's SHA-256).
pub(crate) async fn insert_enrollment(
    conn: &mut PgConnection,
    id: Uuid,
    user: UserId,
    token_hash: &[u8; 32],
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_passkey_enrollments (id, user_id, token_hash, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(user)
    .bind(token_hash.as_slice())
    .bind(created_at)
    .bind(expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// The account of a live (unconsumed, unexpired) enrollment link.
#[cfg(feature = "passkey")]
pub(crate) async fn live_enrollment<'e>(
    executor: impl PgExecutor<'e>,
    token_hash: &[u8; 32],
    now: OffsetDateTime,
) -> Result<Option<UserId>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT user_id FROM admin_passkey_enrollments \
         WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2",
    )
    .bind(token_hash.as_slice())
    .bind(now)
    .fetch_optional(executor)
    .await
}

/// Atomically consumes a live enrollment link of `user` (single use).
#[cfg(feature = "passkey")]
pub(crate) async fn consume_enrollment(
    conn: &mut PgConnection,
    token_hash: &[u8; 32],
    user: UserId,
    now: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_passkey_enrollments SET consumed_at = $3 \
         WHERE token_hash = $1 AND user_id = $2 AND consumed_at IS NULL AND expires_at > $3",
    )
    .bind(token_hash.as_slice())
    .bind(user)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Ends every open enrollment link of `user` (a new link replaces them).
pub(crate) async fn expire_enrollments_of(
    conn: &mut PgConnection,
    user: UserId,
    now: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_passkey_enrollments SET consumed_at = $2 \
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

// --- K-09: single-flight leases (`admin_operation_leases`) -----------------

/// Takes the lease `name` for `holder` unless a live lease exists. One
/// auto-committed statement: no connection is held while the operation
/// runs.
pub(crate) async fn acquire_lease<'e>(
    executor: impl PgExecutor<'e>,
    name: &str,
    holder: Uuid,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let taken: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO admin_operation_leases (name, holder, acquired_at, expires_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, \
           acquired_at = EXCLUDED.acquired_at, expires_at = EXCLUDED.expires_at \
         WHERE admin_operation_leases.expires_at <= EXCLUDED.acquired_at \
         RETURNING holder",
    )
    .bind(name)
    .bind(holder)
    .bind(now)
    .bind(expires_at)
    .fetch_optional(executor)
    .await?;
    Ok(taken == Some(holder))
}

/// Releases the lease `name` if `holder` still holds it.
pub(crate) async fn release_lease<'e>(
    executor: impl PgExecutor<'e>,
    name: &str,
    holder: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM admin_operation_leases WHERE name = $1 AND holder = $2")
        .bind(name)
        .bind(holder)
        .execute(executor)
        .await?;
    Ok(())
}

// --- K-39: export of justifications and legal restrictions ----------------

/// A justification about a subject, as exported to that subject (no staff
/// identity).
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct SubjectReason {
    pub(crate) action: String,
    pub(crate) reason: String,
    pub(crate) created_at: OffsetDateTime,
}

/// Unrestricted justifications about `subject`, oldest first.
pub(crate) async fn reasons_about(
    conn: &mut PgConnection,
    subject: UserId,
) -> Result<Vec<SubjectReason>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.action, r.reason, r.created_at FROM admin_action_reasons r \
         WHERE r.subject_user_id = $1 \
           AND NOT EXISTS (SELECT 1 FROM admin_reason_restrictions x WHERE x.event_id = r.event_id) \
         ORDER BY r.created_at, r.event_id",
    )
    .bind(subject)
    .fetch_all(conn)
    .await
}

/// Number of restricted justifications about `subject`.
pub(crate) async fn restricted_count(
    conn: &mut PgConnection,
    subject: UserId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM admin_action_reasons r \
         JOIN admin_reason_restrictions x ON x.event_id = r.event_id \
         WHERE r.subject_user_id = $1",
    )
    .bind(subject)
    .fetch_one(conn)
    .await
}

/// The subject of a stored justification, row-locked (`None`: no
/// justification for that event), and whether it is already restricted.
pub(crate) async fn lock_reason(
    conn: &mut PgConnection,
    event: EventId,
) -> Result<Option<(Option<UserId>, bool)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.subject_user_id, \
                EXISTS (SELECT 1 FROM admin_reason_restrictions x WHERE x.event_id = r.event_id) \
         FROM admin_action_reasons r WHERE r.event_id = $1 FOR KEY SHARE",
    )
    .bind(event)
    .fetch_optional(conn)
    .await
}

/// Restricts the justification of `event` (append-only).
pub(crate) async fn insert_restriction(
    conn: &mut PgConnection,
    event: EventId,
    restricted_by: EventId,
    at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_reason_restrictions (event_id, restricted_by, created_at) \
         VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(event)
    .bind(restricted_by)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}
