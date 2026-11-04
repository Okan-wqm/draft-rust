//! SQL of authn-admin: only its own table, `admin_action_reasons`
//! (migration `2200`). Every read or write of another module's table goes
//! through that module's API (`UserRepository::{search, stale_passwords,
//! set_admin_flags}` of authn-store; the impersonation event id comes from
//! `SessionIssuer::start_impersonation_audited`).

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
