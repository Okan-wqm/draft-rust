//! Events withheld from the subject's own security-event view (AUD-04,
//! K-62; table `audit_subject_view_holds`, migration `1701`).
//!
//! A module that must keep one of its audit events about a user out of
//! that user's own list for a while — authn-admin's legal restriction of a
//! justification (KVKK art. 28 / GDPR art. 23: the user must not learn of
//! an investigation from their own event list) — adds a hold in the same
//! transaction that records the event. Holds are append-only; an event is
//! hidden while any of its holds lies in the future, then shown again.
//! Staff views (`list_events`, organization logs) are not affected.

use authn_core::error::{AuthError, codes};
use authn_core::id::EventId;
use sqlx::PgConnection;
use time::OffsetDateTime;

/// Longest single hold (K-62: the longest legal restriction period); the
/// table enforces the same bound.
pub const MAX_HOLD: std::time::Duration = std::time::Duration::from_secs(180 * 24 * 3600);

/// Hides `event` from its subject's own security-event list until
/// `until` (at most [`MAX_HOLD`] after `now`, else `validation_failed`),
/// in the caller's transaction (after the event was recorded with
/// `record_in_tx` in the same transaction, or committed before). A later
/// hold with a later `until` extends it; an earlier one changes nothing.
pub async fn hide_from_subject_in_tx(
    conn: &mut PgConnection,
    event: EventId,
    until: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    if until <= now {
        return Ok(());
    }
    if until > now + MAX_HOLD {
        return Err(AuthError::new(codes::common::VALIDATION_FAILED)
            .with_context("a subject-view hold lasts at most 180 days"));
    }
    sqlx::query(
        "INSERT INTO audit_subject_view_holds (event_id, hidden_until, created_at) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(event)
    .bind(until)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}
