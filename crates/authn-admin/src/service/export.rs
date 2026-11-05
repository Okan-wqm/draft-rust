//! Admin action justifications in the subject's personal data export
//! (ACC-10, ADM-08, K-39) and their legal restriction.
//!
//! Decision (2026-11-04, on the project owner's behalf): a justification
//! recorded about a user is personal data concerning that user (GDPR
//! art. 15, KVKK art. 11) and is exported to them — the action code, the
//! time and the text — **without** the acting staff member's identity or IP
//! (GDPR art. 15(4), rights of others): the actor is always shown as
//! `platform_staff`.
//!
//! A justification that is part of a fraud or legal investigation can be
//! **restricted** (KVKK art. 28, GDPR art. 23) by an admin with a mandatory
//! restriction note **and a review date** at most 180 days ahead (K-62).
//! The restriction is itself an audited admin action
//! (`admin.action`, `restrict_justification`) whose note is that action's
//! justification; that note is restricted as well. Restrictions are
//! append-only (`admin_reason_restrictions`, migration `2201`; review dates
//! in `admin_reason_restriction_periods`, migration `2202`): they cannot be
//! silently lifted, shortened or rewritten.
//!
//! Decision (K-62, on the project owner's behalf), while a restriction is
//! active:
//! * the restricted entries are omitted from the export **without any
//!   count or placeholder** — a "withheld: 1" line would itself tell the
//!   subject that an investigation exists (GDPR art. 23(2)(h): the subject
//!   is informed only where that is not prejudicial to the purpose of the
//!   restriction);
//! * the restricting action (and every extension) is hidden from the
//!   subject's own security-event list (`authn_audit::holds`), for the
//!   same reason.
//!
//! The restriction ends at its review date unless an admin extends it
//! (`extend_restriction`: mandatory justification, new date at most 180
//! days ahead, audited, its note restricted too). Once it ends, the
//! entries — including the restriction and extension notes — are exported
//! again and the restricting actions appear in the subject's event list:
//! the right of access (GDPR art. 15, KVKK art. 11) is only deferred, never
//! removed, and after the investigation the subject learns that it was
//! deferred and why (transparency, GDPR art. 12; the staff identity stays
//! hidden as for every justification).

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use std::sync::Arc;

use authn_core::id::{EventId, UserId};
use authn_core::ports::{Clock, DataExporter, SecurityEventKind, SystemClock};
use serde_json::{Value, json};
use sqlx::PgConnection;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{ActionOutcome, AdminService, meta};
use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::store;

/// The `admin_actions` section of the personal data export (ACC-10,
/// K-39). The server registers it in `AccountServiceDeps.exporters`
/// (`AdminActionsDataExporter::default()` reads the system clock; tests
/// pass theirs with [`Self::new`]).
#[derive(Clone)]
pub struct AdminActionsDataExporter {
    clock: Arc<dyn Clock>,
}

impl AdminActionsDataExporter {
    /// An exporter deciding which restrictions are active with `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

impl Default for AdminActionsDataExporter {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl std::fmt::Debug for AdminActionsDataExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminActionsDataExporter")
    }
}

/// How the acting staff member appears in an export.
pub const STAFF_ACTOR: &str = "platform_staff";

/// Longest review period of a restriction (K-62).
pub const RESTRICTION_MAX_PERIOD: std::time::Duration =
    std::time::Duration::from_secs(180 * 24 * 3600);

#[async_trait]
impl DataExporter for AdminActionsDataExporter {
    fn section(&self) -> &'static str {
        "admin_actions"
    }

    async fn export(&self, conn: &mut PgConnection, user: UserId) -> Result<Value, AuthError> {
        // K-62: entries under an active restriction are left out without a
        // count (no hint that anything was withheld).
        let rows = store::reasons_about(&mut *conn, user, self.clock.now()).await?;
        let entries: Vec<Value> = rows
            .into_iter()
            .map(|r| {
                json!({
                    "action": r.action,
                    "at": r.created_at.format(&Rfc3339).unwrap_or_default(),
                    "actor": STAFF_ACTOR,
                    "justification": r.reason,
                })
            })
            .collect();
        Ok(json!({ "entries": entries }))
    }
}

/// A review date `review_at` must lie after `now` and at most
/// [`RESTRICTION_MAX_PERIOD`] ahead (K-62).
fn check_review_at(now: OffsetDateTime, review_at: OffsetDateTime) -> Result<(), AuthError> {
    if review_at > now && review_at <= now + RESTRICTION_MAX_PERIOD {
        Ok(())
    } else {
        Err(AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(json!({ "field": "review_at" })))
    }
}

impl AdminService {
    /// Restricts the justification of the admin action recorded as `event`
    /// from the subject's data export until `review_at` (K-39, K-62; at
    /// most 180 days ahead). `note` is mandatory (same rules as any
    /// justification) and becomes the justification of this audited
    /// action, itself restricted; the action is hidden from the subject's
    /// own event list until the restriction ends. Unknown events and events
    /// without a justification about a user are `404`; the caller's own
    /// entries are `admin_target_not_allowed`. Restricting an entry whose
    /// restriction is still active is recorded but changes nothing
    /// (`changed: false`; the review date stays — use
    /// [`Self::extend_restriction`]); a lapsed restriction can be set
    /// again.
    pub async fn restrict_justification(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        event: EventId,
        note: &Justification,
        review_at: OffsetDateTime,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "restrict_justification";
        let now = self.now();
        check_review_at(now, review_at)?;
        let mut tx = self.begin().await?;
        let (subject, current) = self.lock_restrictable(&mut tx, caller, event).await?;
        let active = current.filter(|until| *until > now);
        let until = active.unwrap_or(review_at);
        let restricting = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(subject),
                Some(note),
                meta([
                    ("restricted_event_id", Value::from(event.to_string())),
                    ("already_restricted", Value::from(active.is_some())),
                    (
                        "review_at",
                        Value::from(until.format(&Rfc3339).unwrap_or_default()),
                    ),
                ]),
            )
            .await?;
        store::insert_restriction(&mut tx, event, restricting, now).await?;
        // Links this note to the restriction (an extension extends it too);
        // for an active restriction the date is unchanged.
        store::insert_restriction_period(&mut tx, event, until, restricting, now).await?;
        self.restrict_note(&mut tx, restricting, until, now).await?;
        authn_store::commit(tx).await?;
        Ok(ActionOutcome {
            action: ACTION.to_owned(),
            user_id: subject,
            changed: active.is_none(),
            sessions_revoked: 0,
            event_id: restricting,
        })
    }

    /// Extends an **active** restriction of `event` to `review_at` (K-62):
    /// a later date, at most 180 days ahead, with a mandatory justification.
    /// Audited (`extend_restriction`); the justification and every earlier
    /// restriction note are restricted, and hidden from the subject's
    /// event list, until the new date. A lapsed (or never set) restriction
    /// answers `409 conflict` — restrict it again instead.
    pub async fn extend_restriction(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        event: EventId,
        reason: &Justification,
        review_at: OffsetDateTime,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "extend_restriction";
        let now = self.now();
        check_review_at(now, review_at)?;
        let mut tx = self.begin().await?;
        let (subject, current) = self.lock_restrictable(&mut tx, caller, event).await?;
        let Some(current) = current.filter(|until| *until > now) else {
            return Err(AuthError::new(codes::common::CONFLICT)
                .with_context("no active restriction to extend"));
        };
        if review_at <= current {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(json!({ "field": "review_at" }))
                .with_context("an extension must move the review date later"));
        }
        let notes = store::restriction_notes(&mut tx, event).await?;
        let extending = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(subject),
                Some(reason),
                meta([
                    ("restricted_event_id", Value::from(event.to_string())),
                    (
                        "previous_review_at",
                        Value::from(current.format(&Rfc3339).unwrap_or_default()),
                    ),
                    (
                        "review_at",
                        Value::from(review_at.format(&Rfc3339).unwrap_or_default()),
                    ),
                ]),
            )
            .await?;
        store::insert_restriction_period(&mut tx, event, review_at, extending, now).await?;
        for note in notes {
            store::insert_restriction_period(&mut tx, note, review_at, extending, now).await?;
            authn_audit::hide_from_subject_in_tx(&mut tx, note, review_at, now).await?;
        }
        self.restrict_note(&mut tx, extending, review_at, now)
            .await?;
        authn_store::commit(tx).await?;
        Ok(ActionOutcome {
            action: ACTION.to_owned(),
            user_id: subject,
            changed: true,
            sessions_revoked: 0,
            event_id: extending,
        })
    }

    /// Locks the justification of `event` and checks that the caller may
    /// restrict it: the subject and the current review date, if any.
    async fn lock_restrictable(
        &self,
        conn: &mut PgConnection,
        caller: &AdminCaller,
        event: EventId,
    ) -> Result<(UserId, Option<OffsetDateTime>), AuthError> {
        let (subject, current) = store::lock_reason(&mut *conn, event)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let subject = subject.ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if subject == caller.user_id() {
            return Err(AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
                .with_context("admins cannot restrict entries about themselves"));
        }
        Ok((subject, current))
    }

    /// The note of a restricting / extending action describes the
    /// investigation: restricted until `until` and hidden from the
    /// subject's event list as long.
    async fn restrict_note(
        &self,
        conn: &mut PgConnection,
        note: EventId,
        until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        store::insert_restriction(&mut *conn, note, note, now).await?;
        store::insert_restriction_period(&mut *conn, note, until, note, now).await?;
        authn_audit::hide_from_subject_in_tx(&mut *conn, note, until, now).await?;
        Ok(())
    }
}
