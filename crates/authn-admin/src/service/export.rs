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
//! restriction note. The restriction is itself an audited admin action
//! (`admin.action`, `restrict_justification`) whose note is that action's
//! justification; that note is restricted as well. Restricted entries are
//! omitted from the export, which states how many were withheld (no
//! content). Restrictions are append-only (`admin_reason_restrictions`,
//! migration `2201`): they cannot be silently lifted or rewritten.

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{EventId, UserId};
use authn_core::ports::{DataExporter, SecurityEventKind};
use serde_json::{Value, json};
use sqlx::PgConnection;
use time::format_description::well_known::Rfc3339;

use super::{ActionOutcome, AdminService, meta};
use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::store;

/// The `admin_actions` section of the personal data export (ACC-10,
/// K-39). The server registers it in `AccountServiceDeps.exporters`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdminActionsDataExporter;

/// How the acting staff member appears in an export.
pub const STAFF_ACTOR: &str = "platform_staff";

#[async_trait]
impl DataExporter for AdminActionsDataExporter {
    fn section(&self) -> &'static str {
        "admin_actions"
    }

    async fn export(&self, conn: &mut PgConnection, user: UserId) -> Result<Value, AuthError> {
        let rows = store::reasons_about(&mut *conn, user).await?;
        let withheld = store::restricted_count(&mut *conn, user).await?;
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
        Ok(json!({
            "entries": entries,
            "withheld_under_legal_restriction": withheld,
        }))
    }
}

impl AdminService {
    /// Restricts the justification of the admin action recorded as `event`
    /// from the subject's data export (K-39). `note` is mandatory (same
    /// rules as any justification) and becomes the justification of this
    /// audited action, itself restricted. Unknown events and events without
    /// a justification about a user are `404`; the caller's own entries are
    /// `admin_target_not_allowed`. Restricting twice is recorded but
    /// changes nothing (`changed: false`).
    pub async fn restrict_justification(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        event: EventId,
        note: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "restrict_justification";
        let mut tx = self.begin().await?;
        let (subject, already) = store::lock_reason(&mut tx, event)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let subject = subject.ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if subject == caller.user_id() {
            return Err(AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
                .with_context("admins cannot restrict entries about themselves"));
        }
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
                    ("already_restricted", Value::from(already)),
                ]),
            )
            .await?;
        let now = self.now();
        store::insert_restriction(&mut tx, event, restricting, now).await?;
        // The note describes the investigation: withheld as well.
        store::insert_restriction(&mut tx, restricting, restricting, now).await?;
        authn_store::commit(tx).await?;
        Ok(ActionOutcome {
            action: ACTION.to_owned(),
            user_id: subject,
            changed: !already,
            sessions_revoked: 0,
            event_id: restricting,
        })
    }
}
