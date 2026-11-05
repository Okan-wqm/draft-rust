//! Session revocation (SES-12, SES-15): [`PgSessionRevoker`], the
//! `SessionRevoker` port implementation.
//!
//! * Every method runs in the caller's transaction (`&mut PgConnection`):
//!   the sessions, their refresh-token families, the trusted devices
//!   (`RevokeOptions::also_trusted_devices`, via authn-mfa's
//!   `revoke_trusted_devices_in_tx` on the same connection), the audit event
//!   and the `session.revoked` domain events commit or roll back together.
//! * User-wide revocations also close the user's pending logins
//!   (`auth_challenges`; for `password_changed` all but those whose
//!   outstanding steps include the password change or the e-mail
//!   verification, see
//!   `pending_logins_ended_by`) and the impersonation sessions the user
//!   started as an admin (ADM-04).
//! * A revoked session is rejected on the very next request: cookie and
//!   bearer authentication read the `sessions` row (no cache); revocation
//!   also clears the stored web token hash.
//! * Domain events (`session.revoked`, AUD-07 webhooks) are published only
//!   for sessions with an active organization (webhooks are per
//!   organization), and not for [`SessionRevoker::revoke_everything`] /
//!   [`SessionRevoker::revoke_everything_except`].

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, SessionId, UserId};
use authn_core::ports::{
    Actor, AuditSink, Clock, DomainEvent, DomainEventKind, EventPublisher, RevocationReason,
    RevokeOptions, SecurityEvent, SecurityEventKind, SessionRevoker,
};
use authn_mfa::MfaService;
use sqlx::PgConnection;

use crate::metrics;
use crate::store::challenges;
use crate::store::sessions::{self, Revoked, Target};

/// Who asked for a revocation (audit attribution of this crate's own
/// endpoints; port calls are attributed to the system).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Attribution<'a> {
    pub(crate) actor: Actor,
    pub(crate) impersonator: Option<UserId>,
    pub(crate) ctx: &'a RequestContext,
}

/// The `SessionRevoker` port implementation (SES-15). Cheap to clone.
///
/// Construct it before `AccountService` (which needs a revoker) and wrap it
/// with `authn_account::AccountAwareSessionRevoker` for the other modules;
/// see the crate README.
#[derive(Clone)]
pub struct PgSessionRevoker {
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    events: Arc<dyn EventPublisher>,
    mfa: MfaService,
}

impl std::fmt::Debug for PgSessionRevoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PgSessionRevoker")
    }
}

impl PgSessionRevoker {
    /// A revoker; `mfa` applies `RevokeOptions::also_trusted_devices`.
    #[must_use]
    pub fn new(
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        events: Arc<dyn EventPublisher>,
        mfa: MfaService,
    ) -> Self {
        Self {
            clock,
            audit,
            events,
            mfa,
        }
    }

    /// Revokes `target` in the caller's transaction and returns the revoked
    /// sessions.
    pub(crate) async fn revoke(
        &self,
        conn: &mut PgConnection,
        target: Target,
        reason: RevocationReason,
        trusted_devices_of: Option<UserId>,
        attribution: Option<Attribution<'_>>,
    ) -> Result<Vec<Revoked>, AuthError> {
        let now = self.clock.now();
        let revoked = sessions::revoke(&mut *conn, target, reason.as_str(), now).await?;
        if let Some((user, keep)) = pending_logins_ended_by(target, reason) {
            let keep_in_flight_steps = reason == RevocationReason::PasswordChanged;
            challenges::close_open(&mut *conn, user, keep, keep_in_flight_steps, now).await?;
        }
        let mut devices = 0;
        if let Some(user) = trusted_devices_of {
            devices = self
                .mfa
                .revoke_trusted_devices_in_tx(&mut *conn, user, reason)
                .await?;
        }
        if !matches!(target, Target::Everything | Target::EverythingExcept(_)) {
            for session in revoked.iter().filter(|s| s.active_org_id.is_some()) {
                let mut event = DomainEvent::new(
                    DomainEventKind::SessionRevoked,
                    now,
                    serde_json::json!({
                        "session_id": session.id,
                        "reason": reason.as_str(),
                    }),
                );
                event.org_id = session.active_org_id;
                event.user_id = Some(session.user_id);
                self.events.publish(&mut *conn, event).await?;
            }
        }
        if !revoked.is_empty() || devices > 0 {
            let kind = if matches!(target, Target::One(_)) {
                SecurityEventKind::SessionRevoked
            } else {
                SecurityEventKind::SessionsRevoked
            };
            let mut event = SecurityEvent::new(kind, now)
                .with_meta("reason", reason.as_str())
                .with_meta("sessions", revoked.len())
                .with_meta("trusted_devices", devices);
            event = match attribution {
                Some(a) => {
                    let mut e = event.with_context(a.ctx).with_actor(a.actor);
                    e.impersonator = a.impersonator;
                    e
                }
                None => event.with_actor(Actor::System),
            };
            if let Some(user) = subject_of(target, &revoked) {
                event = event.with_subject(user);
            }
            if let Target::One(id) = target {
                event = event.with_resource("session", id);
            }
            if let Some(org) = org_of(target) {
                event = event.with_org(org);
            }
            self.audit.record_in_tx(&mut *conn, event).await?;
        }
        metrics::sessions_revoked(reason, revoked.len());
        Ok(revoked)
    }
}

/// Whose pending logins (`auth_challenges`) a revocation also closes:
/// `Some((user, keep))`, `user = None` meaning everyone.
///
/// Every user-wide revocation does — a login started with the old password
/// before a reset, a password change, a suspension, "this wasn't me" or
/// "sign out everywhere" must not be completable afterwards (K-58 audit:
/// `password_changed` used to keep them all open). For
/// [`RevocationReason::PasswordChanged`] the pending logins whose
/// outstanding steps include `change_password` or `verify_email` stay
/// open: those SES-22 steps revoke with that reason *from inside* the
/// login they complete. Neither can be finished by the holder of the old
/// password after somebody else's change: `apply_required_password_change`
/// requires the `must_change_password` flag, which every change clears,
/// and `verify_email` needs a code e-mailed to the mailbox.
fn pending_logins_ended_by(
    target: Target,
    _reason: RevocationReason,
) -> Option<(Option<UserId>, Option<SessionId>)> {
    match target {
        Target::User(user) => Some((Some(user), None)),
        Target::UserExcept(user, keep) => Some((Some(user), Some(keep))),
        Target::Everything => Some((None, None)),
        Target::EverythingExcept(keep) => Some((None, Some(keep))),
        Target::One(_) | Target::UserInOrg(..) | Target::Org(_) => None,
    }
}

fn subject_of(target: Target, revoked: &[Revoked]) -> Option<UserId> {
    match target {
        Target::User(user) | Target::UserExcept(user, _) | Target::UserInOrg(user, _) => Some(user),
        Target::One(_) => revoked.first().map(|r| r.user_id),
        Target::Org(_) | Target::Everything | Target::EverythingExcept(_) => None,
    }
}

fn org_of(target: Target) -> Option<OrgId> {
    match target {
        Target::UserInOrg(_, org) | Target::Org(org) => Some(org),
        _ => None,
    }
}

fn count(revoked: &[Revoked]) -> u64 {
    u64::try_from(revoked.len()).unwrap_or(u64::MAX)
}

#[async_trait]
impl SessionRevoker for PgSessionRevoker {
    async fn revoke_session(
        &self,
        conn: &mut PgConnection,
        session: SessionId,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        let revoked = self
            .revoke(conn, Target::One(session), reason, None, None)
            .await?;
        Ok(!revoked.is_empty())
    }

    async fn revoke_all_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        reason: RevocationReason,
        options: RevokeOptions,
    ) -> Result<u64, AuthError> {
        let devices = options.also_trusted_devices.then_some(user);
        let revoked = self
            .revoke(conn, Target::User(user), reason, devices, None)
            .await?;
        Ok(count(&revoked))
    }

    async fn revoke_all_except(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        keep: SessionId,
        reason: RevocationReason,
        options: RevokeOptions,
    ) -> Result<u64, AuthError> {
        let devices = options.also_trusted_devices.then_some(user);
        let revoked = self
            .revoke(conn, Target::UserExcept(user, keep), reason, devices, None)
            .await?;
        Ok(count(&revoked))
    }

    async fn revoke_for_user_in_org(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        org: OrgId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let revoked = self
            .revoke(conn, Target::UserInOrg(user, org), reason, None, None)
            .await?;
        Ok(count(&revoked))
    }

    async fn revoke_all_for_org(
        &self,
        conn: &mut PgConnection,
        org: OrgId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let revoked = self
            .revoke(conn, Target::Org(org), reason, None, None)
            .await?;
        Ok(count(&revoked))
    }

    async fn revoke_everything(
        &self,
        conn: &mut PgConnection,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let revoked = self
            .revoke(conn, Target::Everything, reason, None, None)
            .await?;
        Ok(count(&revoked))
    }

    async fn revoke_everything_except(
        &self,
        conn: &mut PgConnection,
        keep: SessionId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let revoked = self
            .revoke(conn, Target::EverythingExcept(keep), reason, None, None)
            .await?;
        Ok(count(&revoked))
    }
}
