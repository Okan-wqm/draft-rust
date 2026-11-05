//! [`AdminService`]: the platform admin operations (ADM-01 … ADM-08).
//!
//! Every operation takes an [`AdminCaller`] — proof that the ADM-01 guard
//! passed on this request — and the request context. State-changing
//! operations run in **one** transaction that also records the audit event
//! (`admin.action` / `admin.emergency_action`, real actor = the admin,
//! metadata = action code) and stores the justification in
//! `admin_action_reasons` (ADM-08): the change, its audit record and its
//! justification commit or roll back together.

mod actions;
mod approvals;
mod audit;
mod emergency;
#[cfg(feature = "passkey")]
mod enrollment;
mod export;
mod impersonation;
mod limits;
mod users;

use std::sync::Arc;

use authn_account::AccountService;
use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{EventId, UserId};
use authn_core::ports::{
    Actor, AuditSink, Clock, RateLimiter, SecurityEvent, SecurityEventKind, SessionIssuer,
    SessionRevoker,
};
use authn_crypto::envelope::EnvelopeCipher;
use authn_mfa::MfaService;
use authn_password::PasswordService;
use authn_protect::LoginProtection;
use authn_store::{UserRecord, UserRepository};
use authn_webauthn::WebauthnService;
use serde_json::{Map, Value};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

pub use self::actions::{ActionOutcome, ForcedReset};
pub use self::approvals::{ApprovalView, CriticalOperation};
pub use self::audit::{
    AdminAuditEvent, AdminAuditFilter, AuditExport, ChainVerification, VerifiedAnchor,
};
pub use self::emergency::{BulkResetOutcome, EmergencyOutcome, KeyRotationOutcome};
pub use self::export::{AdminActionsDataExporter, RESTRICTION_MAX_PERIOD, STAFF_ACTOR};
pub use self::impersonation::ImpersonationOptions;
pub use self::users::{
    AdminUserDetail, AdminUserSummary, PasswordState, UserSearch, UserStatusFilter,
};
use crate::guard::{AdminCaller, Denial, authorize};
use crate::hooks::SigningKeyCache;
use crate::metrics;
use crate::reason::Justification;
use crate::settings::AdminSettings;
use crate::store;

/// Everything [`AdminService`] needs. The server passes the **same**
/// instances it gives the other modules (the account-aware session
/// revoker, the real `PgAuditSink`, …).
#[derive(Clone)]
pub struct AdminServiceDeps {
    /// Application database pool.
    pub pool: PgPool,
    /// Injected clock.
    pub clock: Arc<dyn Clock>,
    /// Audit sink. Must store events in `audit_events` (the real
    /// `authn_audit::PgAuditSink`): justifications reference them.
    pub audit: Arc<dyn AuditSink>,
    /// Session revocation (authn-session, account-aware wrapper).
    pub sessions: Arc<dyn SessionRevoker>,
    /// Session issuer for impersonation (authn-session).
    pub issuer: Arc<dyn SessionIssuer>,
    /// Account lifecycle (suspend, unsuspend, unlock, e-mail verification).
    pub accounts: AccountService,
    /// MFA reset and status.
    pub mfa: MfaService,
    /// Passkey removal on MFA reset (ADM-03, K-01).
    pub webauthn: WebauthnService,
    /// Password reset e-mails.
    pub passwords: PasswordService,
    /// Soft locks (unlock).
    pub protection: LoginProtection,
    /// Password hashing (unusable password on forced reset).
    pub hasher: authn_crypto::password::PasswordHasher,
    /// Envelope cipher sealing new signing keys (ADM-06).
    pub envelopes: EnvelopeCipher,
    /// In-process signing key cache to drop after an emergency rotation.
    pub signing_keys: Arc<dyn SigningKeyCache>,
    /// Rate limiter (authn-protect) for the blast-radius limits of
    /// emergency and admin-targeting actions, chain verification and
    /// enrollment links (K-08, K-09, K-11).
    pub rate_limiter: Arc<dyn RateLimiter>,
}

struct Inner {
    deps: AdminServiceDeps,
    settings: AdminSettings,
}

/// The admin service (router state via `FromRef`). Cheap to clone.
#[derive(Clone)]
pub struct AdminService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for AdminService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminService")
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

/// Which accounts an action may target. The caller's own account is never
/// a valid target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetPolicy {
    /// Any other account (`unlock`: it only restores access).
    NotSelf,
    /// Any other account except a break-glass account (defensive actions:
    /// suspend, revoke sessions). A compromised admin must not be able to
    /// disable the recovery path of last resort; break-glass accounts are
    /// managed offline (CLI, ADM-05).
    NotBreakGlass,
    /// Neither another platform admin nor a break-glass account
    /// (takeover-enabling actions: MFA reset, password reset, e-mail
    /// verification, unsuspend, impersonation). Those are done offline
    /// through the CLI.
    RegularUsersOnly,
}

impl AdminService {
    /// Creates the service.
    #[must_use]
    pub fn new(deps: AdminServiceDeps, settings: AdminSettings) -> Self {
        Self {
            inner: Arc::new(Inner { deps, settings }),
        }
    }

    /// Settings.
    #[must_use]
    pub fn settings(&self) -> &AdminSettings {
        &self.inner.settings
    }

    pub(crate) fn deps(&self) -> &AdminServiceDeps {
        &self.inner.deps
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    /// The ADM-01 guard: re-reads the caller's account and applies
    /// [`authorize`]. Refusals of real admins (IP allow-list, missing
    /// passkey MFA) are audited; every use of a break-glass account is
    /// recorded as a high-priority `admin.break_glass_used` event (ADM-05).
    pub async fn authorize(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
    ) -> Result<AdminCaller, AuthError> {
        let live = match principal.user_id() {
            Some(user) if principal.impersonation.is_none() => {
                UserRepository::find_by_id(self.pool(), user).await?
            }
            _ => None,
        };
        let now = self.now();
        match authorize(
            principal,
            live.as_ref(),
            ctx.client_ip,
            now,
            self.settings(),
        ) {
            Ok(caller) => {
                if caller.is_break_glass() {
                    self.record_break_glass_use(ctx, &caller, now).await?;
                }
                Ok(caller)
            }
            Err(denial) => {
                metrics::denied(denial.as_str());
                tracing::warn!(
                    denial = denial.as_str(),
                    client_ip = %authn_core::redact::mask_ip(ctx.client_ip),
                    "admin API request refused"
                );
                let audited = matches!(
                    denial,
                    Denial::IpNotAllowed | Denial::PhishingResistantMfaMissing
                );
                if audited && let Some(admin) = live.as_ref() {
                    self.record_denial(ctx, admin, denial, now).await?;
                }
                Err(denial.into_error())
            }
        }
    }

    async fn record_break_glass_use(
        &self,
        ctx: &RequestContext,
        caller: &AdminCaller,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        metrics::break_glass_used();
        tracing::warn!(
            admin = %caller.user_id(),
            "break-glass account used on the admin API (high priority)"
        );
        let event = SecurityEvent::new(SecurityEventKind::BreakGlassUsed, now)
            .with_context(ctx)
            .with_actor(Actor::User(caller.user_id()))
            .with_resource("session", caller.session_id())
            .with_meta("priority", "high")
            .with_meta("surface", "admin_api");
        self.deps().audit.record(event).await
    }

    async fn record_denial(
        &self,
        ctx: &RequestContext,
        admin: &UserRecord,
        denial: Denial,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
            .with_context(ctx)
            .with_actor(Actor::User(admin.id))
            .with_meta("action", "admin_access")
            .failed(denial.as_str());
        self.deps().audit.record(event).await
    }

    /// Starts a transaction.
    pub(crate) async fn begin(&self) -> Result<authn_store::PgTx, AuthError> {
        authn_store::begin(self.pool()).await
    }

    /// Row-locks the target account and applies `policy`. Unknown accounts
    /// are `404 not_found`.
    pub(crate) async fn lock_target(
        &self,
        conn: &mut PgConnection,
        caller: &AdminCaller,
        target: UserId,
        policy: TargetPolicy,
    ) -> Result<UserRecord, AuthError> {
        let record = UserRepository::lock_for_update(conn, target)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        check_target(caller, &record, policy)?;
        Ok(record)
    }

    /// K-08 / K-64: opens the action's transaction with the target row
    /// locked and the admin-targeting budget applied **according to the
    /// locked row**. Returns the transaction, the locked target and
    /// whether the target is another platform admin (the action is then
    /// high priority).
    ///
    /// The budget is consumed before the transaction (the rate limiter uses
    /// its own connection: never wait for a second pooled connection while
    /// holding one) from an unlocked read. If the locked row shows that the
    /// target became an admin in between (a concurrent promotion), the
    /// transaction is rolled back, the budget is consumed and the
    /// transaction is opened again — an action on an admin never runs
    /// without its budget (K-64). At most two rounds: a target that stops
    /// being an admin only over-counts.
    pub(crate) async fn begin_on_target(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        target: UserId,
        policy: TargetPolicy,
        action: &'static str,
    ) -> Result<(authn_store::PgTx, UserRecord, bool), AuthError> {
        let mut budgeted = UserRepository::find_by_id(self.pool(), target)
            .await?
            .is_some_and(|u| u.is_platform_admin && u.id != caller.user_id());
        if budgeted {
            self.check_admin_target(caller, ctx, action).await?;
        }
        loop {
            let mut tx = self.begin().await?;
            let record = self.lock_target(&mut tx, caller, target, policy).await?;
            let is_admin = record.is_platform_admin && record.id != caller.user_id();
            if !is_admin || budgeted {
                return Ok((tx, record, is_admin));
            }
            // Promoted since the unlocked read: release the lock and the
            // connection, then pay the budget and start over.
            tx.rollback().await?;
            tracing::warn!(
                admin = %caller.user_id(),
                action,
                "target became a platform admin during the request; admin-target budget applied"
            );
            self.check_admin_target(caller, ctx, action).await?;
            budgeted = true;
        }
    }

    /// Records the audit event of an admin action in the caller's
    /// transaction and stores its justification (ADM-08). Returns the
    /// event id. Call once, as the last step before committing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_action(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        caller: &AdminCaller,
        kind: SecurityEventKind,
        action: &'static str,
        subject: Option<UserId>,
        reason: Option<&Justification>,
        metadata: Map<String, Value>,
    ) -> Result<EventId, AuthError> {
        self.record_action_outcome(
            conn, ctx, caller, kind, action, subject, reason, metadata, None,
        )
        .await
    }

    /// [`Self::record_action`] with an explicit outcome: `failure` records
    /// a failed (possibly partially applied) action, still with its
    /// justification (ADM-08).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_action_outcome(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        caller: &AdminCaller,
        kind: SecurityEventKind,
        action: &'static str,
        subject: Option<UserId>,
        reason: Option<&Justification>,
        metadata: Map<String, Value>,
        failure: Option<&'static str>,
    ) -> Result<EventId, AuthError> {
        let now = self.now();
        let mut event = SecurityEvent::new(kind, now)
            .with_context(ctx)
            .with_actor(Actor::User(caller.user_id()))
            .with_meta("action", action)
            .with_meta("reason_recorded", reason.is_some());
        if let Some(subject) = subject {
            event = event.with_subject(subject);
        }
        if caller.is_break_glass() {
            event = event
                .with_meta("break_glass", true)
                .with_meta("priority", "high");
        }
        for (key, value) in metadata {
            event.metadata.insert(key, value);
        }
        if let Some(failure) = failure {
            event = event.failed(failure);
        }
        let id = event.id;
        self.deps().audit.record_in_tx(&mut *conn, event).await?;
        if let Some(reason) = reason {
            store::insert_reason(
                conn,
                id,
                Some(caller.user_id()),
                subject,
                action,
                reason.as_str(),
                now,
            )
            .await?;
        }
        metrics::action(action);
        tracing::info!(admin = %caller.user_id(), action, event = %id, "admin action");
        Ok(id)
    }
}

/// The target rules (ADM-03, ADM-04, ADM-05).
pub(crate) fn check_target(
    caller: &AdminCaller,
    target: &UserRecord,
    policy: TargetPolicy,
) -> Result<(), AuthError> {
    if target.id == caller.user_id() {
        return Err(AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
            .with_context("admins cannot act on their own account"));
    }
    let refused = match policy {
        TargetPolicy::NotSelf => false,
        TargetPolicy::NotBreakGlass => target.is_break_glass,
        TargetPolicy::RegularUsersOnly => target.is_platform_admin || target.is_break_glass,
    };
    if refused {
        return Err(AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
            .with_context("not applicable to this platform admin or break-glass account"));
    }
    Ok(())
}

/// A metadata map from key/value pairs.
pub(crate) fn meta<const N: usize>(entries: [(&str, Value); N]) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}
