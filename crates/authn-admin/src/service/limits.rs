//! Blast-radius limits of a compromised admin account (K-08) and of the
//! expensive audit chain verification (K-09).
//!
//! * **Emergency operations** (ADM-06): a per-admin budget
//!   (`emergency_per_admin`), a budget of all admins together
//!   (`emergency_global`) and a cool-down between two runs of the *same*
//!   operation (`emergency_cooldown`). One compromised console session
//!   cannot cause repeated platform-wide outages.
//! * **Actions on another platform admin** (suspend, revoke sessions,
//!   unlock): a per-admin and a global budget, so a compromised admin
//!   cannot sweep the other admins out.
//! * **Break-glass accounts** (ADM-05) are only subject to their own
//!   per-admin budgets: an attacker exhausting the shared (global /
//!   cool-down) budgets must not block the recovery account.
//! * **Four-eyes requests** (K-66): at most
//!   [`MAX_PENDING_APPROVALS`] pending and [`MAX_APPROVALS_PER_HOUR`]
//!   requests per hour per requester, counted in `admin_approvals` under a
//!   per-requester transaction lock — one admin cannot flood the others
//!   with approval prompts (approval fatigue).
//! * Every refusal answers `429 rate_limited` with `Retry-After`, counts
//!   `authn_admin_throttled_total{limit}` and records a **high-priority**
//!   failed `admin.action` event (`reason`: the limit) — alert on either.
//!
//! The rate limiter uses its own connection: checks run **before** the
//! action's transaction is opened (never wait for a second pooled
//! connection while holding one).

use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::ports::{Actor, RateLimitKey, RateLimitPolicy, SecurityEvent, SecurityEventKind};
use time::OffsetDateTime;

use super::AdminService;
use crate::guard::AdminCaller;
use crate::metrics;

/// Most pending four-eyes requests of one admin at a time (K-66).
pub(crate) const MAX_PENDING_APPROVALS: i64 = 3;
/// Most four-eyes requests of one admin per hour, decided ones included
/// (K-66).
pub(crate) const MAX_APPROVALS_PER_HOUR: i64 = 10;

/// Rate-limit actions (stable key names).
pub(crate) mod keys {
    pub(crate) const EMERGENCY: &str = "admin_emergency";
    pub(crate) const ADMIN_TARGET: &str = "admin_target_admin";
    pub(crate) const AUDIT_VERIFY: &str = "admin_audit_verify";
    #[cfg(feature = "passkey")]
    pub(crate) const ENROLLMENT: &str = "admin_passkey_enrollment";
}

/// The cool-down key of an emergency operation.
fn cooldown_key(action: &'static str) -> &'static str {
    match action {
        "revoke_all_sessions" => "admin_emergency_cooldown_revoke_all_sessions",
        "rotate_signing_key" => "admin_emergency_cooldown_rotate_signing_key",
        "force_password_change_before" => "admin_emergency_cooldown_force_password_change",
        _ => "admin_emergency_cooldown_other",
    }
}

/// Which limit refused a request (metric label, audit reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Limit {
    EmergencyPerAdmin,
    EmergencyGlobal,
    EmergencyCooldown,
    AdminTargetPerAdmin,
    AdminTargetGlobal,
    AuditVerifyPerAdmin,
    AuditVerifyRunning,
    ApprovalsPendingPerAdmin,
    ApprovalsPerHourPerAdmin,
}

impl Limit {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EmergencyPerAdmin => "emergency_per_admin",
            Self::EmergencyGlobal => "emergency_global",
            Self::EmergencyCooldown => "emergency_cooldown",
            Self::AdminTargetPerAdmin => "admin_target_per_admin",
            Self::AdminTargetGlobal => "admin_target_global",
            Self::AuditVerifyPerAdmin => "audit_verify_per_admin",
            Self::AuditVerifyRunning => "audit_verify_running",
            Self::ApprovalsPendingPerAdmin => "approvals_pending_per_admin",
            Self::ApprovalsPerHourPerAdmin => "approvals_per_hour_per_admin",
        }
    }
}

impl AdminService {
    async fn consume(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<Option<std::time::Duration>, AuthError> {
        let decision = self.deps().rate_limiter.check(key, policy, 1).await?;
        Ok(if decision.allowed {
            None
        } else {
            Some(
                decision
                    .retry_after
                    .unwrap_or(std::time::Duration::from_secs(1)),
            )
        })
    }

    /// K-08: the budgets of an emergency operation `action`.
    pub(crate) async fn check_emergency(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        action: &'static str,
    ) -> Result<(), AuthError> {
        let settings = self.settings();
        let mut checks = vec![(
            Limit::EmergencyPerAdmin,
            RateLimitKey::user(keys::EMERGENCY, caller.user_id()),
            settings.emergency_per_admin,
        )];
        if !caller.is_break_glass() {
            checks.push((
                Limit::EmergencyCooldown,
                RateLimitKey::global(cooldown_key(action)),
                RateLimitPolicy::new(1, settings.emergency_cooldown),
            ));
            checks.push((
                Limit::EmergencyGlobal,
                RateLimitKey::global(keys::EMERGENCY),
                settings.emergency_global,
            ));
        }
        self.apply(caller, ctx, action, checks).await
    }

    /// K-08: the budgets of an action whose target is a platform admin.
    pub(crate) async fn check_admin_target(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        action: &'static str,
    ) -> Result<(), AuthError> {
        let settings = self.settings();
        let mut checks = vec![(
            Limit::AdminTargetPerAdmin,
            RateLimitKey::user(keys::ADMIN_TARGET, caller.user_id()),
            settings.admin_target_per_admin,
        )];
        if !caller.is_break_glass() {
            checks.push((
                Limit::AdminTargetGlobal,
                RateLimitKey::global(keys::ADMIN_TARGET),
                settings.admin_target_global,
            ));
        }
        self.apply(caller, ctx, action, checks).await
    }

    /// K-09: the per-admin budget of chain verifications.
    pub(crate) async fn check_audit_verify(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let checks = vec![(
            Limit::AuditVerifyPerAdmin,
            RateLimitKey::user(keys::AUDIT_VERIFY, caller.user_id()),
            self.settings().audit_verify_per_admin,
        )];
        self.apply(caller, ctx, "audit_chain_verified", checks)
            .await
    }

    async fn apply(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        action: &'static str,
        checks: Vec<(Limit, RateLimitKey, RateLimitPolicy)>,
    ) -> Result<(), AuthError> {
        for (limit, key, policy) in checks {
            if let Some(retry_after) = self.consume(&key, policy).await? {
                return Err(self
                    .throttled(caller, ctx, action, limit, retry_after)
                    .await);
            }
        }
        Ok(())
    }

    /// Records a refusal (metric + high-priority event) and returns the
    /// `429 rate_limited` error.
    pub(crate) async fn throttled(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        action: &'static str,
        limit: Limit,
        retry_after: std::time::Duration,
    ) -> AuthError {
        metrics::throttled(limit.as_str());
        tracing::warn!(
            admin = %caller.user_id(),
            action,
            limit = limit.as_str(),
            "admin action throttled (high priority)"
        );
        let now: OffsetDateTime = self.now();
        let event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
            .with_context(ctx)
            .with_actor(Actor::User(caller.user_id()))
            .with_meta("action", action)
            .with_meta("priority", "high")
            .with_meta("limit", limit.as_str())
            .with_meta("break_glass", caller.is_break_glass())
            .failed(limit.as_str());
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::error!(
                code = err.code().code(),
                "could not audit a throttled admin action"
            );
        }
        AuthError::new(authn_core::error::codes::common::RATE_LIMITED)
            .with_retry_after(retry_after.max(std::time::Duration::from_secs(1)))
    }
}
