//! Security audit events (AUD-01, AUD-03). Owner of this file: authn-audit.
//!
//! Semantics required from implementations:
//! * Events are appended to a tamper-evident hash chain (AUD-02); recording
//!   is append-only.
//! * Personal data (user ids, IP, user agent) is stored separately from the
//!   chained record so that it can be pseudonymised on account deletion
//!   (AUD-05) without breaking the chain.
//! * `record` uses its own short transaction and must succeed even when the
//!   business operation failed (e.g. `login.failed`).
//! * `record_in_tx` writes inside the caller's transaction: the event exists
//!   if and only if the business change commits.
//!
//! Producers must never put secrets, passwords, tokens, OTP codes or
//! free-form user input into `reason` or `metadata` (AUD-03).

use std::net::IpAddr;

use async_trait::async_trait;
use serde::Serialize;
use sqlx::PgConnection;
use time::OffsetDateTime;

use crate::error::AuthError;
use crate::http::RequestContext;
use crate::id::{ApiKeyId, EventId, OrgId, RequestId, ServiceAccountId, UserId};

/// Records security events.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Records an event in its own transaction.
    async fn record(&self, event: SecurityEvent) -> Result<(), AuthError>;

    /// Records an event inside the caller's transaction.
    ///
    /// Appends are serialized on the chain head until the caller commits, so
    /// call this as late as possible in the transaction (ideally as the last
    /// statement before `COMMIT`) and at most once per transaction.
    async fn record_in_tx(
        &self,
        conn: &mut PgConnection,
        event: SecurityEvent,
    ) -> Result<(), AuthError>;

    /// Pseudonymises a user in the audit log (AUD-05), inside the caller's
    /// transaction: removes the user ↔ pseudonym mapping and every
    /// personal-data row (IP, user agent) linked to it. Chained events keep
    /// their now unlinkable pseudonym, so the hash chain stays intact.
    ///
    /// Account deletion (ACC-09) calls this in the same transaction that
    /// removes or anonymises the user row. A user whose status is `deleted`
    /// is never linked again (later events get a one-off pseudonym and no
    /// personal data, even if a mapping was left behind). Hard-deleting the
    /// user row has the same effect through `ON DELETE CASCADE`.
    ///
    /// The default implementation does nothing (test fakes); the real
    /// implementation in `authn-audit` overrides it.
    async fn pseudonymize_subject(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<(), AuthError> {
        let _ = (conn, user);
        Ok(())
    }
}

text_enum! {
    /// Every security event kind (AUD-01). Wire format `<area>.<event>`.
    pub enum SecurityEventKind {
        /// Successful primary login (session created or challenge issued).
        LoginSucceeded => "login.succeeded",
        /// Failed login; `reason` holds the internal reason code.
        LoginFailed => "login.failed",
        /// An MFA / required-action challenge was issued during login.
        LoginChallengeIssued => "login.challenge_issued",
        /// Explicit logout.
        Logout => "logout",
        /// Step-up re-authentication succeeded.
        StepUpSucceeded => "step_up.succeeded",
        /// Step-up re-authentication failed.
        StepUpFailed => "step_up.failed",
        /// Session created.
        SessionCreated => "session.created",
        /// One session revoked.
        SessionRevoked => "session.revoked",
        /// Several / all sessions of a user revoked.
        SessionsRevoked => "session.revoked_bulk",
        /// Active organization switched (SES-17).
        SessionOrgSwitched => "session.org_switched",
        /// A rotated refresh token was replayed; the family was revoked (SES-05).
        RefreshTokenReuseDetected => "session.refresh_token_reused",
        /// Second factor verified.
        MfaVerified => "mfa.verified",
        /// Second factor verification failed.
        MfaFailed => "mfa.failed",
        /// MFA attempts exhausted; temporary lock (MFA-03).
        MfaLocked => "mfa.locked",
        /// Factor enrolled.
        MfaFactorAdded => "mfa.factor_added",
        /// Factor removed.
        MfaFactorRemoved => "mfa.factor_removed",
        /// Recovery codes (re)generated.
        RecoveryCodesGenerated => "mfa.recovery_codes_generated",
        /// Recovery code consumed.
        RecoveryCodeUsed => "mfa.recovery_code_used",
        /// MFA reset by an admin (ADM-03).
        MfaReset => "mfa.reset",
        /// Trusted device registered (MFA-09).
        TrustedDeviceAdded => "mfa.trusted_device_added",
        /// Trusted device(s) revoked.
        TrustedDeviceRevoked => "mfa.trusted_device_revoked",
        /// Password changed by the user.
        PasswordChanged => "password.changed",
        /// Password added to a passwordless account.
        PasswordAdded => "password.added",
        /// Password removed.
        PasswordRemoved => "password.removed",
        /// Password reset requested (logged even for unknown accounts, without
        /// revealing that to the caller).
        PasswordResetRequested => "password.reset_requested",
        /// Password reset completed.
        PasswordResetCompleted => "password.reset_completed",
        /// `must_change_password` set or cleared.
        PasswordChangeRequiredSet => "password.change_required_set",
        /// Stored hash upgraded (CRY-03 / CRY-04).
        PasswordRehashed => "password.rehashed",
        /// Account registered.
        AccountRegistered => "account.registered",
        /// Registration attempted for an existing e-mail (ACC-02).
        AccountRegistrationAttemptExisting => "account.registration_attempt_existing",
        /// E-mail address verified.
        EmailVerified => "account.email_verified",
        /// E-mail change requested.
        EmailChangeRequested => "account.email_change_requested",
        /// E-mail changed.
        EmailChanged => "account.email_changed",
        /// E-mail change reverted from the old address (ACC-07).
        EmailChangeReverted => "account.email_change_reverted",
        /// Account status transition (ACC-06); metadata has `from` / `to`.
        AccountStatusChanged => "account.status_changed",
        /// Account deletion scheduled.
        AccountDeletionScheduled => "account.deletion_scheduled",
        /// Account deletion cancelled.
        AccountDeletionCancelled => "account.deletion_cancelled",
        /// Account deleted / anonymised.
        AccountDeleted => "account.deleted",
        /// Personal data exported (ACC-10).
        AccountDataExported => "account.data_exported",
        /// Terms / privacy policy accepted (ACC-11).
        TermsAccepted => "account.terms_accepted",
        /// Passkey registered.
        PasskeyRegistered => "passkey.registered",
        /// Passkey renamed.
        PasskeyRenamed => "passkey.renamed",
        /// Passkey removed.
        PasskeyRemoved => "passkey.removed",
        /// Signature counter regression / clone suspicion (PKY-05).
        PasskeyCloneSuspected => "passkey.clone_suspected",
        /// External identity linked (SOC-06).
        IdentityLinked => "identity.linked",
        /// External identity unlinked.
        IdentityUnlinked => "identity.unlinked",
        /// A provider token of a removed or re-authorized external identity
        /// was revoked at the provider (K-35, K-59, K-60); `Actor::System`.
        /// Failure reasons: `provider_token_revocation_failed` (given up
        /// after retries), `provider_token_unreadable` (the stored token
        /// could not be decrypted, nothing could be sent). Never means the
        /// unlink itself failed.
        IdentityProviderTokenRevoked => "identity.provider_token_revoked",
        /// Organization created.
        OrgCreated => "org.created",
        /// Organization updated.
        OrgUpdated => "org.updated",
        /// Organization deletion scheduled.
        OrgDeletionScheduled => "org.deletion_scheduled",
        /// Scheduled organization deletion cancelled (ORG-12).
        OrgDeletionCancelled => "org.deletion_cancelled",
        /// Organization deleted.
        OrgDeleted => "org.deleted",
        /// Ownership transfer requested (ORG-11).
        OrgOwnershipTransferRequested => "org.ownership_transfer_requested",
        /// Ownership transferred.
        OrgOwnershipTransferred => "org.ownership_transferred",
        /// Pending ownership transfer cancelled (ORG-11).
        OrgOwnershipTransferCancelled => "org.ownership_transfer_cancelled",
        /// Organization policy changed (ORG-07).
        OrgPolicyChanged => "org.policy_changed",
        /// Domain added, verification pending (ORG-06).
        OrgDomainAdded => "org.domain_added",
        /// Domain verified (ORG-06).
        OrgDomainVerified => "org.domain_verified",
        /// Domain removed.
        OrgDomainRemoved => "org.domain_removed",
        /// Member added.
        MemberAdded => "org.member_added",
        /// Member removed.
        MemberRemoved => "org.member_removed",
        /// Member role changed.
        MemberRoleChanged => "org.member_role_changed",
        /// Member suspended or reactivated.
        MemberStatusChanged => "org.member_status_changed",
        /// Invitation created or re-sent.
        InvitationCreated => "org.invitation_created",
        /// Invitation accepted.
        InvitationAccepted => "org.invitation_accepted",
        /// Invitation revoked.
        InvitationRevoked => "org.invitation_revoked",
        /// Custom role created.
        RoleCreated => "org.role_created",
        /// Custom role updated.
        RoleUpdated => "org.role_updated",
        /// Custom role deleted.
        RoleDeleted => "org.role_deleted",
        /// API key created.
        ApiKeyCreated => "api_key.created",
        /// API key rotated.
        ApiKeyRotated => "api_key.rotated",
        /// API key revoked.
        ApiKeyRevoked => "api_key.revoked",
        /// Authentication with an unknown / revoked / expired API key.
        ApiKeyAuthFailed => "api_key.auth_failed",
        /// Service account created.
        ServiceAccountCreated => "service_account.created",
        /// Service account updated.
        ServiceAccountUpdated => "service_account.updated",
        /// Service account deleted.
        ServiceAccountDeleted => "service_account.deleted",
        /// Webhook endpoint created.
        WebhookEndpointCreated => "webhook.endpoint_created",
        /// Webhook endpoint updated.
        WebhookEndpointUpdated => "webhook.endpoint_updated",
        /// Webhook endpoint deleted.
        WebhookEndpointDeleted => "webhook.endpoint_deleted",
        /// Webhook signing secret rotated.
        WebhookSecretRotated => "webhook.secret_rotated",
        /// Webhook endpoint disabled automatically after sustained delivery
        /// failures (AUD-07).
        WebhookEndpointAutoDisabled => "webhook.endpoint_auto_disabled",
        /// Manual redelivery of a webhook delivery requested (AUD-07).
        WebhookRedeliveryRequested => "webhook.redelivery_requested",
        /// Generic admin action (ADM-08); metadata names the action + reason.
        AdminAction => "admin.action",
        /// Impersonation started (ADM-04).
        ImpersonationStarted => "admin.impersonation_started",
        /// Impersonation ended.
        ImpersonationEnded => "admin.impersonation_ended",
        /// Break-glass account used (ADM-05) — high priority.
        BreakGlassUsed => "admin.break_glass_used",
        /// Emergency operation (ADM-06).
        EmergencyAction => "admin.emergency_action",
        /// A four-eyes approval of a critical admin operation was requested
        /// (K-66); metadata names the approval and the operation.
        AdminApprovalRequested => "admin.approval_requested",
        /// A second platform admin approved or denied a four-eyes request
        /// (K-66); metadata `decision` = `approved` / `denied`.
        AdminApprovalDecided => "admin.approval_decided",
        /// A critical admin operation ran without a second admin's approval
        /// under a defined exception (K-66: `break_glass`, `no_second_admin`)
        /// — high priority, alert on it.
        AdminFourEyesBypassed => "admin.four_eyes_bypassed",
        /// JWT signing key rotated (CRY-10).
        SigningKeyRotated => "keys.signing_key_rotated",
        /// JWT signing key revoked.
        SigningKeyRevoked => "keys.signing_key_revoked",
        /// Key-encryption key rotated / data re-encrypted.
        KekRotated => "keys.kek_rotated",
        /// Rate limit triggered (PRT-01).
        RateLimitTriggered => "protect.rate_limited",
        /// CAPTCHA failed.
        CaptchaFailed => "protect.captcha_failed",
        /// Soft lock engaged (PRT-03).
        SoftLockEngaged => "protect.soft_lock_engaged",
        /// High-risk login blocked (RSK-03).
        RiskHighBlocked => "risk.high_blocked",
        /// Successful login from a new device (RSK-04).
        NewDeviceLogin => "risk.new_device_login",
    }
}

/// Success or failure of the audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    /// The action succeeded.
    Success,
    /// The action failed or was denied.
    Failure,
}

/// Who performed the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum Actor {
    /// A user (for impersonation: the impersonated user; see
    /// [`SecurityEvent::impersonator`]).
    User(UserId),
    /// A service account.
    ServiceAccount(ServiceAccountId),
    /// An API key without a service account.
    ApiKey(ApiKeyId),
    /// The system itself (background jobs, CLI).
    System,
    /// An unauthenticated caller.
    Anonymous,
}

/// The resource an event is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceRef {
    /// Resource type, snake_case (`session`, `api_key`, `role`…).
    pub kind: &'static str,
    /// Resource id (a typed id rendered as string).
    pub id: String,
}

/// A security event (AUD-03: who, what, which resource, outcome, IP, user
/// agent, request id, organization).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecurityEvent {
    /// Event id (UUIDv7).
    pub id: EventId,
    /// What happened.
    pub kind: SecurityEventKind,
    /// When it happened (from the injected clock).
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// Success / failure.
    pub outcome: EventOutcome,
    /// Stable snake_case reason code (e.g. `wrong_password`). Never free text.
    pub reason: Option<String>,
    /// Who acted.
    pub actor: Actor,
    /// Real actor when an admin impersonates the user.
    pub impersonator: Option<UserId>,
    /// The user the event is about (target), if any.
    pub subject_user: Option<UserId>,
    /// Organization scope, if any.
    pub org_id: Option<OrgId>,
    /// Affected resource, if any.
    pub resource: Option<ResourceRef>,
    /// Client IP.
    pub ip: Option<IpAddr>,
    /// Client user agent (truncated).
    pub user_agent: Option<String>,
    /// Request id for log correlation.
    pub request_id: Option<RequestId>,
    /// Additional non-sensitive structured data.
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl SecurityEvent {
    /// A successful event by an anonymous actor; refine with the builder
    /// methods.
    #[must_use]
    pub fn new(kind: SecurityEventKind, occurred_at: OffsetDateTime) -> Self {
        Self {
            id: EventId::generate(),
            kind,
            occurred_at,
            outcome: EventOutcome::Success,
            reason: None,
            actor: Actor::Anonymous,
            impersonator: None,
            subject_user: None,
            org_id: None,
            resource: None,
            ip: None,
            user_agent: None,
            request_id: None,
            metadata: serde_json::Map::new(),
        }
    }

    /// Copies IP, user agent and request id from the request context.
    #[must_use]
    pub fn with_context(mut self, ctx: &RequestContext) -> Self {
        self.ip = Some(ctx.client_ip);
        self.user_agent.clone_from(&ctx.user_agent);
        self.request_id = Some(ctx.request_id);
        self
    }

    /// Sets the actor.
    #[must_use]
    pub fn with_actor(mut self, actor: Actor) -> Self {
        self.actor = actor;
        self
    }

    /// Sets the subject user.
    #[must_use]
    pub fn with_subject(mut self, user: UserId) -> Self {
        self.subject_user = Some(user);
        self
    }

    /// Sets the organization.
    #[must_use]
    pub fn with_org(mut self, org: OrgId) -> Self {
        self.org_id = Some(org);
        self
    }

    /// Sets the resource.
    #[must_use]
    pub fn with_resource(mut self, kind: &'static str, id: impl ToString) -> Self {
        self.resource = Some(ResourceRef {
            kind,
            id: id.to_string(),
        });
        self
    }

    /// Marks the event as failed with a stable reason code.
    #[must_use]
    pub fn failed(mut self, reason: impl Into<String>) -> Self {
        self.outcome = EventOutcome::Failure;
        self.reason = Some(reason.into());
        self
    }

    /// Adds a metadata entry (non-sensitive).
    #[must_use]
    pub fn with_meta(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.metadata.insert(key.to_owned(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aud_01_event_kinds_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for kind in SecurityEventKind::ALL {
            let s = kind.as_str();
            assert!(seen.insert(s), "duplicate {s}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.'),
                "{s}"
            );
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(s));
        }
    }

    #[test]
    fn aud_03_builder_sets_fields() {
        let user = UserId::generate();
        let ev = SecurityEvent::new(SecurityEventKind::LoginFailed, OffsetDateTime::UNIX_EPOCH)
            .with_actor(Actor::Anonymous)
            .with_subject(user)
            .failed("wrong_password")
            .with_meta("method", "password");
        assert_eq!(ev.outcome, EventOutcome::Failure);
        assert_eq!(ev.reason.as_deref(), Some("wrong_password"));
        assert_eq!(ev.subject_user, Some(user));
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["kind"], "login.failed");
        assert_eq!(json["actor"]["type"], "anonymous");
    }
}
