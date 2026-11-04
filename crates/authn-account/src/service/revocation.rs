//! Account consequences of events other modules own (ADR 0002):
//!
//! * [`AccountService::confirm_mailbox_control_in_tx`] — the mailbox owner
//!   proved control of the address outside this crate (completed password
//!   reset, magic link / login code, provider-verified e-mail, administrator).
//!   An unverified account becomes verified **for the mailbox owner**: every
//!   pending registration (with the credentials somebody else may have
//!   submitted) is deleted and, unless the proof itself set a new password,
//!   a password nobody proved is removed and every session revoked.
//! * [`AccountService::revoke_pending_email_changes_in_tx`] — a pending
//!   e-mail change (`email_change` link / `email_change_code`) must not
//!   survive a password reset, a password change or "sign out everywhere":
//!   it may have been requested by whoever is being locked out (ACC-07).
//! * [`AccountAwareSessionRevoker`] — a `SessionRevoker` decorator that
//!   applies both automatically. authn-password's reset completion and
//!   authn-session's bulk revocations already call the `SessionRevoker`
//!   port inside their transaction, so wrapping the port is the whole
//!   wiring; nothing in those crates changes.

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::domain::AccountStatus;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, SessionId, UserId};
use authn_core::ports::{
    Actor, DomainEvent, DomainEventKind, RevocationReason, RevokeOptions, SecurityEvent,
    SecurityEventKind, SessionRevoker,
};
use authn_store::{OneTimeTokenRepository, TokenPurpose, UserRepository};
use sqlx::PgConnection;

use super::AccountService;
use crate::lifecycle::{StatusChange, transition_event, write_transition};
use crate::registration_store::RegistrationRepository;

/// How the mailbox owner proved control of the address outside this
/// crate's verification flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxProof {
    /// An e-mailed password reset was completed (PWD-09): the reset token
    /// was bound to the account's current address and the new password was
    /// chosen in the same flow. Applied automatically by
    /// [`AccountAwareSessionRevoker`] on `RevocationReason::PasswordReset`.
    PasswordReset,
    /// Passwordless sign-in through the mailbox (magic link SES-18, login
    /// code SES-19) or an identity provider asserting this verified address
    /// (SOC-05 linking). No password is set by the proof itself.
    Passwordless,
    /// A platform administrator marked the address verified (ADM-03).
    /// The account's events are written as `Actor::System` without the
    /// administrator's IP / user agent (K-14); authn-admin audits the staff
    /// member in its own `admin.action` event in the same transaction.
    Administrator {
        /// The acting administrator (audited by the caller's `admin.*`
        /// event, never in the user's own events).
        admin: UserId,
    },
}

impl MailboxProof {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset",
            Self::Passwordless => "passwordless",
            Self::Administrator { .. } => "administrator",
        }
    }

    /// Whether the proof set the account's password in the same flow.
    const fn sets_password(self) -> bool {
        matches!(self, Self::PasswordReset)
    }

    /// Actor of the account events. An administrator's proof is recorded
    /// as [`Actor::System`] (K-14, ADM-08): these events land in the
    /// **user's** own security-event list, and platform staff must appear
    /// there neither by user id nor by IP; the acting administrator is
    /// recorded by authn-admin in its own `admin.action` event (same
    /// transaction), exactly like `passkey.removed` of an admin MFA reset.
    const fn actor(self, user: UserId) -> Actor {
        match self {
            Self::PasswordReset | Self::Passwordless => Actor::User(user),
            Self::Administrator { .. } => Actor::System,
        }
    }

    /// Whether the request context (client IP, user agent) of the caller
    /// may be attached to the user's events: not for staff actions — the
    /// audit sink would store the administrator's IP as the subject's
    /// personal data and the user's view would show its network (K-14).
    /// The request id is kept for correlation with the `admin.*` event.
    const fn keeps_client_context(self) -> bool {
        !matches!(self, Self::Administrator { .. })
    }

    /// The request context to attach to the user's events (see
    /// [`Self::keeps_client_context`]).
    fn event_context(self, ctx: Option<&RequestContext>) -> Option<RequestContext> {
        let ctx = ctx?;
        if self.keeps_client_context() {
            return Some(ctx.clone());
        }
        None
    }
}

/// Bulk revocation reasons after which a pending e-mail change ends: the
/// user (or an administrator) reacts to a possible compromise, or the
/// credentials changed.
const PENDING_CHANGE_ENDING_REASONS: &[RevocationReason] = &[
    RevocationReason::Logout,
    RevocationReason::UserRequest,
    RevocationReason::PasswordChanged,
    RevocationReason::PasswordReset,
    RevocationReason::EmailChangeReverted,
    RevocationReason::NotMe,
    RevocationReason::RefreshTokenReuse,
    RevocationReason::AccountSuspended,
    RevocationReason::AdminAction,
    RevocationReason::Emergency,
];

/// The purposes of a pending e-mail change (never the revert link: that is
/// the original owner's way back).
const PENDING_CHANGE_PURPOSES: &[TokenPurpose] =
    &[TokenPurpose::EmailChange, TokenPurpose::EmailChangeCode];

impl AccountService {
    /// The mailbox owner of `user`'s current address proved control of it
    /// outside this crate (see [`MailboxProof`]). Runs in the caller's
    /// transaction, which must also hold whatever proved it (consumed reset
    /// token, magic link…). Returns whether an unverified account was
    /// verified (`false`: already verified, nothing to do).
    ///
    /// For an unverified account, in this order: every pending
    /// registration is deleted (their credentials were never proven by the
    /// mailbox owner); unless the proof set a new password, the stored
    /// password is removed (nobody proved it) and every session and
    /// trusted device is revoked; the address is marked verified,
    /// `pending_verification` → `active` (ACC-06, audited), outstanding
    /// verification tokens are revoked.
    pub async fn confirm_mailbox_control_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: Option<&RequestContext>,
        user: UserId,
        proof: MailboxProof,
    ) -> Result<bool, AuthError> {
        let now = self.now();
        let record = UserRepository::lock_for_update(&mut *conn, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if record.email_verified_at.is_some() {
            return Ok(false);
        }
        let registrations = RegistrationRepository::delete_for_user(&mut *conn, user).await?;
        let password_removed = if proof.sets_password() {
            false
        } else {
            UserRepository::delete_password(&mut *conn, user).await?
        };
        OneTimeTokenRepository::revoke_for_user(
            &mut *conn,
            user,
            &[
                TokenPurpose::EmailVerification,
                TokenPurpose::EmailVerificationCode,
            ],
            now,
        )
        .await?;
        UserRepository::mark_email_verified(&mut *conn, user, now).await?;
        let event_ctx = proof.event_context(ctx);
        let request_id = ctx.map(|c| c.request_id);
        if record.status == AccountStatus::PendingVerification {
            let change =
                StatusChange::new(AccountStatus::Active, "email_verified", proof.actor(user));
            write_transition(&mut *conn, &record, &change, true, now).await?;
            let mut event = transition_event(&record, &change, now, event_ctx.as_ref());
            event.request_id = request_id;
            self.deps().audit.record_in_tx(&mut *conn, event).await?;
        }
        if !proof.sets_password() {
            self.deps()
                .sessions
                .revoke_all_for_user(
                    &mut *conn,
                    user,
                    RevocationReason::PasswordChanged,
                    RevokeOptions {
                        also_trusted_devices: true,
                    },
                )
                .await?;
        }
        self.deps()
            .events
            .publish(
                &mut *conn,
                DomainEvent {
                    user_id: Some(user),
                    ..DomainEvent::new(
                        DomainEventKind::UserUpdated,
                        now,
                        serde_json::json!({ "user_id": user, "email_verified": true }),
                    )
                },
            )
            .await?;
        let mut event = SecurityEvent::new(SecurityEventKind::EmailVerified, now);
        if let Some(ctx) = &event_ctx {
            event = event.with_context(ctx);
        }
        event.request_id = request_id;
        let event = event
            .with_actor(proof.actor(user))
            .with_subject(user)
            .with_meta("method", proof.as_str())
            .with_meta("registrations_discarded", registrations)
            .with_meta("password_removed", password_removed);
        self.deps().audit.record_in_tx(&mut *conn, event).await?;
        metrics::counter!("authn_account_email_verifications_total").increment(1);
        Ok(true)
    }

    /// Revokes `user`'s pending e-mail change (link and code; the revert
    /// links of completed changes are kept) in the caller's transaction.
    /// Returns the number of revoked tokens.
    pub async fn revoke_pending_email_changes_in_tx(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<u64, AuthError> {
        Ok(
            OneTimeTokenRepository::revoke_for_user(
                conn,
                user,
                PENDING_CHANGE_PURPOSES,
                self.now(),
            )
            .await?,
        )
    }

    /// Account consequences of a bulk revocation of `user`'s sessions with
    /// `reason` (called by [`AccountAwareSessionRevoker`], same
    /// transaction): a pending e-mail change ends (see
    /// `PENDING_CHANGE_ENDING_REASONS`); a completed password reset
    /// verifies an unverified account for the mailbox owner
    /// ([`MailboxProof::PasswordReset`]).
    ///
    /// `RevocationReason::PasswordReset` must therefore only be used by the
    /// completion of an e-mailed password reset (authn-password, PWD-09).
    pub async fn on_sessions_revoked_in_tx(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        reason: RevocationReason,
    ) -> Result<(), AuthError> {
        if PENDING_CHANGE_ENDING_REASONS.contains(&reason) {
            self.revoke_pending_email_changes_in_tx(&mut *conn, user)
                .await?;
        }
        if reason == RevocationReason::PasswordReset {
            self.confirm_mailbox_control_in_tx(conn, None, user, MailboxProof::PasswordReset)
                .await?;
        }
        Ok(())
    }

    /// Emergency (ADM-06): every pending e-mail change of every user ends.
    async fn revoke_every_pending_email_change_in_tx(
        &self,
        conn: &mut PgConnection,
    ) -> Result<u64, AuthError> {
        let purposes: Vec<&str> = PENDING_CHANGE_PURPOSES.iter().map(|p| p.as_str()).collect();
        let result = sqlx::query(
            "UPDATE one_time_tokens SET revoked_at = $2 WHERE purpose = ANY($1) \
             AND consumed_at IS NULL AND revoked_at IS NULL",
        )
        .bind(&purposes)
        .bind(self.now())
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }
}

/// A [`SessionRevoker`] that also applies the account consequences of bulk
/// revocations (see [`AccountService::on_sessions_revoked_in_tx`]) on the
/// same connection, inside the caller's transaction.
///
/// `authn-server` wraps authn-session's revoker once and hands the wrapped
/// port to every module (authn-password, authn-session's own "sign out
/// everywhere", authn-mfa, authn-org, authn-admin). Pass the **inner**
/// revoker to `AccountServiceDeps::sessions` (this crate applies its own
/// consequences itself; wrapping it there is harmless but creates a
/// reference cycle).
#[derive(Clone)]
pub struct AccountAwareSessionRevoker {
    inner: Arc<dyn SessionRevoker>,
    account: AccountService,
}

impl AccountAwareSessionRevoker {
    /// Wraps `inner` (authn-session's implementation).
    #[must_use]
    pub fn new(inner: Arc<dyn SessionRevoker>, account: AccountService) -> Self {
        Self { inner, account }
    }
}

impl std::fmt::Debug for AccountAwareSessionRevoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountAwareSessionRevoker")
    }
}

#[async_trait]
impl SessionRevoker for AccountAwareSessionRevoker {
    async fn revoke_session(
        &self,
        conn: &mut PgConnection,
        session: SessionId,
        reason: RevocationReason,
    ) -> Result<bool, AuthError> {
        self.inner.revoke_session(conn, session, reason).await
    }

    async fn revoke_all_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        reason: RevocationReason,
        options: RevokeOptions,
    ) -> Result<u64, AuthError> {
        let revoked = self
            .inner
            .revoke_all_for_user(&mut *conn, user, reason, options)
            .await?;
        self.account
            .on_sessions_revoked_in_tx(conn, user, reason)
            .await?;
        Ok(revoked)
    }

    async fn revoke_all_except(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        keep: SessionId,
        reason: RevocationReason,
        options: RevokeOptions,
    ) -> Result<u64, AuthError> {
        let revoked = self
            .inner
            .revoke_all_except(&mut *conn, user, keep, reason, options)
            .await?;
        self.account
            .on_sessions_revoked_in_tx(conn, user, reason)
            .await?;
        Ok(revoked)
    }

    async fn revoke_for_user_in_org(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        org: OrgId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        self.inner
            .revoke_for_user_in_org(conn, user, org, reason)
            .await
    }

    async fn revoke_all_for_org(
        &self,
        conn: &mut PgConnection,
        org: OrgId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        self.inner.revoke_all_for_org(conn, org, reason).await
    }

    async fn revoke_everything(
        &self,
        conn: &mut PgConnection,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let revoked = self.inner.revoke_everything(&mut *conn, reason).await?;
        self.account
            .revoke_every_pending_email_change_in_tx(conn)
            .await?;
        Ok(revoked)
    }

    /// Emergency "revoke every session but the caller's" (ADM-06, K-10):
    /// the same account consequence as [`SessionRevoker::revoke_everything`]
    /// — every pending e-mail change ends, the caller's included.
    async fn revoke_everything_except(
        &self,
        conn: &mut PgConnection,
        keep: SessionId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let revoked = self
            .inner
            .revoke_everything_except(&mut *conn, keep, reason)
            .await?;
        self.account
            .revoke_every_pending_email_change_in_tx(conn)
            .await?;
        Ok(revoked)
    }
}
