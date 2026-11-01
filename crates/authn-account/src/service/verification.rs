//! E-mail verification (ACC-04) and the verification part of ACC-05.
//!
//! * One issuance = a 256-bit **link** token (`email_verification`, default
//!   24 h) and a **6-digit code** (`email_verification_code`, default
//!   15 min, 5 attempts) sharing a `group_id`; using one revokes the other,
//!   issuing new ones revokes the previous ones. Both are bound to the
//!   address they were sent to (`target`): after an e-mail change an old
//!   token can never verify the new address.
//! * Links and codes are consumed atomically (single `UPDATE … RETURNING`
//!   / row-locked attempt counter in `authn-store`): of concurrent uses
//!   exactly one succeeds.
//! * Code guessing is bounded three ways: 5 attempts per code (then the
//!   code is revoked), `account.verification.code_attempts_per_email`
//!   across codes (re-sending must not multiply guesses) and a per-IP limit.
//! * Re-sending obeys `resend_cooldown` (60 s) and `max_sends_per_hour`
//!   per address.
//! * Unauthenticated code verification answers unknown addresses, wrong,
//!   expired and locked-out codes identically (`invalid_code`, no faster
//!   than `code_failure_floor`) — no account enumeration (ACC-02).

use std::time::Instant;

use authn_core::domain::{AccountStatus, EmailAddress, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, DomainEvent, DomainEventKind, Notification, NotificationKind, RateLimitKey,
    RateLimitPolicy, SecurityEventKind,
};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::otp::OtpCode;
use authn_crypto::token::OpaqueToken;
use authn_store::{
    CodeVerification, OneTimeTokenRecord, OneTimeTokenRepository, TokenPurpose, TokenSubject,
    UserRecord, UserRepository,
};
use uuid::Uuid;

use super::{AccountService, actions, parse_email, stored_email};
use crate::lifecycle::{StatusChange, apply_transition, lock_user};
use crate::tx::AccountTx;

/// Proof presented to verify an address without a session.
#[derive(Clone)]
pub enum VerificationProof {
    /// Token of the e-mailed link.
    Link {
        /// Raw link token.
        token: SecretString,
    },
    /// The e-mailed 6-digit code together with the address (mobile).
    Code {
        /// The address the code was sent to.
        email: String,
        /// The code.
        code: SecretString,
    },
}

impl std::fmt::Debug for VerificationProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Link { .. } => f.write_str("VerificationProof::Link([REDACTED])"),
            Self::Code { email, .. } => write!(
                f,
                "VerificationProof::Code({}, [REDACTED])",
                authn_core::redact::mask_email(email)
            ),
        }
    }
}

/// The common "unusable link" error (unknown, used, revoked, expired and
/// mis-bound links are indistinguishable).
pub(super) fn invalid_token() -> AuthError {
    AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN)
}

/// The common "wrong code" error.
pub(super) fn invalid_code() -> AuthError {
    AuthError::new(codes::common::INVALID_CODE)
}

/// Whether a token's `target` is the user's current address.
pub(super) fn target_matches(record: &OneTimeTokenRecord, user: &UserRecord) -> bool {
    let target = record
        .target
        .as_deref()
        .and_then(|t| EmailAddress::parse(t).ok());
    match (target, user.email_normalized.as_deref()) {
        (Some(target), Some(current)) => {
            authn_core::secret::constant_time_eq(target.normalized().as_bytes(), current.as_bytes())
        }
        _ => false,
    }
}

impl AccountService {
    /// Verifies an address with a link token or e-mail + code (no session).
    pub async fn verify_email(
        &self,
        ctx: &RequestContext,
        proof: VerificationProof,
    ) -> Result<(), AuthError> {
        match proof {
            VerificationProof::Link { token } => self.verify_email_link(ctx, &token).await,
            VerificationProof::Code { email, code } => {
                self.verify_email_code(ctx, &email, &code).await
            }
        }
    }

    /// ACC-04: consumes a verification link and activates the account.
    pub async fn verify_email_link(
        &self,
        ctx: &RequestContext,
        token: &SecretString,
    ) -> Result<(), AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::VERIFY_IP, ctx.client_ip),
            self.config().verification.verify_per_ip,
        )
        .await?;
        let token = OpaqueToken::parse(token.expose_secret()).map_err(|_| invalid_token())?;
        let mut tx = self.begin().await?;
        let consumed = OneTimeTokenRepository::consume_link(
            tx.conn(),
            TokenPurpose::EmailVerification,
            &token.hash(),
            self.now(),
        )
        .await?;
        let Some(user_id) = consumed.as_ref().and_then(|r| r.user_id) else {
            return Err(invalid_token());
        };
        let user = lock_user(&mut tx, user_id)
            .await
            .map_err(|_| invalid_token())?;
        if !consumed.as_ref().is_some_and(|r| target_matches(r, &user)) {
            return Err(invalid_token());
        }
        self.complete_verification(&mut tx, &user, Actor::Anonymous, ctx)
            .await?;
        tx.commit().await
    }

    /// ACC-04: e-mail + code without a session (mobile). Enumeration-safe.
    pub async fn verify_email_code(
        &self,
        ctx: &RequestContext,
        email: &str,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let started = Instant::now();
        let result = self.verify_email_code_inner(ctx, email, code).await;
        if result.is_err() {
            self.failure_floor(started).await;
        }
        result
    }

    /// Sleeps until `code_failure_floor` has passed since `started`.
    pub(super) async fn failure_floor(&self, started: Instant) {
        let floor = self.settings().code_failure_floor;
        if let Some(rest) = floor.checked_sub(started.elapsed()) {
            tokio::time::sleep(rest).await;
        }
    }

    async fn verify_email_code_inner(
        &self,
        ctx: &RequestContext,
        email: &str,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let verification = &self.config().verification;
        self.limit(
            &RateLimitKey::ip(actions::VERIFY_IP, ctx.client_ip),
            verification.verify_per_ip,
        )
        .await?;
        let email = parse_email(email)?;
        self.limit(
            &RateLimitKey::account(actions::VERIFICATION_CODE, email.normalized()),
            verification.code_attempts_per_email,
        )
        .await?;
        let code = OtpCode::parse(code.expose_secret()).map_err(|_| invalid_code())?;
        // Same queries for known and unknown addresses (the nil id never
        // exists).
        let user = UserRepository::find_by_email(self.pool(), &email)
            .await?
            .filter(|u| u.email_verified_at.is_none());
        let lookup = user
            .as_ref()
            .map_or_else(|| UserId::from_uuid(Uuid::nil()), |u| u.id);
        let outcome = self
            .check_code(TokenPurpose::EmailVerificationCode, lookup, &code)
            .await?;
        match (outcome, user) {
            (CodeVerification::Verified(record), Some(user)) => {
                self.finish_code_verification(ctx, &record, user.id, Actor::Anonymous)
                    .await
            }
            (outcome, user) => {
                self.audit_failed_verification(ctx, user.map(|u| u.id), &outcome)
                    .await;
                Err(invalid_code())
            }
        }
    }

    /// ACC-04 / ACC-05 (limited mode): the signed-in user verifies their
    /// own address with the code.
    pub async fn verify_own_email_code(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let user = self
            .principal_user(Self::self_service_user(principal)?)
            .await?;
        if user.email_verified_at.is_some() {
            return Err(AuthError::new(codes::account::EMAIL_ALREADY_VERIFIED));
        }
        let email = stored_email(&user).ok_or_else(|| AuthError::new(codes::common::CONFLICT))?;
        self.limit(
            &RateLimitKey::account(actions::VERIFICATION_CODE, email.normalized()),
            self.config().verification.code_attempts_per_email,
        )
        .await?;
        let code = OtpCode::parse(code.expose_secret()).map_err(|_| invalid_code())?;
        match self
            .check_code(TokenPurpose::EmailVerificationCode, user.id, &code)
            .await?
        {
            CodeVerification::Verified(record) => {
                self.finish_code_verification(ctx, &record, user.id, Actor::User(user.id))
                    .await
            }
            outcome => {
                self.audit_failed_verification(ctx, Some(user.id), &outcome)
                    .await;
                Err(match outcome {
                    CodeVerification::LockedOut => AuthError::new(codes::common::TOO_MANY_ATTEMPTS),
                    _ => invalid_code(),
                })
            }
        }
    }

    /// Verifies a code of `purpose` for `user` in the store's own
    /// transaction (failed attempts stay counted, CRY-07).
    pub(super) async fn check_code(
        &self,
        purpose: TokenPurpose,
        user: UserId,
        code: &OtpCode,
    ) -> Result<CodeVerification, AuthError> {
        let candidate = self.deps().otp.hash(purpose.as_str(), code);
        Ok(OneTimeTokenRepository::verify_code(
            self.pool(),
            purpose,
            TokenSubject::user(user),
            &candidate,
            self.now(),
        )
        .await?)
    }

    async fn finish_code_verification(
        &self,
        ctx: &RequestContext,
        record: &OneTimeTokenRecord,
        user_id: UserId,
        actor: Actor,
    ) -> Result<(), AuthError> {
        let mut tx = self.begin().await?;
        let user = lock_user(&mut tx, user_id)
            .await
            .map_err(|_| invalid_code())?;
        if !target_matches(record, &user) {
            return Err(invalid_code());
        }
        self.complete_verification(&mut tx, &user, actor, ctx)
            .await?;
        tx.commit().await
    }

    /// Marks the address verified and activates a `pending_verification`
    /// account (ACC-06 transition, audited). Other statuses are kept
    /// (a suspended account stays suspended).
    async fn complete_verification(
        &self,
        tx: &mut AccountTx,
        user: &UserRecord,
        actor: Actor,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let now = self.now();
        UserRepository::mark_email_verified(tx.conn(), user.id, now).await?;
        if user.status == AccountStatus::PendingVerification {
            apply_transition(
                tx,
                user,
                &StatusChange::new(AccountStatus::Active, "email_verified", actor),
                true,
                now,
                Some(ctx),
            )
            .await?;
        }
        OneTimeTokenRepository::revoke_for_user(
            tx.conn(),
            user.id,
            &[
                TokenPurpose::EmailVerification,
                TokenPurpose::EmailVerificationCode,
            ],
            now,
        )
        .await?;
        self.deps()
            .events
            .publish(
                tx.conn(),
                DomainEvent {
                    user_id: Some(user.id),
                    ..DomainEvent::new(
                        DomainEventKind::UserUpdated,
                        now,
                        serde_json::json!({ "user_id": user.id, "email_verified": true }),
                    )
                },
            )
            .await?;
        tx.audit(
            self.event(SecurityEventKind::EmailVerified, ctx)
                .with_actor(actor)
                .with_subject(user.id),
        );
        metrics::counter!("authn_account_email_verifications_total").increment(1);
        Ok(())
    }

    async fn audit_failed_verification(
        &self,
        ctx: &RequestContext,
        user: Option<UserId>,
        outcome: &CodeVerification,
    ) {
        let reason = match outcome {
            CodeVerification::LockedOut => "locked_out",
            CodeVerification::NotFound => "no_active_code",
            _ => "invalid_code",
        };
        let mut event = self
            .event(SecurityEventKind::EmailVerified, ctx)
            .failed(reason);
        if let Some(user) = user {
            event = event.with_subject(user);
        }
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::warn!(error = %err, "failed verification could not be audited");
        }
    }

    /// ACC-04: "resend the verification e-mail" without a session. Always
    /// `Ok(())` (`202`) for a syntactically valid address; the lookup runs
    /// in the background.
    pub async fn resend_verification(
        &self,
        ctx: &RequestContext,
        email: &str,
    ) -> Result<(), AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::VERIFICATION_RESEND_IP, ctx.client_ip),
            self.config().verification.resend_per_ip,
        )
        .await?;
        let email = parse_email(email)?;
        let service = self.clone();
        let ctx = ctx.clone();
        self.inner.jobs.spawn("resend_verification", async move {
            service.process_resend(&ctx, &email).await
        })
    }

    async fn process_resend(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
    ) -> Result<(), AuthError> {
        let Some(user) = UserRepository::find_by_email(self.pool(), email).await? else {
            return Ok(());
        };
        if user.status != AccountStatus::PendingVerification || user.email_verified_at.is_some() {
            return Ok(());
        }
        if !self.verification_send_allowed(email).await? {
            return Ok(());
        }
        self.send_verification_to(ctx, user.id).await
    }

    /// ACC-04: the signed-in (unverified) user asks for a new verification
    /// e-mail. Cooldown and hourly limit answer `429` + `Retry-After`.
    pub async fn resend_own_verification(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let user = self
            .principal_user(Self::self_service_user(principal)?)
            .await?;
        if user.email_verified_at.is_some() {
            return Err(AuthError::new(codes::account::EMAIL_ALREADY_VERIFIED));
        }
        let email = stored_email(&user).ok_or_else(|| AuthError::new(codes::common::CONFLICT))?;
        let verification = &self.config().verification;
        self.limit(
            &RateLimitKey::account(actions::VERIFICATION_COOLDOWN, email.normalized()),
            RateLimitPolicy::new(1, verification.resend_cooldown),
        )
        .await?;
        self.limit(
            &RateLimitKey::account(actions::VERIFICATION_HOURLY, email.normalized()),
            RateLimitPolicy::new(
                verification.max_sends_per_hour,
                std::time::Duration::from_secs(3600),
            ),
        )
        .await?;
        self.send_verification_to(ctx, user.id).await
    }

    /// Issues new verification secrets for the user's current address and
    /// enqueues the e-mail (one transaction).
    async fn send_verification_to(
        &self,
        ctx: &RequestContext,
        user_id: UserId,
    ) -> Result<(), AuthError> {
        let mut tx = self.begin().await?;
        let user = lock_user(&mut tx, user_id).await?;
        if user.email_verified_at.is_some() {
            return Ok(());
        }
        let Some(email) = stored_email(&user) else {
            tracing::error!(user_id = %user.id, "stored e-mail address is unusable; verification not sent");
            return Ok(());
        };
        let (recipient, locale) = self
            .unproven_recipient_at(tx.conn(), user.id, email, ctx.locale)
            .await?;
        let secrets = self
            .issue_link_and_code(
                tx.conn(),
                (
                    TokenPurpose::EmailVerification,
                    TokenPurpose::EmailVerificationCode,
                ),
                user.id,
                &recipient.email,
                Some(ctx.client_ip),
            )
            .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                tx.conn(),
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::EmailVerification {
                        token: secrets.token.into_sensitive(),
                        code: secrets.code.into_sensitive(),
                        expires_at: secrets.link_expires_at,
                    },
                },
            )
            .await?;
        tx.commit().await
    }

    /// Cooldown + hourly limit of verification e-mails to an address;
    /// consumes a unit of each when allowed.
    async fn verification_send_allowed(&self, email: &EmailAddress) -> Result<bool, AuthError> {
        let verification = &self.config().verification;
        if !self
            .allowed(
                &RateLimitKey::account(actions::VERIFICATION_COOLDOWN, email.normalized()),
                RateLimitPolicy::new(1, verification.resend_cooldown),
            )
            .await?
        {
            return Ok(false);
        }
        self.allowed(
            &RateLimitKey::account(actions::VERIFICATION_HOURLY, email.normalized()),
            RateLimitPolicy::new(
                verification.max_sends_per_hour,
                std::time::Duration::from_secs(3600),
            ),
        )
        .await
    }

    /// Starts the resend cooldown after an automatic send (registration).
    pub(super) async fn record_verification_send(
        &self,
        email: &EmailAddress,
    ) -> Result<(), AuthError> {
        // Decisions are irrelevant here: the first e-mail is always sent.
        let _ = self.verification_send_allowed(email).await?;
        Ok(())
    }
}
