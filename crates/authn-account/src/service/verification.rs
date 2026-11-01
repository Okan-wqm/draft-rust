//! E-mail verification (ACC-04) and the verification part of ACC-05.
//!
//! **Registrations** (the normal case) are completed in `registration.rs`:
//! their link and code live in `pending_registrations` and activate only
//! the credentials of their own registration, only for a client that proves
//! it submitted that registration (ADR 0002, account pre-hijacking).
//!
//! **Session-issued verification** (`POST /v1/me/email/verification`, for an
//! unverified account that can sign in — `account.unverified_login =
//! "limited"`): one issuance = a 256-bit **link** token
//! (`email_verification`, default 24 h) and a **6-digit code**
//! (`email_verification_code`, default 15 min, 5 attempts) sharing a
//! `group_id`; using one revokes the other, issuing new ones revokes the
//! previous ones. Both are bound to the address they were sent to
//! (`target`). The code is accepted only from the signed-in user. The link
//! verifies only when its opener is that signed-in user, knows the
//! account's password, or sets a new password — an e-mailed link alone
//! never activates credentials its clicker did not choose.
//! * Links and codes are consumed atomically (single `UPDATE … RETURNING`
//!   / row-locked attempt counter in `authn-store`): of concurrent uses
//!   exactly one succeeds.
//! * Code guessing is bounded three ways: 5 attempts per code (then the
//!   code is revoked), `account.verification.code_attempts_per_email`
//!   across codes (re-sending must not multiply guesses) and a per-IP limit.
//! * Re-sending obeys `resend_cooldown` (60 s) and `max_sends_per_hour`
//!   per address.
//! * Unauthenticated code verification answers unknown handles, wrong,
//!   expired and locked-out codes identically (`invalid_code`, no faster
//!   than `code_failure_floor`) — no account enumeration (ACC-02).

use std::time::Instant;

use authn_core::domain::{AccountStatus, EmailAddress, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, DomainEvent, DomainEventKind, Notification, NotificationKind, RateLimitKey,
    RateLimitPolicy, RevocationReason, RevokeOptions, SecurityEventKind,
};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::otp::OtpCode;
use authn_crypto::password::StoredPasswordHash;
use authn_crypto::token::{OpaqueToken, TokenHash};
use authn_store::{
    CodeVerification, NewPasswordHash, OneTimeTokenRecord, OneTimeTokenRepository, TokenPurpose,
    TokenSubject, UserRecord, UserRepository,
};

use super::registration::{Activation, CredentialConfirmation, LinkConfirmation};
use super::{AccountService, actions, parse_email, stored_email};
use crate::lifecycle::{StatusChange, apply_transition, lock_user};
use crate::registration_store::RegistrationRepository;
use crate::repo::{ConsentRepository, lock_email};
use crate::tx::AccountTx;

/// Proof presented to verify an address without a session.
pub enum VerificationProof {
    /// Token of the e-mailed link, plus whatever the opener presents to
    /// prove or set the credentials ([`LinkConfirmation`]).
    Link {
        /// Raw link token.
        token: SecretString,
        /// Registration handle, signed-in user, chosen or new password.
        confirmation: LinkConfirmation,
    },
    /// The e-mailed 6-digit code, accepted only together with the
    /// registration handle of the registering client.
    Code {
        /// The code.
        code: SecretString,
        /// Registration handle (request body or cookie).
        registration: Option<SecretString>,
        /// Optional address; when present it must be the registration's.
        email: Option<String>,
    },
}

impl std::fmt::Debug for VerificationProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Link { confirmation, .. } => f
                .debug_struct("VerificationProof::Link")
                .field("token", &authn_core::secret::REDACTED)
                .field("confirmation", confirmation)
                .finish(),
            Self::Code {
                email,
                registration,
                ..
            } => f
                .debug_struct("VerificationProof::Code")
                .field("code", &authn_core::secret::REDACTED)
                .field("registration", &registration.is_some())
                .field(
                    "email",
                    &email.as_deref().map(authn_core::redact::mask_email),
                )
                .finish(),
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
    /// Verifies an address with an e-mailed link or a code (no session
    /// required; see [`VerificationProof`]).
    pub async fn verify_email(
        &self,
        ctx: &RequestContext,
        proof: VerificationProof,
    ) -> Result<(), AuthError> {
        match proof {
            VerificationProof::Link {
                token,
                confirmation,
            } => self.verify_email_link(ctx, &token, &confirmation).await,
            VerificationProof::Code {
                code,
                registration,
                email,
            } => {
                self.verify_email_code(ctx, registration.as_ref(), email.as_deref(), &code)
                    .await
            }
        }
    }

    /// ACC-04: an e-mailed verification link. Registration links complete
    /// their registration (see `registration.rs`); session-issued links
    /// verify the account. In both cases the link proves mailbox control
    /// and `confirmation` must prove — or set — the credentials that end up
    /// active; otherwise `registration_confirmation_required`.
    pub async fn verify_email_link(
        &self,
        ctx: &RequestContext,
        token: &SecretString,
        confirmation: &LinkConfirmation,
    ) -> Result<(), AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::VERIFY_IP, ctx.client_ip),
            self.config().verification.verify_per_ip,
        )
        .await?;
        let token = OpaqueToken::parse(token.expose_secret()).map_err(|_| invalid_token())?;
        let hash = token.hash();
        if let Some(registration) =
            RegistrationRepository::find_by_link(self.pool(), &hash, self.now()).await?
        {
            return self
                .verify_registration_link(ctx, registration, hash, confirmation)
                .await;
        }
        self.verify_account_link(ctx, hash, confirmation).await
    }

    /// A session-issued verification link (`email_verification`).
    async fn verify_account_link(
        &self,
        ctx: &RequestContext,
        hash: TokenHash,
        confirmation: &LinkConfirmation,
    ) -> Result<(), AuthError> {
        let Some(found) = OneTimeTokenRepository::find_active_link(
            self.pool(),
            TokenPurpose::EmailVerification,
            &hash,
            self.now(),
        )
        .await?
        else {
            return Err(invalid_token());
        };
        let user = match found.user_id {
            Some(user) => UserRepository::find_by_id(self.pool(), user).await?,
            None => None,
        }
        .filter(|u| u.email_verified_at.is_none())
        .ok_or_else(invalid_token)?;
        let (replacement, method) = if confirmation.signed_in_user == Some(user.id) {
            (None, "link_signed_in")
        } else {
            match &confirmation.credentials {
                Some(CredentialConfirmation::ChosenPassword(password)) => {
                    let stored = UserRepository::find_password(self.pool(), user.id)
                        .await?
                        .map(|p| {
                            StoredPasswordHash::new(
                                &p.password_hash,
                                &p.algorithm,
                                p.pepper_version,
                            )
                        });
                    // No password: equal-cost dummy verification, never valid.
                    if !self
                        .deps()
                        .hasher
                        .verify(password, stored.as_ref())
                        .await?
                        .is_valid()
                    {
                        return Err(AuthError::new(
                            codes::account::REGISTRATION_PASSWORD_MISMATCH,
                        ));
                    }
                    (None, "link_chosen_password")
                }
                Some(CredentialConfirmation::NewPassword {
                    password,
                    accepted_terms,
                }) => {
                    let email = stored_email(&user).ok_or_else(invalid_token)?;
                    let activation = self
                        .new_credentials(ctx, &email, password, accepted_terms)
                        .await?;
                    (Some(activation), "link_new_password")
                }
                None => {
                    return Err(
                        AuthError::new(codes::account::REGISTRATION_CONFIRMATION_REQUIRED)
                            .with_details(
                                serde_json::json!({ "methods": ["password", "new_password"] }),
                            ),
                    );
                }
            }
        };
        let mut tx = self.begin().await?;
        if let Some(address) = user.email_normalized.as_deref() {
            lock_email(tx.conn(), address).await?;
        }
        let consumed = OneTimeTokenRepository::consume_link(
            tx.conn(),
            TokenPurpose::EmailVerification,
            &hash,
            self.now(),
        )
        .await?
        .filter(|r| r.id == found.id)
        .ok_or_else(invalid_token)?;
        let user = lock_user(&mut tx, user.id)
            .await
            .map_err(|_| invalid_token())?;
        if !target_matches(&consumed, &user) || user.email_verified_at.is_some() {
            return Err(invalid_token());
        }
        if let Some(Activation::Chosen { hash, consents }) = replacement {
            let now = self.now();
            UserRepository::set_password(
                tx.conn(),
                user.id,
                &NewPasswordHash {
                    password_hash: &hash.hash,
                    algorithm: hash.algorithm.as_str(),
                    pepper_version: hash.pepper_version,
                },
                false,
                now,
            )
            .await?;
            for version in consents {
                ConsentRepository::record(
                    tx.conn(),
                    user.id,
                    version,
                    now,
                    Some(ctx.client_ip),
                    ctx.user_agent.as_deref(),
                )
                .await?;
            }
            // Whoever knew the previous password loses every session.
            self.deps()
                .sessions
                .revoke_all_for_user(
                    tx.conn(),
                    user.id,
                    RevocationReason::PasswordChanged,
                    RevokeOptions {
                        also_trusted_devices: true,
                    },
                )
                .await?;
        }
        self.complete_verification(&mut tx, &user, Actor::Anonymous, ctx, method)
            .await?;
        tx.commit().await
    }

    /// Sleeps until `code_failure_floor` has passed since `started`.
    pub(super) async fn failure_floor(&self, started: Instant) {
        let floor = self.settings().code_failure_floor;
        if let Some(rest) = floor.checked_sub(started.elapsed()) {
            tokio::time::sleep(rest).await;
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
        self.complete_verification(&mut tx, &user, actor, ctx, "code_signed_in")
            .await?;
        tx.commit().await
    }

    /// Marks the address verified and activates a `pending_verification`
    /// account (ACC-06 transition, audited). Other statuses are kept
    /// (a suspended account stays suspended). Every pending registration of
    /// the account is deleted — their links, codes and handles can never
    /// complete afterwards — and outstanding verification tokens are
    /// revoked. `method` is audited.
    pub(super) async fn complete_verification(
        &self,
        tx: &mut AccountTx,
        user: &UserRecord,
        actor: Actor,
        ctx: &RequestContext,
        method: &'static str,
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
        RegistrationRepository::delete_for_user(tx.conn(), user.id).await?;
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
                .with_subject(user.id)
                .with_meta("method", method),
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
    /// in the background. `registration` (the caller's handle, if any)
    /// selects which registration of the address gets a fresh link and
    /// code; otherwise the newest one does.
    pub async fn resend_verification(
        &self,
        ctx: &RequestContext,
        email: &str,
        registration: Option<&SecretString>,
    ) -> Result<(), AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::VERIFICATION_RESEND_IP, ctx.client_ip),
            self.config().verification.resend_per_ip,
        )
        .await?;
        let email = parse_email(email)?;
        let service = self.clone();
        let ctx = ctx.clone();
        let registration = registration.cloned();
        self.inner.jobs.spawn("resend_verification", async move {
            service
                .process_resend(&ctx, &email, registration.as_ref())
                .await
        })
    }

    async fn process_resend(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
        registration: Option<&SecretString>,
    ) -> Result<(), AuthError> {
        let Some(user) = UserRepository::find_by_email(self.pool(), email).await? else {
            return Ok(());
        };
        if user.status != AccountStatus::PendingVerification || user.email_verified_at.is_some() {
            return Ok(());
        }
        let now = self.now();
        if let Some(registration) = self
            .registration_for_resend(user.id, registration, now)
            .await?
        {
            if !self.verification_send_allowed(email).await? {
                return Ok(());
            }
            return self.resend_registration(&registration).await;
        }
        // No registration: only an account that can sign in (and therefore
        // has a password) gets a session-style link and code; a placeholder
        // whose registrations all expired is simply purged.
        if UserRepository::find_password(self.pool(), user.id)
            .await?
            .is_none()
            || !self.verification_send_allowed(email).await?
        {
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
