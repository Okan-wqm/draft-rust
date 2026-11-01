//! Completing a registration — the account pre-hijacking defence
//! (ACC-01, ACC-02, ACC-04, ACC-05; ADR 0002).
//!
//! A registration (`pending_registrations`) holds the password, profile
//! and consents submitted with it, and is bound to three secrets: the
//! e-mailed **link**, the e-mailed **code** and the **handle** returned to
//! the registering client. Completing it is the *only* way the submitted
//! password becomes a credential of the account, and it requires proof of
//! mailbox control **and** proof that the completer chose that password:
//!
//! | Proof presented | Credentials activated |
//! |-----------------|-----------------------|
//! | link + handle (the registering browser, cookie) | the registration's |
//! | link + the password chosen in that registration | the registration's |
//! | link + a **new** password (and terms) chosen now | the new one; the registration's profile is discarded |
//! | link alone | none — `registration_confirmation_required` |
//! | code + handle (the registering client's flow) | the registration's |
//! | code without the handle (e.g. e-mail + code) | none — `invalid_code` |
//!
//! Completion runs in one transaction under the address lock, the
//! registration's row lock and the user's row lock (in this order): the
//! credentials, profile and consents are written, the address is marked
//! verified, `pending_verification` → `active`, **every** registration of
//! the account is deleted (their links, codes and handles die with them),
//! outstanding verification tokens are revoked and every session and
//! trusted device of the account is revoked. Of concurrent completions
//! (same or different registrations) exactly one succeeds.
//!
//! Brute force: a registration's code allows `verification.code_max_attempts`
//! wrong answers over its whole life (a resend rotates the code but does not
//! reset the counter), on top of the per-address and per-IP limits; the
//! "password you chose" answer allows [`MAX_PASSWORD_CONFIRMATIONS`].

use std::time::{Duration, Instant};

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{TermsVersionId, UserId};
use authn_core::ports::{
    Actor, Notification, NotificationKind, PasswordContext, RateLimitKey, RevocationReason,
    RevokeOptions, SecurityEventKind,
};
use authn_core::secret::{ExposeSecret, SecretString, SensitiveString};
use authn_crypto::otp::OtpCode;
use authn_crypto::password::PasswordHashRecord;
use authn_crypto::token::{OpaqueToken, TokenHash};
use authn_store::{NewPasswordHash, TokenPurpose, UserRepository};
use time::OffsetDateTime;

use super::verification::{invalid_code, invalid_token};
use super::{AccountService, actions, after, parse_email};
use crate::lifecycle::lock_user;
use crate::model::TermsAcceptance;
use crate::profile::DEFAULT_TIME_ZONE;
use crate::registration_store::{RegistrationRecord, RegistrationRepository, RotatedSecrets};
use crate::repo::{ConsentRepository, ProfileRepository, ProfileValues, lock_email};
use crate::tx::AccountTx;

/// Cookie carrying the registration handle in browsers (`HttpOnly`,
/// `Secure`, `SameSite=Strict`, `Path=/`). Native clients send the handle
/// in the request body instead.
pub const REGISTRATION_COOKIE: &str = "__Host-authn_registration";

/// Wrong "password you chose" answers accepted per registration on the
/// link page; after that only a new password completes it.
pub const MAX_PASSWORD_CONFIRMATIONS: i32 = 5;

/// Registrations kept per unverified account (the oldest are dropped).
pub(crate) const MAX_LIVE_REGISTRATIONS: i64 = 10;

/// What the registering client receives from [`AccountService::signup`]:
/// the registration handle (256 random bits, independent of the address,
/// so it reveals nothing about whether the address is registered).
///
/// Browsers keep it in the [`REGISTRATION_COOKIE`]; native clients keep it
/// in memory and send it with the verification code.
pub struct RegistrationReceipt {
    handle: SensitiveString,
    max_age: Duration,
}

impl RegistrationReceipt {
    pub(crate) fn new(handle: &OpaqueToken, max_age: Duration) -> Self {
        Self {
            handle: SensitiveString::new(handle.expose()),
            max_age,
        }
    }

    /// The raw handle (response body and cookie value only — never log it).
    #[must_use]
    pub fn handle(&self) -> &SensitiveString {
        &self.handle
    }

    /// How long the handle is useful (`account.unverified_purge_after`);
    /// the cookie's `Max-Age`.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        self.max_age
    }
}

impl std::fmt::Debug for RegistrationReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationReceipt")
            .field("handle", &authn_core::secret::REDACTED)
            .field("max_age", &self.max_age)
            .finish()
    }
}

/// Everything the opener of an e-mailed verification link presents besides
/// the link itself. The link proves mailbox control; one of these proves
/// (or sets) the credentials that become active.
#[derive(Default)]
pub struct LinkConfirmation {
    /// The registration handle (cookie or request body): the link is opened
    /// by the client that submitted the registration.
    pub registration: Option<SecretString>,
    /// The signed-in user opening the link (accounts verified through a
    /// session-issued link, not through a registration).
    pub signed_in_user: Option<UserId>,
    /// The password chosen at registration, or a new one.
    pub credentials: Option<CredentialConfirmation>,
}

impl std::fmt::Debug for LinkConfirmation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkConfirmation")
            .field("registration", &self.registration.is_some())
            .field("signed_in_user", &self.signed_in_user)
            .field("credentials", &self.credentials)
            .finish()
    }
}

/// How the opener of a verification link proves or sets the credentials.
pub enum CredentialConfirmation {
    /// The password chosen in this registration (or the account's current
    /// password for a session-issued link).
    ChosenPassword(SecretString),
    /// A password chosen now by the mailbox owner; replaces whatever was
    /// submitted before. The terms must be accepted again when required
    /// (ACC-11), because the registration's acceptance was not theirs.
    NewPassword {
        /// The new password (validated by the password policy).
        password: SecretString,
        /// Accepted current terms versions.
        accepted_terms: Vec<TermsAcceptance>,
    },
}

impl std::fmt::Debug for CredentialConfirmation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChosenPassword(_) => f.write_str("ChosenPassword([REDACTED])"),
            Self::NewPassword { accepted_terms, .. } => f
                .debug_struct("NewPassword")
                .field("password", &authn_core::secret::REDACTED)
                .field("accepted_terms", accepted_terms)
                .finish(),
        }
    }
}

/// Which credentials a completion activates.
pub(super) enum Activation {
    /// The credentials, profile and consents submitted with the
    /// registration (the completer proved they submitted it).
    Submitted,
    /// A password chosen now by the mailbox owner; the registration's
    /// profile and consents are discarded.
    Chosen {
        hash: PasswordHashRecord,
        consents: Vec<TermsVersionId>,
    },
}

/// `registration_confirmation_required` (the methods a page can offer).
fn confirmation_required() -> AuthError {
    AuthError::new(codes::account::REGISTRATION_CONFIRMATION_REQUIRED)
        .with_details(serde_json::json!({ "methods": ["password", "new_password"] }))
}

fn password_mismatch() -> AuthError {
    AuthError::new(codes::account::REGISTRATION_PASSWORD_MISMATCH)
}

/// Parses an optional raw handle (malformed values count as absent).
fn handle_hash(raw: Option<&SecretString>) -> Option<TokenHash> {
    raw.and_then(|h| OpaqueToken::parse(h.expose_secret()).ok())
        .map(|h| h.hash())
}

impl AccountService {
    /// Link flow of a registration (see the module table).
    pub(super) async fn verify_registration_link(
        &self,
        ctx: &RequestContext,
        record: RegistrationRecord,
        link: TokenHash,
        confirmation: &LinkConfirmation,
    ) -> Result<(), AuthError> {
        let bound = handle_hash(confirmation.registration.as_ref())
            .is_some_and(|candidate| record.handle_matches(&candidate));
        let (activation, method) = if bound {
            (Activation::Submitted, "link_registering_client")
        } else {
            match &confirmation.credentials {
                Some(CredentialConfirmation::ChosenPassword(password)) => {
                    self.check_registration_password(ctx, &record, password)
                        .await?;
                    (Activation::Submitted, "link_chosen_password")
                }
                Some(CredentialConfirmation::NewPassword {
                    password,
                    accepted_terms,
                }) => {
                    let email = EmailAddress::parse(&record.email_normalized)
                        .map_err(|_| invalid_token())?;
                    let activation = self
                        .new_credentials(ctx, &email, password, accepted_terms)
                        .await?;
                    (activation, "link_new_password")
                }
                None => {
                    self.audit_unconfirmed_link(ctx, record.user_id).await;
                    return Err(confirmation_required());
                }
            }
        };
        let mut tx = self.begin().await?;
        lock_email(tx.conn(), &record.email_normalized).await?;
        let Some(locked) = RegistrationRepository::lock(tx.conn(), record.id, self.now()).await?
        else {
            return Err(invalid_token());
        };
        // The link may have been rotated (resend) or used meanwhile.
        if !locked.link_matches(&link) || locked.link_expires_at <= self.now() {
            return Err(invalid_token());
        }
        self.finish_registration(tx, ctx, locked, activation, method, invalid_token)
            .await
    }

    /// Verifies the password chosen in `record` (Argon2, outside any
    /// transaction); counts and limits wrong answers.
    async fn check_registration_password(
        &self,
        ctx: &RequestContext,
        record: &RegistrationRecord,
        password: &SecretString,
    ) -> Result<(), AuthError> {
        if record.password_attempts >= MAX_PASSWORD_CONFIRMATIONS {
            return Err(password_mismatch());
        }
        let stored = record.stored_password()?;
        if self
            .deps()
            .hasher
            .verify(password, Some(&stored))
            .await?
            .is_valid()
        {
            return Ok(());
        }
        let mut tx = self.begin().await?;
        RegistrationRepository::record_password_failure(tx.conn(), record.id).await?;
        tx.audit(
            self.event(SecurityEventKind::EmailVerified, ctx)
                .with_subject(record.user_id)
                .with_meta("method", "link_chosen_password")
                .failed("password_mismatch"),
        );
        tx.commit().await?;
        Err(password_mismatch())
    }

    /// A password (and terms acceptance) chosen now by the mailbox owner:
    /// policy-checked and hashed before any lock is taken.
    pub(super) async fn new_credentials(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
        password: &SecretString,
        accepted_terms: &[TermsAcceptance],
    ) -> Result<Activation, AuthError> {
        let consents = self.signup_consents(accepted_terms).await?;
        let check = self
            .deps()
            .password_validator
            .validate(
                password,
                &PasswordContext {
                    email: Some(email.clone()),
                    display_name: None,
                    locale: ctx.locale,
                },
            )
            .await?;
        if !check.is_acceptable() {
            return Err(super::signup::password_policy_error(&check));
        }
        let hash = self.deps().hasher.hash(password).await?;
        Ok(Activation::Chosen { hash, consents })
    }

    /// ACC-04: the registering client submits the e-mailed code together
    /// with its registration handle (body or cookie). Without the handle —
    /// e.g. the old "e-mail + code" form — no registration can be
    /// completed. Every failure answers `invalid_code`, no faster than
    /// `code_failure_floor`.
    pub async fn verify_email_code(
        &self,
        ctx: &RequestContext,
        registration: Option<&SecretString>,
        email: Option<&str>,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let started = Instant::now();
        let result = self
            .verify_registration_code(ctx, registration, email, code)
            .await;
        if result.is_err() {
            self.failure_floor(started).await;
        }
        result
    }

    async fn verify_registration_code(
        &self,
        ctx: &RequestContext,
        registration: Option<&SecretString>,
        email: Option<&str>,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let verification = &self.config().verification;
        self.limit(
            &RateLimitKey::ip(actions::VERIFY_IP, ctx.client_ip),
            verification.verify_per_ip,
        )
        .await?;
        let email = email.map(parse_email).transpose()?;
        let code = OtpCode::parse(code.expose_secret()).map_err(|_| invalid_code())?;
        let now = self.now();
        let record = match handle_hash(registration) {
            Some(hash) => RegistrationRepository::find_by_handle(self.pool(), &hash, now).await?,
            None => None,
        };
        // Per-address budget across every registration of the address (a
        // new registration must not multiply guesses); keyed on the
        // submitted address when the handle is unknown.
        let budget_address = record
            .as_ref()
            .map(|r| r.email_normalized.clone())
            .or_else(|| email.as_ref().map(|e| e.normalized().to_owned()));
        if let Some(address) = budget_address {
            self.limit(
                &RateLimitKey::account(actions::VERIFICATION_CODE, &address),
                verification.code_attempts_per_email,
            )
            .await?;
        }
        let Some(record) = record.filter(|r| {
            email
                .as_ref()
                .is_none_or(|e| e.normalized() == r.email_normalized)
        }) else {
            self.audit_failed_code(ctx, None, "no_registration").await;
            return Err(invalid_code());
        };
        let candidate = self
            .deps()
            .otp
            .hash(TokenPurpose::EmailVerificationCode.as_str(), &code);
        let max_attempts = i32::try_from(verification.code_max_attempts).unwrap_or(i32::MAX);

        let mut tx = self.begin().await?;
        lock_email(tx.conn(), &record.email_normalized).await?;
        let Some(locked) = RegistrationRepository::lock(tx.conn(), record.id, now).await? else {
            self.audit_failed_code(ctx, Some(record.user_id), "no_registration")
                .await;
            return Err(invalid_code());
        };
        if locked.code_attempts >= max_attempts {
            drop(tx);
            self.audit_failed_code(ctx, Some(record.user_id), "locked_out")
                .await;
            return Err(invalid_code());
        }
        if locked.code_expires_at <= now || !locked.code_matches(&candidate) {
            let attempts =
                RegistrationRepository::record_code_failure(tx.conn(), locked.id).await?;
            tx.commit().await?;
            let reason = if attempts >= max_attempts {
                "locked_out"
            } else if locked.code_expires_at <= now {
                "expired"
            } else {
                "invalid_code"
            };
            self.audit_failed_code(ctx, Some(record.user_id), reason)
                .await;
            return Err(invalid_code());
        }
        self.finish_registration(
            tx,
            ctx,
            locked,
            Activation::Submitted,
            "code_registering_client",
            invalid_code,
        )
        .await
    }

    /// Activates the account with `activation` (see the module docs). `tx`
    /// holds the address lock and the registration's row lock.
    async fn finish_registration(
        &self,
        mut tx: AccountTx,
        ctx: &RequestContext,
        registration: RegistrationRecord,
        activation: Activation,
        method: &'static str,
        failure: fn() -> AuthError,
    ) -> Result<(), AuthError> {
        let now = self.now();
        let user = lock_user(&mut tx, registration.user_id)
            .await
            .map_err(|_| failure())?;
        if user.status != AccountStatus::PendingVerification
            || user.email_verified_at.is_some()
            || user.email_normalized.as_deref() != Some(registration.email_normalized.as_str())
        {
            // The account left verification by another route: this
            // registration can never complete any more.
            RegistrationRepository::delete(tx.conn(), registration.id).await?;
            tx.commit().await?;
            return Err(failure());
        }
        match &activation {
            Activation::Submitted => {
                // The completer's own spelling of the address (the first
                // registrant only chose the placeholder's).
                if let Ok(email) = EmailAddress::parse(&registration.email)
                    && email.normalized() == registration.email_normalized
                {
                    UserRepository::update_email(tx.conn(), user.id, &email, Some(now)).await?;
                }
                let stored = registration.stored_password()?;
                UserRepository::set_password(
                    tx.conn(),
                    user.id,
                    &NewPasswordHash {
                        password_hash: &stored.hash,
                        algorithm: &stored.algorithm,
                        pepper_version: stored.pepper_version,
                    },
                    false,
                    now,
                )
                .await?;
                ProfileRepository::upsert(
                    tx.conn(),
                    user.id,
                    &ProfileValues {
                        display_name: registration.display_name.as_deref(),
                        locale: registration.locale,
                        time_zone: &registration.time_zone,
                    },
                    now,
                )
                .await?;
                for version in registration.terms_versions() {
                    ConsentRepository::record(
                        tx.conn(),
                        user.id,
                        version,
                        registration.created_at,
                        registration.created_ip,
                        registration.user_agent.as_deref(),
                    )
                    .await?;
                }
            }
            Activation::Chosen { hash, consents } => {
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
                ProfileRepository::upsert(
                    tx.conn(),
                    user.id,
                    &ProfileValues {
                        display_name: None,
                        locale: ctx.locale,
                        time_zone: DEFAULT_TIME_ZONE,
                    },
                    now,
                )
                .await?;
                for version in consents {
                    ConsentRepository::record(
                        tx.conn(),
                        user.id,
                        *version,
                        now,
                        Some(ctx.client_ip),
                        ctx.user_agent.as_deref(),
                    )
                    .await?;
                }
            }
        }
        // Nobody but the completer may keep access to the account: whatever
        // existed before (sessions of a legacy limited-mode login, trusted
        // devices) ends here.
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
        self.complete_verification(&mut tx, &user, Actor::Anonymous, ctx, method)
            .await?;
        tx.commit().await?;
        metrics::counter!("authn_account_registrations_completed_total", "method" => method)
            .increment(1);
        Ok(())
    }

    /// ACC-04 resend for a registration: new link + code (the attempt
    /// counters stay), same handle; e-mail in the registration's language.
    pub(super) async fn resend_registration(
        &self,
        registration: &RegistrationRecord,
    ) -> Result<(), AuthError> {
        let now = self.now();
        let verification = &self.config().verification;
        let token = OpaqueToken::generate()?;
        let code = OtpCode::generate()?;
        let link_expires_at = after(now, verification.link_ttl)?;
        let code_expires_at = after(now, verification.code_ttl)?;
        let mut tx = self.begin().await?;
        lock_email(tx.conn(), &registration.email_normalized).await?;
        let Some(locked) = RegistrationRepository::lock(tx.conn(), registration.id, now).await?
        else {
            return Ok(());
        };
        let Some(user) = UserRepository::lock_for_update(tx.conn(), locked.user_id).await? else {
            return Ok(());
        };
        if user.email_verified_at.is_some()
            || user.email_normalized.as_deref() != Some(locked.email_normalized.as_str())
        {
            return Ok(());
        }
        let Some(email) = super::stored_email(&user) else {
            return Ok(());
        };
        RegistrationRepository::rotate(
            tx.conn(),
            locked.id,
            &RotatedSecrets {
                link_hash: &token.hash(),
                link_expires_at,
                code_hash: &self
                    .deps()
                    .otp
                    .hash(TokenPurpose::EmailVerificationCode.as_str(), &code),
                code_expires_at,
            },
        )
        .await?;
        let (recipient, locale) = self
            .unproven_recipient_at(tx.conn(), user.id, email, locked.locale)
            .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                tx.conn(),
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::EmailVerification {
                        token: token.into_sensitive(),
                        code: code.into_sensitive(),
                        expires_at: link_expires_at.min(locked.expires_at),
                    },
                },
            )
            .await?;
        tx.commit().await
    }

    /// The registration a resend refers to: the caller's own (handle) when
    /// it belongs to `user`, otherwise the newest live one.
    pub(super) async fn registration_for_resend(
        &self,
        user: UserId,
        registration: Option<&SecretString>,
        now: OffsetDateTime,
    ) -> Result<Option<RegistrationRecord>, AuthError> {
        if let Some(hash) = handle_hash(registration)
            && let Some(own) =
                RegistrationRepository::find_by_handle(self.pool(), &hash, now).await?
            && own.user_id == user
        {
            return Ok(Some(own));
        }
        Ok(RegistrationRepository::newest_live(self.pool(), user, now).await?)
    }

    async fn audit_failed_code(&self, ctx: &RequestContext, user: Option<UserId>, reason: &str) {
        let mut event = self
            .event(SecurityEventKind::EmailVerified, ctx)
            .with_meta("method", "code")
            .failed(reason);
        if let Some(user) = user {
            event = event.with_subject(user);
        }
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::warn!(error = %err, "failed verification could not be audited");
        }
    }

    async fn audit_unconfirmed_link(&self, ctx: &RequestContext, user: UserId) {
        let event = self
            .event(SecurityEventKind::EmailVerified, ctx)
            .with_subject(user)
            .with_meta("method", "link")
            .failed("confirmation_required");
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::warn!(error = %err, "unconfirmed verification could not be audited");
        }
    }
}
