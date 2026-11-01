//! Registration (ACC-01, ACC-02, ACC-12, ACC-13).
//!
//! **Synchronous part** (identical for every address): per-IP rate limit →
//! CAPTCHA per policy → address syntax (ACC-03) → disposable-domain list
//! (ACC-12) → profile fields → terms acceptance (ACC-11) → password policy
//! (`PasswordValidator`, ACC-01) → Argon2id hash → hand-over to a
//! background job → `202 Accepted`. Nothing in this part looks at existing
//! accounts, so status, body and timing are the same for new and
//! registered addresses (ACC-02); the expensive hash is computed on both
//! paths.
//!
//! The synchronous part also generates the **registration handle** (256
//! bits, independent of the address) that the caller returns to the
//! registering client (response body and `__Host-authn_registration`
//! cookie). It is the client's proof of "I submitted this registration"
//! (ADR 0002).
//!
//! **Background part** (serialized per address with an advisory lock):
//! * new address → a `pending_verification` placeholder account **without
//!   credentials**, a `pending_registrations` row holding the submitted
//!   password hash, profile and consents bound to its own link, code and
//!   handle, `user.created` event, `account.registered` audit, verification
//!   e-mail;
//! * registered and **never verified** → another registration of the same
//!   placeholder (throttled per address). Nothing that exists changes: no
//!   credentials, profile or sessions are touched. Each registration
//!   activates only its own credentials, and only through its own link or
//!   code (see `registration.rs`) — so neither an attacker registering
//!   *first* (squatting) nor *second* (overwriting) can end up with a
//!   verified account holding a password the mailbox owner did not choose;
//! * registered and verified (or reserved for a revert, ACC-07) → the
//!   owner receives a "someone tried to register with your address"
//!   e-mail with the sign-in and password-reset paths (at most
//!   `account.registration_notice_per_email`); credentials never change.

use authn_core::config::common::CaptchaPolicy;
use authn_core::domain::{AccountStatus, EmailAddress, Locale};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{TermsVersionId, UserId};
use authn_core::ports::{
    Actor, CaptchaContext, CaptchaProvider, CaptchaVerdict, DomainEvent, DomainEventKind,
    Notification, NotificationKind, PasswordCheck, PasswordContext, RateLimitKey,
    SecurityEventKind,
};
use authn_crypto::otp::OtpCode;
use authn_crypto::password::PasswordHashRecord;
use authn_crypto::token::{OpaqueToken, TokenHash};
use authn_store::{NewUser, StoreError, TokenPurpose, UserRecord, UserRepository};
use uuid::Uuid;

use super::registration::{MAX_LIVE_REGISTRATIONS, RegistrationReceipt};
use super::{AccountService, actions, after, parse_email};
use crate::model::{SignupInput, TermsAcceptance};
use crate::profile::{DEFAULT_TIME_ZONE, normalize_display_name, validate_time_zone};
use crate::registration_store::{NewRegistration, RegistrationRepository};
use crate::repo::{ReservationRepository, TermsRepository, lock_email};
use crate::tx::AccountTx;

/// CAPTCHA action name bound into proof-of-work challenges.
const CAPTCHA_ACTION: &str = "register";
/// Longest CAPTCHA response accepted (bytes).
const MAX_CAPTCHA_RESPONSE_BYTES: usize = 8192;
/// Most `accepted_terms` entries accepted in one request.
const MAX_TERMS_ENTRIES: usize = 8;

/// Everything the background part needs (validated values only).
struct SignupWork {
    ctx: RequestContext,
    email: EmailAddress,
    /// SHA-256 of the registration handle given to the registering client.
    handle_hash: TokenHash,
    hash: PasswordHashRecord,
    display_name: Option<String>,
    locale: Locale,
    time_zone: &'static str,
    consents: Vec<TermsVersionId>,
}

/// Why an existing address received a notice instead of a new account.
#[derive(Debug, Clone, Copy)]
enum NoticeReason {
    ExistingAccount,
    ReservedAddress,
}

impl NoticeReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ExistingAccount => "existing_account",
            Self::ReservedAddress => "reserved_address",
        }
    }
}

impl AccountService {
    /// Registers an account (see the module docs). Always answers with a
    /// fresh [`RegistrationReceipt`] (`202`) once the input is valid —
    /// whether or not the address is already registered; the receipt is
    /// random and reveals nothing about the address.
    pub async fn signup(
        &self,
        ctx: &RequestContext,
        input: SignupInput,
    ) -> Result<RegistrationReceipt, AuthError> {
        let config = self.config();
        self.limit(
            &RateLimitKey::ip(actions::REGISTER, ctx.client_ip),
            config.registration_per_ip,
        )
        .await?;
        self.enforce_registration_captcha(ctx, input.captcha.as_deref())
            .await?;

        let email = parse_email(&input.email)?;
        if let Some(list) = &self.settings().disposable_domains {
            list.check(&email)?;
        }
        let display_name = input
            .display_name
            .as_deref()
            .map(|name| normalize_display_name(name, config.display_name_max_chars))
            .transpose()?;
        let time_zone = match input.time_zone.as_deref() {
            Some(tz) => validate_time_zone(tz)?,
            None => DEFAULT_TIME_ZONE,
        };
        let locale = input.locale.unwrap_or(ctx.locale);
        let consents = self.signup_consents(&input.accepted_terms).await?;

        let check = self
            .deps()
            .password_validator
            .validate(
                &input.password,
                &PasswordContext {
                    email: Some(email.clone()),
                    display_name: display_name.clone(),
                    locale,
                },
            )
            .await?;
        if !check.is_acceptable() {
            return Err(password_policy_error(&check));
        }
        // Same cost for every address (ACC-02).
        let hash = self.deps().hasher.hash(&input.password).await?;
        let handle = OpaqueToken::generate()?;
        let receipt = RegistrationReceipt::new(&handle, self.config().unverified_purge_after);

        let work = SignupWork {
            ctx: ctx.clone(),
            email,
            handle_hash: handle.hash(),
            hash,
            display_name,
            locale,
            time_zone,
            consents,
        };
        let service = self.clone();
        self.inner
            .jobs
            .spawn("signup", async move { service.process_signup(work).await })?;
        Ok(receipt)
    }

    /// ACC-13: CAPTCHA according to `account.registration_captcha`.
    async fn enforce_registration_captcha(
        &self,
        ctx: &RequestContext,
        response: Option<&str>,
    ) -> Result<(), AuthError> {
        let verifier = &self.deps().captcha;
        if verifier.provider() == CaptchaProvider::Disabled {
            return Ok(());
        }
        let required = match self.config().registration_captcha {
            CaptchaPolicy::Never => false,
            CaptchaPolicy::Always => true,
            CaptchaPolicy::RiskBased => {
                !self
                    .allowed(
                        &RateLimitKey::ip(actions::REGISTER_CAPTCHA_FREE, ctx.client_ip),
                        self.config().registration_captcha_free_per_ip,
                    )
                    .await?
            }
        };
        if !required {
            return Ok(());
        }
        let captcha_ctx = CaptchaContext {
            action: CAPTCHA_ACTION,
            ip: ctx.client_ip,
        };
        let Some(response) =
            response.filter(|r| !r.is_empty() && r.len() <= MAX_CAPTCHA_RESPONSE_BYTES)
        else {
            let challenge = verifier.issue_challenge(&captcha_ctx).await?;
            return Err(AuthError::new(codes::protect::CAPTCHA_REQUIRED)
                .with_details(serde_json::json!({ "captcha": challenge })));
        };
        match verifier.verify(response, &captcha_ctx).await? {
            CaptchaVerdict::Passed => Ok(()),
            CaptchaVerdict::Failed => {
                let event = self
                    .event(SecurityEventKind::CaptchaFailed, ctx)
                    .failed("captcha_failed")
                    .with_meta("action", CAPTCHA_ACTION);
                if let Err(err) = self.deps().audit.record(event).await {
                    tracing::warn!(error = %err, "captcha failure could not be audited");
                }
                let challenge = verifier.issue_challenge(&captcha_ctx).await?;
                Err(AuthError::new(codes::protect::CAPTCHA_FAILED)
                    .with_details(serde_json::json!({ "captcha": challenge })))
            }
            CaptchaVerdict::Unavailable if self.settings().captcha_fail_open => {
                tracing::warn!("captcha provider unavailable; registration allowed (fail-open)");
                Ok(())
            }
            CaptchaVerdict::Unavailable => Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("captcha provider unavailable")),
        }
    }

    /// ACC-11: the submitted acceptances must name current versions; with
    /// `account.require_terms_acceptance`, every current document must be
    /// accepted.
    pub(super) async fn signup_consents(
        &self,
        accepted: &[TermsAcceptance],
    ) -> Result<Vec<TermsVersionId>, AuthError> {
        if accepted.len() > MAX_TERMS_ENTRIES {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("too many accepted_terms entries"));
        }
        let current = TermsRepository::current(self.pool(), self.now()).await?;
        let mut ids = Vec::new();
        for acceptance in accepted {
            let Some(version) = current
                .iter()
                .find(|v| v.document == acceptance.document && v.version == acceptance.version)
            else {
                return Err(AuthError::new(codes::account::TERMS_VERSION_NOT_CURRENT));
            };
            if !ids.contains(&version.id) {
                ids.push(version.id);
            }
        }
        if self.config().require_terms_acceptance && current.iter().any(|v| !ids.contains(&v.id)) {
            return Err(AuthError::new(codes::account::TERMS_ACCEPTANCE_REQUIRED).with_details(
                serde_json::json!({
                    "documents": current
                        .iter()
                        .map(|v| serde_json::json!({ "document": v.document, "version": v.version }))
                        .collect::<Vec<_>>()
                }),
            ));
        }
        Ok(ids)
    }

    /// The background part of [`Self::signup`].
    async fn process_signup(&self, work: SignupWork) -> Result<(), AuthError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        lock_email(tx.conn(), work.email.normalized()).await?;
        let existing = UserRepository::find_by_email(tx.conn(), &work.email).await?;
        let reserved_by =
            ReservationRepository::active_owner(tx.conn(), work.email.normalized(), now).await?;
        match (existing, reserved_by) {
            (None, None) => match self.create_account(tx, &work).await {
                Err(err) if is_email_conflict(&err) => {
                    // Written by a path that does not take the address lock
                    // (e.g. an admin tool): treat as an existing account.
                    let mut tx = self.begin().await?;
                    let Some(user) = UserRepository::find_by_email(tx.conn(), &work.email).await?
                    else {
                        return Err(err);
                    };
                    self.registration_notice(
                        &mut tx,
                        &work,
                        user.id,
                        NoticeReason::ExistingAccount,
                    )
                    .await?;
                    tx.commit().await
                }
                other => other,
            },
            (Some(user), _)
                if user.status == AccountStatus::PendingVerification
                    && user.email_verified_at.is_none() =>
            {
                self.add_registration(tx, &work, user).await
            }
            (Some(user), _) => {
                self.registration_notice(&mut tx, &work, user.id, NoticeReason::ExistingAccount)
                    .await?;
                tx.commit().await
            }
            (None, Some(owner)) => {
                self.registration_notice(&mut tx, &work, owner, NoticeReason::ReservedAddress)
                    .await?;
                tx.commit().await
            }
        }
    }

    /// First registration of an address: a placeholder account without
    /// credentials plus the registration that holds them.
    async fn create_account(&self, mut tx: AccountTx, work: &SignupWork) -> Result<(), AuthError> {
        let now = self.now();
        let user_id = UserId::generate();
        UserRepository::create(
            tx.conn(),
            &NewUser {
                id: user_id,
                email: work.email.clone(),
                status: AccountStatus::PendingVerification,
                created_at: now,
            },
        )
        .await?;
        self.create_registration(&mut tx, user_id, work).await?;
        self.deps()
            .events
            .publish(
                tx.conn(),
                DomainEvent {
                    user_id: Some(user_id),
                    ..DomainEvent::new(
                        DomainEventKind::UserCreated,
                        now,
                        serde_json::json!({ "user_id": user_id, "status": AccountStatus::PendingVerification }),
                    )
                },
            )
            .await?;
        tx.audit(
            self.event(SecurityEventKind::AccountRegistered, &work.ctx)
                .with_actor(Actor::Anonymous)
                .with_subject(user_id)
                .with_resource("user", user_id),
        );
        tx.commit().await?;
        metrics::counter!("authn_account_registrations_total", "outcome" => "created").increment(1);
        Ok(())
    }

    /// Registration of an address whose account was never verified: one
    /// more registration of the placeholder, bound to its own secrets.
    /// Nothing that exists changes — no credentials, profile, consents or
    /// sessions — so a later registrant can neither overwrite an earlier
    /// one nor inherit anything from it (ADR 0002).
    async fn add_registration(
        &self,
        mut tx: AccountTx,
        work: &SignupWork,
        user: UserRecord,
    ) -> Result<(), AuthError> {
        let notice_key =
            RateLimitKey::account(actions::REGISTRATION_NOTICE, work.email.normalized());
        if !self
            .allowed(&notice_key, self.config().registration_notice_per_email)
            .await?
        {
            tx.audit(
                self.event(
                    SecurityEventKind::AccountRegistrationAttemptExisting,
                    &work.ctx,
                )
                .with_subject(user.id)
                .with_meta("reason", "unverified_reregistration")
                .failed("rate_limited"),
            );
            return tx.commit().await;
        }
        let Some(user) = UserRepository::lock_for_update(tx.conn(), user.id).await? else {
            return tx.commit().await;
        };
        if user.status != AccountStatus::PendingVerification || user.email_verified_at.is_some() {
            self.registration_notice_unthrottled(
                &mut tx,
                work,
                user.id,
                NoticeReason::ExistingAccount,
            )
            .await?;
            return tx.commit().await;
        }
        self.create_registration(&mut tx, user.id, work).await?;
        tx.audit(
            self.event(
                SecurityEventKind::AccountRegistrationAttemptExisting,
                &work.ctx,
            )
            .with_subject(user.id)
            .with_meta("reason", "unverified_reregistration"),
        );
        tx.commit().await?;
        metrics::counter!("authn_account_registrations_total", "outcome" => "additional_registration")
            .increment(1);
        Ok(())
    }

    /// ACC-02: "someone tried to register with your address", throttled
    /// per address against mail bombing.
    async fn registration_notice(
        &self,
        tx: &mut AccountTx,
        work: &SignupWork,
        owner: UserId,
        reason: NoticeReason,
    ) -> Result<(), AuthError> {
        let notice_key =
            RateLimitKey::account(actions::REGISTRATION_NOTICE, work.email.normalized());
        if self
            .allowed(&notice_key, self.config().registration_notice_per_email)
            .await?
        {
            self.registration_notice_unthrottled(tx, work, owner, reason)
                .await
        } else {
            tx.audit(
                self.event(
                    SecurityEventKind::AccountRegistrationAttemptExisting,
                    &work.ctx,
                )
                .with_subject(owner)
                .with_meta("reason", reason.as_str())
                .with_meta("notified", false),
            );
            Ok(())
        }
    }

    async fn registration_notice_unthrottled(
        &self,
        tx: &mut AccountTx,
        work: &SignupWork,
        owner: UserId,
        reason: NoticeReason,
    ) -> Result<(), AuthError> {
        // Prefer the stored spelling of the address for existing accounts.
        let stored = match reason {
            NoticeReason::ExistingAccount => UserRepository::find_by_id(tx.conn(), owner)
                .await?
                .and_then(|u| super::stored_email(&u)),
            NoticeReason::ReservedAddress => None,
        };
        let address = stored.unwrap_or_else(|| work.email.clone());
        let (recipient, locale) = self
            .recipient_at(tx.conn(), owner, address, work.locale)
            .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                tx.conn(),
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::RegistrationAttempt,
                },
            )
            .await?;
        tx.audit(
            self.event(
                SecurityEventKind::AccountRegistrationAttemptExisting,
                &work.ctx,
            )
            .with_subject(owner)
            .with_meta("reason", reason.as_str())
            .with_meta("notified", true),
        );
        metrics::counter!("authn_account_registrations_total", "outcome" => "existing")
            .increment(1);
        Ok(())
    }

    /// Stores a registration of `user` (credentials, profile, consents,
    /// link, code and the client handle), keeps at most
    /// `MAX_LIVE_REGISTRATIONS` per account and enqueues the verification
    /// e-mail; also starts the resend cooldown of the address.
    async fn create_registration(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        work: &SignupWork,
    ) -> Result<(), AuthError> {
        let now = self.now();
        let verification = &self.config().verification;
        let token = OpaqueToken::generate()?;
        let code = OtpCode::generate()?;
        let link_expires_at = after(now, verification.link_ttl)?;
        let code_expires_at = after(now, verification.code_ttl)?;
        let expires_at = after(now, self.config().unverified_purge_after)?;
        RegistrationRepository::insert(
            tx.conn(),
            &NewRegistration {
                id: Uuid::now_v7(),
                user_id: user,
                email: &work.email,
                handle_hash: &work.handle_hash,
                link_hash: &token.hash(),
                link_expires_at,
                code_hash: &self
                    .deps()
                    .otp
                    .hash(TokenPurpose::EmailVerificationCode.as_str(), &code),
                code_expires_at,
                password_hash: &work.hash.hash,
                password_algorithm: work.hash.algorithm.as_str(),
                pepper_version: work.hash.pepper_version,
                display_name: work.display_name.as_deref(),
                locale: work.locale,
                time_zone: work.time_zone,
                terms_version_ids: &work.consents,
                created_ip: Some(work.ctx.client_ip),
                user_agent: work.ctx.user_agent.as_deref(),
                created_at: now,
                expires_at,
            },
        )
        .await?;
        RegistrationRepository::trim(tx.conn(), user, MAX_LIVE_REGISTRATIONS).await?;
        self.record_verification_send(&work.email).await?;
        let (recipient, locale) = self
            .unproven_recipient_at(tx.conn(), user, work.email.clone(), work.locale)
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
                        expires_at: link_expires_at.min(expires_at),
                    },
                },
            )
            .await
    }
}

/// `password_policy_violation` with the violations and feedback (they only
/// describe the submitted password).
pub(super) fn password_policy_error(check: &PasswordCheck) -> AuthError {
    AuthError::new(codes::password::PASSWORD_POLICY_VIOLATION).with_details(serde_json::json!({
        "score": check.score,
        "violations": check.violations,
        "feedback": check.feedback,
    }))
}

/// Whether `err` is the unique violation of `users.email_normalized`.
fn is_email_conflict(err: &AuthError) -> bool {
    err.code() == codes::common::CONFLICT
        && std::error::Error::source(err)
            .and_then(|s| s.downcast_ref::<StoreError>())
            .is_some_and(|s| s.is_unique_violation(authn_store::users::EMAIL_UNIQUE_CONSTRAINT))
}
