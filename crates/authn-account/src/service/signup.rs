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
//! **Background part** (serialized per address with an advisory lock):
//! * new address → user (`pending_verification`), profile, password,
//!   consents, verification link + code, `user.created` event,
//!   `account.registered` audit, verification e-mail;
//! * registered and **never verified** → nobody has proven control of the
//!   address yet, so the latest registrant wins: the password is replaced,
//!   every session of the unverified account is revoked and a fresh
//!   verification is sent to the address (defeats account pre-hijacking
//!   with a squatted, unverified registration);
//! * registered and verified (or reserved for a revert, ACC-07) → the
//!   owner receives a "someone tried to register with your address"
//!   e-mail (at most `account.registration_notice_per_email`).

use authn_core::config::common::CaptchaPolicy;
use authn_core::domain::{AccountStatus, EmailAddress, Locale};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{TermsVersionId, UserId};
use authn_core::ports::{
    Actor, CaptchaContext, CaptchaProvider, CaptchaVerdict, DomainEvent, DomainEventKind,
    Notification, NotificationKind, PasswordCheck, PasswordContext, RateLimitKey, RevocationReason,
    RevokeOptions, SecurityEventKind,
};
use authn_crypto::password::PasswordHashRecord;
use authn_store::{NewPasswordHash, NewUser, StoreError, TokenPurpose, UserRecord, UserRepository};

use super::{AccountService, actions, parse_email};
use crate::model::{SignupInput, TermsAcceptance};
use crate::profile::{DEFAULT_TIME_ZONE, normalize_display_name, validate_time_zone};
use crate::repo::{
    ConsentRepository, ProfileRepository, ProfileValues, ReservationRepository, TermsRepository,
    lock_email,
};
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
    /// Registers an account (see the module docs). Always answers `Ok(())`
    /// (`202`) once the input is valid — whether or not the address is
    /// already registered.
    pub async fn signup(&self, ctx: &RequestContext, input: SignupInput) -> Result<(), AuthError> {
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

        let work = SignupWork {
            ctx: ctx.clone(),
            email,
            hash,
            display_name,
            locale,
            time_zone,
            consents,
        };
        let service = self.clone();
        self.inner
            .jobs
            .spawn("signup", async move { service.process_signup(work).await })
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
    async fn signup_consents(
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
                self.reregister_unverified(tx, &work, user).await
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
        ProfileRepository::upsert(
            tx.conn(),
            user_id,
            &ProfileValues {
                display_name: work.display_name.as_deref(),
                locale: work.locale,
                time_zone: work.time_zone,
            },
            now,
        )
        .await?;
        self.store_password(&mut tx, user_id, &work.hash).await?;
        self.store_consents(&mut tx, user_id, work).await?;
        self.send_verification(&mut tx, user_id, work).await?;
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

    async fn reregister_unverified(
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
        let now = self.now();
        self.store_password(&mut tx, user.id, &work.hash).await?;
        ProfileRepository::upsert(
            tx.conn(),
            user.id,
            &ProfileValues {
                display_name: work.display_name.as_deref(),
                locale: work.locale,
                time_zone: work.time_zone,
            },
            now,
        )
        .await?;
        self.store_consents(&mut tx, user.id, work).await?;
        // Whoever registered before never proved control of the address:
        // their sessions end here.
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
        self.send_verification(&mut tx, user.id, work).await?;
        tx.audit(
            self.event(
                SecurityEventKind::AccountRegistrationAttemptExisting,
                &work.ctx,
            )
            .with_subject(user.id)
            .with_meta("reason", "unverified_reregistration"),
        );
        tx.commit().await?;
        metrics::counter!("authn_account_registrations_total", "outcome" => "reregistered")
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

    async fn store_password(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        hash: &PasswordHashRecord,
    ) -> Result<(), AuthError> {
        UserRepository::set_password(
            tx.conn(),
            user,
            &NewPasswordHash {
                password_hash: &hash.hash,
                algorithm: hash.algorithm.as_str(),
                pepper_version: hash.pepper_version,
            },
            false,
            self.now(),
        )
        .await?;
        Ok(())
    }

    async fn store_consents(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        work: &SignupWork,
    ) -> Result<(), AuthError> {
        for version in &work.consents {
            ConsentRepository::record(
                tx.conn(),
                user,
                *version,
                self.now(),
                Some(work.ctx.client_ip),
                work.ctx.user_agent.as_deref(),
            )
            .await?;
        }
        Ok(())
    }

    /// Issues the verification link + code and enqueues the e-mail; also
    /// starts the resend cooldown of the address.
    async fn send_verification(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        work: &SignupWork,
    ) -> Result<(), AuthError> {
        let secrets = self
            .issue_link_and_code(
                tx.conn(),
                (
                    TokenPurpose::EmailVerification,
                    TokenPurpose::EmailVerificationCode,
                ),
                user,
                &work.email,
                Some(work.ctx.client_ip),
            )
            .await?;
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
                        token: secrets.token.into_sensitive(),
                        code: secrets.code.into_sensitive(),
                        expires_at: secrets.link_expires_at,
                    },
                },
            )
            .await
    }
}

/// `password_policy_violation` with the violations and feedback (they only
/// describe the submitted password).
fn password_policy_error(check: &PasswordCheck) -> AuthError {
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
