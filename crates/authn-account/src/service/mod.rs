//! [`AccountService`]: every account use case.
//!
//! | Method | Requirement | Caller |
//! |--------|-------------|--------|
//! | [`AccountService::signup`] | ACC-01, 02, 12, 13 | `POST /v1/signup` |
//! | [`AccountService::resend_verification`] / [`AccountService::resend_own_verification`] | ACC-04 | `POST /v1/email/verification/resend`, `POST /v1/me/email/verification` |
//! | [`AccountService::verify_email_link`] / [`AccountService::verify_email_code`] / [`AccountService::verify_own_email_code`] | ACC-04 | `POST /v1/email/verify`, `POST /v1/me/email/verify` |
//! | [`AccountService::assess_login`] | ACC-05, 06, 11 | authn-session (login, SES-01/SES-22) |
//! | [`AccountService::change_status`] / [`AccountService::change_status_in_tx`] | ACC-06 | authn-admin (suspend, unlock…) |
//! | [`AccountService::request_email_change`], `confirm_*`, [`AccountService::revert_email_change`] | ACC-07 | `/v1/me/email*`, `/v1/email/change/*` |
//! | [`AccountService::profile`] / [`AccountService::update_profile`] | ACC-08 | `/v1/me/profile` |
//! | [`AccountService::request_deletion`], `cancel_*`, [`AccountService::purge_due_deletions`] | ACC-09 | `DELETE /v1/me`, `/v1/me/deletion*`, server job |
//! | [`AccountService::export_data`] | ACC-10 | `GET /v1/me/export` |
//! | [`AccountService::record_consent`], [`AccountService::terms_requirements`] | ACC-11 | `/v1/me/consents`, authn-session |
//! | [`AccountService::purge_unverified_accounts`] | ACC-05 | server job |
//!
//! Every state change runs in one transaction (ARC-06) that also carries
//! session revocation (`SessionRevoker`, caller's transaction), outbox
//! notifications (`Notifier::notify_in_tx`), domain events
//! (`EventPublisher`) and audit events (recorded right before `COMMIT`).

mod consent;
mod deletion;
mod email_change;
mod export;
mod login;
mod maintenance;
mod profile;
mod signup;
mod verification;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::account::AccountConfig;
use authn_core::domain::{EmailAddress, Locale, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OneTimeTokenId, UserId};
use authn_core::ports::{
    AuditSink, CaptchaVerifier, Clock, DataExporter, EventPublisher, Notifier, PasswordValidator,
    RateLimitKey, RateLimitPolicy, RateLimiter, Recipient, SecurityEvent, SecurityEventKind,
    SessionRevoker,
};
use authn_crypto::otp::{OtpCode, OtpHasher};
use authn_crypto::password::PasswordHasher;
use authn_crypto::token::OpaqueToken;
use authn_store::{
    NewOneTimeToken, OneTimeTokenRepository, TokenPurpose, TokenSubject, UserRecord, UserRepository,
};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use crate::background::BackgroundJobs;
use crate::disposable::DisposableDomains;
use crate::export::AccountDataExporter;
use crate::hooks::OrganizationOwnership;
use crate::repo::ProfileRepository;
use crate::tx::AccountTx;

pub use self::verification::VerificationProof;

/// Rate-limit action names (`RateLimitKey::action`).
pub mod actions {
    /// Registrations per IP (ACC-01).
    pub const REGISTER: &str = "account_register";
    /// Registrations per IP without CAPTCHA (ACC-13 risk-based policy).
    pub const REGISTER_CAPTCHA_FREE: &str = "account_register_captcha_free";
    /// "Someone tried to register" notices per address (ACC-02).
    pub const REGISTRATION_NOTICE: &str = "account_registration_notice";
    /// Verification e-mail cooldown per address (ACC-04).
    pub const VERIFICATION_COOLDOWN: &str = "account_verification_cooldown";
    /// Verification e-mails per address per hour (ACC-04).
    pub const VERIFICATION_HOURLY: &str = "account_verification_hourly";
    /// Unauthenticated resend requests per IP (ACC-04).
    pub const VERIFICATION_RESEND_IP: &str = "account_verification_resend";
    /// Unauthenticated verification attempts per IP (ACC-04).
    pub const VERIFY_IP: &str = "account_verify";
    /// Verification code submissions per address (ACC-04).
    pub const VERIFICATION_CODE: &str = "account_verification_code";
    /// E-mail change requests per user (ACC-07).
    pub const EMAIL_CHANGE: &str = "account_email_change";
    /// E-mail change code submissions per user (ACC-07).
    pub const EMAIL_CHANGE_CODE: &str = "account_email_change_code";
    /// Unauthenticated link actions per IP (ACC-07, ACC-09).
    pub const LINK_ACTION_IP: &str = "account_link_action";
    /// Data exports per user (ACC-10).
    pub const EXPORT: &str = "account_export";
}

/// Default minimum duration of a failed unauthenticated code submission
/// (see [`AccountServiceSettings::code_failure_floor`]).
pub const DEFAULT_CODE_FAILURE_FLOOR: Duration = Duration::from_millis(250);

/// Ports and infrastructure the service needs.
#[derive(Clone)]
pub struct AccountServiceDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Argon2id hashing (`CryptoServices::passwords`).
    pub hasher: PasswordHasher,
    /// Keyed hashing of verification codes (`CryptoServices::otp`).
    pub otp: OtpHasher,
    /// Rate limiter (authn-protect).
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// CAPTCHA verifier (authn-protect).
    pub captcha: Arc<dyn CaptchaVerifier>,
    /// Password policy (authn-password: `PasswordService::validator()`).
    pub password_validator: Arc<dyn PasswordValidator>,
    /// Notifications (authn-notify).
    pub notifier: Arc<dyn Notifier>,
    /// Security audit (authn-audit).
    pub audit: Arc<dyn AuditSink>,
    /// Domain events / webhooks (authn-audit).
    pub events: Arc<dyn EventPublisher>,
    /// Session revocation (authn-session).
    pub sessions: Arc<dyn SessionRevoker>,
    /// Data exporters of the other modules (ACC-10). This crate's own
    /// section (`account`) is always included.
    pub exporters: Vec<Arc<dyn DataExporter>>,
    /// Last-owner check (server, over authn-org).
    pub ownership: Arc<dyn OrganizationOwnership>,
}

/// Settings of the service.
#[derive(Debug, Clone)]
pub struct AccountServiceSettings {
    /// `[account]`.
    pub account: AccountConfig,
    /// Step-up window for sensitive operations (`session.step_up_max_age`,
    /// SES-13).
    pub step_up_max_age: Duration,
    /// Treat an unreachable CAPTCHA provider as passed
    /// (`protect.captcha.fail_open`).
    pub captcha_fail_open: bool,
    /// Minimum response time of a failed *unauthenticated* code
    /// submission, so that unknown addresses, wrong and locked-out codes
    /// cannot be told apart by timing (ACC-02). Default 250 ms.
    pub code_failure_floor: Duration,
    /// Loaded disposable-domain block list (ACC-12).
    pub disposable_domains: Option<Arc<DisposableDomains>>,
}

impl AccountServiceSettings {
    /// Settings from the application configuration; loads the
    /// disposable-domain list (fails fast when it cannot be read).
    pub fn from_app_config(config: &AppConfig) -> Result<Self, AuthError> {
        Ok(Self {
            account: config.account.clone(),
            step_up_max_age: config.session.step_up_max_age,
            captcha_fail_open: config.protect.captcha.fail_open,
            code_failure_floor: DEFAULT_CODE_FAILURE_FLOOR,
            disposable_domains: DisposableDomains::from_config(&config.account)?.map(Arc::new),
        })
    }
}

/// The account service. Cheap to clone; obtain it in handlers through
/// `FromRef` (see [`crate::router`]).
#[derive(Clone)]
pub struct AccountService {
    inner: Arc<Inner>,
}

struct Inner {
    deps: AccountServiceDeps,
    settings: AccountServiceSettings,
    jobs: BackgroundJobs,
    own_exporter: AccountDataExporter,
}

impl std::fmt::Debug for AccountService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountService")
            .field("exporters", &self.inner.deps.exporters.len())
            .field("background_jobs", &self.inner.jobs.pending())
            .finish_non_exhaustive()
    }
}

impl AccountService {
    /// Builds the service. Fails when two data exporters share a section
    /// name (or use the reserved `account` section) — an export must never
    /// silently drop data (ACC-10).
    pub fn new(
        deps: AccountServiceDeps,
        settings: AccountServiceSettings,
    ) -> Result<Self, AuthError> {
        let mut sections = HashSet::from([crate::export::ACCOUNT_SECTION]);
        for exporter in &deps.exporters {
            let section = exporter.section();
            if !crate::export::is_valid_section(section) || !sections.insert(section) {
                return Err(AuthError::internal(
                    "data exporter sections must be unique snake_case names",
                ));
            }
        }
        let own_exporter = AccountDataExporter::new(Arc::clone(&deps.clock));
        Ok(Self {
            inner: Arc::new(Inner {
                deps,
                settings,
                jobs: BackgroundJobs::new(),
                own_exporter,
            }),
        })
    }

    /// Waits until every background job started so far (registration,
    /// resend, e-mail change requests) has finished. Call on graceful
    /// shutdown (OPS-07); tests use it to observe the side effects.
    pub async fn drain_background_jobs(&self) {
        self.inner.jobs.drain().await;
    }

    /// The unverified-account login policy (ACC-05).
    #[must_use]
    pub fn unverified_login_policy(&self) -> authn_core::config::account::UnverifiedLoginPolicy {
        self.config().unverified_login
    }

    // --- shared helpers ---------------------------------------------------

    fn deps(&self) -> &AccountServiceDeps {
        &self.inner.deps
    }

    fn settings(&self) -> &AccountServiceSettings {
        &self.inner.settings
    }

    fn config(&self) -> &AccountConfig {
        &self.inner.settings.account
    }

    fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    async fn begin(&self) -> Result<AccountTx, AuthError> {
        AccountTx::begin(self.pool(), Arc::clone(&self.deps().audit)).await
    }

    /// Consumes one unit; `rate_limited` (429 + `Retry-After`) when denied.
    async fn limit(&self, key: &RateLimitKey, policy: RateLimitPolicy) -> Result<(), AuthError> {
        self.deps()
            .rate_limiter
            .check(key, policy, 1)
            .await?
            .into_result()
            .map(|_| ())
    }

    /// Consumes one unit and reports whether it was allowed (no error).
    async fn allowed(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<bool, AuthError> {
        Ok(self
            .deps()
            .rate_limiter
            .check(key, policy, 1)
            .await?
            .allowed)
    }

    fn event(&self, kind: SecurityEventKind, ctx: &RequestContext) -> SecurityEvent {
        SecurityEvent::new(kind, self.now()).with_context(ctx)
    }

    /// Self-service guard: a human user acting through a session (not an
    /// API key), not impersonated, not read-only.
    fn self_service_user(principal: &Principal) -> Result<UserId, AuthError> {
        let user = principal.require_user()?;
        if principal.is_impersonated() || principal.session_id().is_none() {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        principal.require_writable()?;
        Ok(user)
    }

    /// Step-up guard for sensitive operations (SES-13).
    fn require_step_up(&self, principal: &Principal) -> Result<(), AuthError> {
        principal.require_recent_authentication(self.now(), self.settings().step_up_max_age)
    }

    /// The principal's user row; `unauthenticated` when it no longer
    /// exists (deleted while the session was alive).
    async fn principal_user(&self, user: UserId) -> Result<UserRecord, AuthError> {
        UserRepository::find_by_id(self.pool(), user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))
    }

    /// Recipient + language for a notification to the account's current
    /// address; `None` when the stored address is unusable.
    async fn recipient(
        &self,
        conn: &mut PgConnection,
        user: &UserRecord,
        fallback: Locale,
    ) -> Result<Option<(Recipient, Locale)>, AuthError> {
        let Some(email) = stored_email(user) else {
            tracing::error!(user_id = %user.id, "stored e-mail address is unusable; notification skipped");
            return Ok(None);
        };
        Ok(Some(
            self.recipient_at(conn, user.id, email, fallback).await?,
        ))
    }

    /// Recipient + language for a notification to `email` on behalf of
    /// `user` (profile language and display name).
    async fn recipient_at(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        email: EmailAddress,
        fallback: Locale,
    ) -> Result<(Recipient, Locale), AuthError> {
        let profile = ProfileRepository::find(conn, user).await?;
        let locale = profile.as_ref().map_or(fallback, |p| p.locale);
        let recipient = Recipient {
            email,
            user_id: Some(user),
            display_name: profile.and_then(|p| p.display_name),
        };
        Ok((recipient, locale))
    }

    /// Recipient + language for a mail to an address whose owner has **not**
    /// proven to be the account holder (verification after registration,
    /// e-mail change verification to the new address). The display name is
    /// left out: it was chosen by whoever registered or requested the
    /// change, and anybody can make the service mail any address, so it
    /// would let them put their own text ("Hello <text>,", the `To:` name)
    /// into a genuine e-mail of the service.
    async fn unproven_recipient_at(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        email: EmailAddress,
        fallback: Locale,
    ) -> Result<(Recipient, Locale), AuthError> {
        let (mut recipient, locale) = self.recipient_at(conn, user, email, fallback).await?;
        recipient.display_name = None;
        Ok((recipient, locale))
    }

    /// Issues a link token and a 6-digit code in one group (ACC-04, ACC-07),
    /// revoking earlier tokens of the same purposes. Returns the secrets
    /// for the notification.
    async fn issue_link_and_code(
        &self,
        conn: &mut PgConnection,
        purposes: (TokenPurpose, TokenPurpose),
        user: UserId,
        target: &EmailAddress,
        created_ip: Option<std::net::IpAddr>,
    ) -> Result<IssuedSecrets, AuthError> {
        let now = self.now();
        let verification = &self.config().verification;
        let token = OpaqueToken::generate()?;
        let code = OtpCode::generate()?;
        let group = uuid::Uuid::now_v7();
        let link_expires_at = after(now, verification.link_ttl)?;
        let code_expires_at = after(now, verification.code_ttl)?;
        let (link_purpose, code_purpose) = purposes;
        OneTimeTokenRepository::create(
            conn,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: link_purpose,
                token_hash: token.hash(),
                subject: TokenSubject::user(user),
                group_id: Some(group),
                target: Some(target.as_str()),
                max_attempts: 1,
                metadata: serde_json::json!({}),
                created_ip,
                created_at: now,
                expires_at: link_expires_at,
            },
            true,
        )
        .await?;
        OneTimeTokenRepository::create(
            conn,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: code_purpose,
                token_hash: self.deps().otp.hash(code_purpose.as_str(), &code),
                subject: TokenSubject::user(user),
                group_id: Some(group),
                target: Some(target.as_str()),
                max_attempts: verification.code_max_attempts,
                metadata: serde_json::json!({}),
                created_ip,
                created_at: now,
                expires_at: code_expires_at,
            },
            true,
        )
        .await?;
        Ok(IssuedSecrets {
            token,
            code,
            link_expires_at,
        })
    }

    /// Issues a single link token (revert, deletion cancel).
    async fn issue_link(
        &self,
        conn: &mut PgConnection,
        link: LinkSpec<'_>,
        created_ip: Option<std::net::IpAddr>,
    ) -> Result<OpaqueToken, AuthError> {
        let token = OpaqueToken::generate()?;
        OneTimeTokenRepository::create(
            conn,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: link.purpose,
                token_hash: token.hash(),
                subject: TokenSubject::user(link.user),
                group_id: None,
                target: link.target,
                max_attempts: 1,
                metadata: serde_json::json!({}),
                created_ip,
                created_at: self.now(),
                expires_at: link.expires_at,
            },
            link.invalidate_previous,
        )
        .await?;
        Ok(token)
    }

    /// Revokes every outstanding token that was delivered to (or proves
    /// control of) an e-mail address of the user: when the address changes
    /// or a change is reverted, links and codes sent to the other address
    /// must stop working (ACC-07). Revocation only ever *removes* access, so
    /// it is applied to the purposes of other modules too (see the change
    /// request log). Revert links are handled separately (a revert ends
    /// only the revert links of later changes).
    async fn revoke_address_bound_tokens(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<u64, AuthError> {
        Ok(OneTimeTokenRepository::revoke_for_user(
            conn,
            user,
            crate::ADDRESS_BOUND_PURPOSES,
            self.now(),
        )
        .await?)
    }
}

/// A single link token to issue.
struct LinkSpec<'a> {
    purpose: TokenPurpose,
    user: UserId,
    target: Option<&'a str>,
    expires_at: OffsetDateTime,
    /// Revoke earlier active links of the same purpose.
    invalidate_previous: bool,
}

/// Secrets of a freshly issued link + code pair.
struct IssuedSecrets {
    token: OpaqueToken,
    code: OtpCode,
    link_expires_at: OffsetDateTime,
}

/// The stored address as a validated value (`None` if unusable / absent).
fn stored_email(user: &UserRecord) -> Option<EmailAddress> {
    user.email
        .as_deref()
        .and_then(|e| EmailAddress::parse(e).ok())
}

/// `now + ttl` without overflow panics.
fn after(now: OffsetDateTime, ttl: Duration) -> Result<OffsetDateTime, AuthError> {
    time::Duration::try_from(ttl)
        .ok()
        .and_then(|d| now.checked_add(d))
        .ok_or_else(|| AuthError::internal("expiry out of range"))
}

/// Parses user input into an address (`invalid_email`).
fn parse_email(raw: &str) -> Result<EmailAddress, AuthError> {
    EmailAddress::parse(raw).map_err(|e| {
        AuthError::new(codes::account::INVALID_EMAIL)
            .with_details(serde_json::json!({ "reason": email_error_reason(e) }))
    })
}

fn email_error_reason(err: authn_core::domain::EmailError) -> &'static str {
    use authn_core::domain::EmailError;
    match err {
        EmailError::Empty => "empty",
        EmailError::TooLong => "too_long",
        EmailError::InvalidAtSign => "at_sign",
        EmailError::InvalidLocalPart => "local_part",
        EmailError::InvalidDomain => "domain",
    }
}
