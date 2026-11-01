//! [`PasswordService`]: every password use case of the system.
//!
//! | Method | Requirement | Caller |
//! |--------|-------------|--------|
//! | [`PasswordService::check_password`] | PWD-01…05 | `POST /v1/password/check` |
//! | [`PasswordService::verify_login_password`] | CRY-03/04/05, PWD-12 | authn-session (login, step-up) |
//! | [`PasswordService::request_reset`] | PWD-07, PWD-08 | `POST /v1/password/forgot` |
//! | [`PasswordService::complete_reset`] | PWD-08, PWD-09 | `POST /v1/password/reset` |
//! | [`PasswordService::change_password`] | PWD-06 | `POST /v1/me/password/change` |
//! | [`PasswordService::add_password`] | PWD-10 | `POST /v1/me/password` |
//! | [`PasswordService::remove_password`] | PWD-11 | `DELETE /v1/me/password` |
//! | [`PasswordService::apply_required_password_change`] | PWD-12, SES-22 | authn-session (required action) |
//! | [`PasswordService::set_must_change_password`] | PWD-12, ADM-03 | authn-admin |
//!
//! Every state change runs in one database transaction (ARC-06) that also
//! carries the session revocation ([`SessionRevoker`], caller's
//! transaction), the notification (`Notifier::notify_in_tx`) and the audit
//! event (`AuditSink::record_in_tx`, last statement before `COMMIT`).

mod login;
mod manage;
mod reset;

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::password::PasswordConfig;
use authn_core::domain::{EmailAddress, Locale, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    AuditSink, BreachedPasswordChecker, Clock, Notification, NotificationKind, Notifier,
    PasswordCheck, PasswordContext, PasswordValidator, RateLimitKey, RateLimitPolicy, RateLimiter,
    Recipient, SecurityEvent, SecurityEventKind, SessionRevoker,
};
use authn_core::redact::mask_ip;
use authn_core::secret::SecretString;
use authn_crypto::otp::OtpHasher;
use authn_crypto::password::{PasswordHasher, StoredPasswordHash};
use authn_store::{PasswordCredentialRecord, UserRecord};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

pub use self::login::LoginPasswordOutcome;
pub use self::reset::ResetProof;
use crate::hooks::{LoginMethodInventory, ProfileHints, ProfileLookup};
use crate::policy::PasswordPolicy;

/// Rate-limit action names (`RateLimitKey::action`).
pub mod actions {
    /// Live strength check, per IP (PWD-05).
    pub const CHECK: &str = "password_check";
    /// Reset request, per IP and per e-mail (PWD-07).
    pub const RESET_REQUEST: &str = "password_reset_request";
    /// Reset completion (link or code), per IP (PWD-08).
    pub const RESET_VERIFY: &str = "password_reset_verify";
    /// Reset-code submissions, per e-mail (PWD-08).
    pub const RESET_CODE: &str = "password_reset_code";
    /// Current-password verification on change, per user (PWD-06).
    pub const CHANGE: &str = "password_change";
}

/// Concurrent background reset-request jobs (PWD-07); further jobs wait.
const MAX_CONCURRENT_RESET_JOBS: usize = 16;
/// Queued background reset-request jobs before new ones are dropped (memory
/// bound under a distributed flood; the caller still gets the same `202`).
const MAX_PENDING_RESET_JOBS: usize = 4096;
/// Default minimum duration of a failed reset-code submission (see
/// [`PasswordServiceSettings::code_failure_floor`]).
pub const DEFAULT_CODE_FAILURE_FLOOR: Duration = Duration::from_millis(250);
/// Longest device description put into notifications.
const MAX_DEVICE_CHARS: usize = 128;

/// Ports and infrastructure the service needs.
#[derive(Clone)]
pub struct PasswordServiceDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Argon2id hashing service (`CryptoServices::passwords`).
    pub hasher: PasswordHasher,
    /// Keyed hashing of reset codes (`CryptoServices::otp`).
    pub otp: OtpHasher,
    /// Rate limiter (authn-protect).
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Notifications (authn-notify).
    pub notifier: Arc<dyn Notifier>,
    /// Security audit (authn-audit).
    pub audit: Arc<dyn AuditSink>,
    /// Session revocation (authn-session).
    pub sessions: Arc<dyn SessionRevoker>,
    /// Breach lookup (normally [`crate::HibpBreachChecker`]).
    pub breach_checker: Arc<dyn BreachedPasswordChecker>,
    /// The user's other sign-in methods (PWD-11; implemented by the server).
    pub login_methods: Arc<dyn LoginMethodInventory>,
    /// Profile hints (implemented by the server over authn-account).
    pub profiles: Arc<dyn ProfileLookup>,
}

/// Settings of the service.
#[derive(Debug, Clone)]
pub struct PasswordServiceSettings {
    /// `[password]`.
    pub password: PasswordConfig,
    /// Step-up window for sensitive operations (`session.step_up_max_age`,
    /// SES-13).
    pub step_up_max_age: Duration,
    /// Minimum response time of a *failed* reset-code submission: unknown
    /// addresses, missing, wrong and locked-out codes all answer
    /// `invalid_code` no sooner than this after the request started, so the
    /// different amount of database work cannot reveal whether an account
    /// exists (PWD-07). Default 250 ms.
    pub code_failure_floor: Duration,
}

impl PasswordServiceSettings {
    /// Settings from the application configuration.
    #[must_use]
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            password: config.password.clone(),
            step_up_max_age: config.session.step_up_max_age,
            code_failure_floor: DEFAULT_CODE_FAILURE_FLOOR,
        }
    }
}

/// The password service. Cheap to clone; obtain it in handlers through
/// `FromRef` (see [`crate::router`]).
#[derive(Clone)]
pub struct PasswordService {
    inner: Arc<Inner>,
}

struct Inner {
    deps: PasswordServiceDeps,
    settings: PasswordServiceSettings,
    policy: PasswordPolicy,
    jobs: TaskTracker,
    job_permits: Arc<Semaphore>,
}

impl std::fmt::Debug for PasswordService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordService")
            .field("policy", &self.inner.policy)
            .field("background_jobs", &self.inner.jobs.len())
            .finish_non_exhaustive()
    }
}

impl PasswordService {
    /// Builds the service.
    #[must_use]
    pub fn new(deps: PasswordServiceDeps, settings: PasswordServiceSettings) -> Self {
        let policy = PasswordPolicy::from_config(&settings.password, deps.breach_checker.clone());
        Self {
            inner: Arc::new(Inner {
                deps,
                settings,
                policy,
                jobs: TaskTracker::new(),
                job_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RESET_JOBS)),
            }),
        }
    }

    /// The password policy (PWD-01…04).
    #[must_use]
    pub fn policy(&self) -> &PasswordPolicy {
        &self.inner.policy
    }

    /// The policy as the [`PasswordValidator`] port (for authn-account's
    /// registration, ACC-01, and authn-admin).
    #[must_use]
    pub fn validator(&self) -> Arc<dyn PasswordValidator> {
        Arc::new(self.inner.policy.clone())
    }

    /// Waits until every background job started so far (reset requests,
    /// PWD-07) has finished. Call on graceful shutdown (OPS-07); tests use
    /// it to observe the side effects of `request_reset`.
    pub async fn drain_background_jobs(&self) {
        let jobs = &self.inner.jobs;
        jobs.close();
        jobs.wait().await;
        jobs.reopen();
    }

    /// Live policy check (PWD-05): rate limited per IP; nothing about the
    /// password is logged or stored.
    pub async fn check_password(
        &self,
        ctx: &RequestContext,
        password: &SecretString,
        email: Option<EmailAddress>,
        display_name: Option<String>,
    ) -> Result<PasswordCheck, AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::CHECK, ctx.client_ip),
            self.config().check_endpoint_per_ip,
        )
        .await?;
        let context = PasswordContext {
            email,
            display_name,
            locale: ctx.locale,
        };
        self.inner.policy.evaluate(password, &context).await
    }

    // --- shared helpers ---------------------------------------------------

    fn deps(&self) -> &PasswordServiceDeps {
        &self.inner.deps
    }

    fn config(&self) -> &PasswordConfig {
        &self.inner.settings.password
    }

    fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    async fn limit(&self, key: &RateLimitKey, policy: RateLimitPolicy) -> Result<(), AuthError> {
        self.deps()
            .rate_limiter
            .check(key, policy, 1)
            .await?
            .into_result()
            .map(|_| ())
    }

    fn event(&self, kind: SecurityEventKind, ctx: &RequestContext) -> SecurityEvent {
        SecurityEvent::new(kind, self.now()).with_context(ctx)
    }

    /// Profile hints; lookup failures degrade to defaults (they must never
    /// block a password operation).
    async fn profile(&self, user: UserId) -> ProfileHints {
        match self.deps().profiles.profile(user).await {
            Ok(hints) => hints,
            Err(err) => {
                tracing::warn!(error = %err, "profile lookup failed; using defaults");
                ProfileHints::default()
            }
        }
    }

    /// The policy context of an existing user (PWD-04 user inputs).
    fn password_context(
        user: &UserRecord,
        hints: &ProfileHints,
        locale: Locale,
    ) -> PasswordContext {
        PasswordContext {
            email: user
                .email
                .as_deref()
                .and_then(|e| EmailAddress::parse(e).ok()),
            display_name: hints.display_name.clone(),
            locale,
        }
    }

    /// The recipient of a notification to `user`, if the stored address is
    /// usable.
    fn recipient(user: &UserRecord, hints: &ProfileHints) -> Option<Recipient> {
        let email = user
            .email
            .as_deref()
            .and_then(|e| EmailAddress::parse(e).ok());
        if email.is_none() {
            tracing::error!(user_id = %user.id, "stored e-mail address is unusable; notification skipped");
        }
        email.map(|email| Recipient {
            email,
            user_id: Some(user.id),
            display_name: hints.display_name.clone(),
        })
    }

    /// Enqueues the "password changed" notice (PWD-06, PWD-09, PWD-10,
    /// PWD-11) in the caller's transaction.
    async fn notify_password_changed(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: &UserRecord,
        hints: &ProfileHints,
        at: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let Some(recipient) = Self::recipient(user, hints) else {
            return Ok(());
        };
        let device = ctx
            .user_agent
            .as_deref()
            .map(|ua| ua.chars().take(MAX_DEVICE_CHARS).collect::<String>());
        let notification = Notification {
            recipient,
            locale: hints.locale.unwrap_or(ctx.locale),
            kind: NotificationKind::PasswordChanged {
                at,
                ip_masked: Some(mask_ip(ctx.client_ip)),
                device,
            },
        };
        self.deps().notifier.notify_in_tx(conn, notification).await
    }

    /// Self-service guard: a human user, not impersonated, authenticated
    /// with a session (not an API key).
    fn self_service_user(principal: &Principal) -> Result<UserId, AuthError> {
        let user = principal.require_user()?;
        if principal.is_impersonated() || principal.session_id().is_none() {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        principal.require_writable()?;
        Ok(user)
    }
}

/// `now + ttl` without overflow panics.
fn after(now: OffsetDateTime, ttl: Duration) -> Result<OffsetDateTime, AuthError> {
    time::Duration::try_from(ttl)
        .ok()
        .and_then(|d| now.checked_add(d))
        .ok_or_else(|| AuthError::internal("expiry out of range"))
}

/// The stored hash in the form `authn-crypto` verifies.
fn stored_hash(credential: &PasswordCredentialRecord) -> StoredPasswordHash {
    StoredPasswordHash::new(
        &credential.password_hash,
        &credential.algorithm,
        credential.pepper_version,
    )
}
