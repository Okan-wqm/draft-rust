//! [`SessionService`]: the session core of authn-session.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | `establish` | SES-03, SES-05, SES-06, SES-07, SES-14 | [`SessionService::establish`] — creating sessions and their credentials |
//! | `authenticate` | SES-03, SES-04, SES-05, SES-08 | cookie / bearer resolution into a `Principal` |
//! | `tokens` | SES-05, SES-08, SES-09 | access-token issuance and verification, JWKS |
//! | `refresh` | SES-05, SES-06 | refresh rotation, reuse detection, grace window |
//! | `revoke` | SES-12, SES-15 | [`PgSessionRevoker`] (port) |
//! | `manage` | SES-11, SES-12, SES-16 | session list, logout, `GET /v1/me` |
//! | `org_switch` | SES-17 | active organization switch |
//! | `step_up` | SES-13 | re-authentication |
//! | `introspect` | SES-10 | RFC 7662 introspection |
//! | `challenge` | SES-02, SES-22 (API for the login flows) | pending login state |
//! | `issuer` | SES-15, ADM-04 | `SessionIssuer` port, impersonation, post-primary pipeline |
//! | `maintenance` | OPS-06 | cleanup job |

mod authenticate;
mod challenge;
mod establish;
mod introspect;
mod issuer;
mod maintenance;
mod manage;
mod org_switch;
mod refresh;
mod revoke;
mod step_up;
mod tokens;

use std::sync::Arc;

use authn_account::AccountService;
use authn_core::error::AuthError;
use authn_core::ports::{AuditSink, Clock, EventPublisher, Notifier, RateLimiter, RiskEvaluator};
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::kdf::KeyRing;
use authn_crypto::otp::OtpHasher;
use authn_mfa::MfaService;
use authn_org::OrgService;
use authn_password::PasswordService;
use authn_protect::LoginProtection;
use authn_protect::risk::RiskAlerts;
use authn_store::PgTx;
use authn_webauthn::WebauthnService;
use sqlx::PgPool;
use time::OffsetDateTime;

pub use self::authenticate::{Authenticated, is_session_active_in};
pub use self::challenge::{
    CHALLENGE_LOCK_TIMEOUT, ChallengeKind, ChallengeProgress, ChallengeState, IssuedChallenge,
    NewChallenge,
};
pub use self::establish::{ClientChannel, EstablishSession, VerifiedOrg};
pub(crate) use self::establish::{normalize_amr, record_second_factor};
pub use self::introspect::IntrospectionResponse;
pub use self::issuer::org_mfa_policy;
pub(crate) use self::issuer::{primary_amr, strictest_membership_policy};
pub use self::maintenance::PurgeReport;
pub use self::manage::{MeResponse, SessionSummary};
pub use self::org_switch::OrgSwitch;
pub(crate) use self::org_switch::has_passkey;
pub use self::refresh::RefreshedTokens;
pub use self::revoke::PgSessionRevoker;
pub use self::step_up::{PasskeyStepUpStart, StepUpProof};
pub use self::tokens::VerifiedAccessToken;
use crate::csrf::CsrfProtector;
use crate::keys::KeyCache;
use crate::settings::SessionSettings;

/// Everything the service needs. The wave-A services are the real ones
/// (step-up factors, organization policy, profile, trusted devices).
#[derive(Clone)]
pub struct SessionServiceDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Purpose sub-keys (`CryptoServices::keys`): CSRF tokens (CRY-11).
    pub keys: KeyRing,
    /// Envelope encryption (`CryptoServices::envelopes`): signing keys and
    /// the grace-window successor of refresh tokens.
    pub envelopes: EnvelopeCipher,
    /// Rate limiter (authn-protect).
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Security audit (authn-audit).
    pub audit: Arc<dyn AuditSink>,
    /// Domain events / webhooks (authn-audit).
    pub events: Arc<dyn EventPublisher>,
    /// Notifications (authn-notify): impersonation notice (ADM-04).
    pub notifier: Arc<dyn Notifier>,
    /// Password verification for step-up (authn-password).
    pub passwords: PasswordService,
    /// Second factors, MFA policy and trusted devices (authn-mfa).
    pub mfa: MfaService,
    /// Passkeys for step-up (authn-webauthn).
    pub webauthn: WebauthnService,
    /// Memberships, organization policies, API keys (authn-org).
    pub orgs: OrgService,
    /// Profiles, login assessment, e-mail-change consequences of bulk
    /// revocations (authn-account).
    pub accounts: AccountService,
    /// Login throttling, CAPTCHA escalation and soft lock (authn-protect,
    /// PRT-02 … PRT-05) for the password login (SES-01).
    pub protection: LoginProtection,
    /// Login risk evaluation (authn-protect, RSK-01 … RSK-03).
    pub risk: Arc<dyn RiskEvaluator>,
    /// New-device notification and blocked-login notice (RSK-03, RSK-04).
    pub risk_alerts: RiskAlerts,
    /// Keyed hash of the e-mailed login codes (CRY-07, SES-19).
    pub otp: OtpHasher,
}

struct Inner {
    deps: SessionServiceDeps,
    settings: SessionSettings,
    keys: KeyCache,
    csrf: CsrfProtector,
    revoker: PgSessionRevoker,
    /// Passwordless requests processed after the uniform answer was sent
    /// (SES-18, SES-19: no timing difference between existing and unknown
    /// addresses).
    jobs: tokio::sync::Mutex<tokio::task::JoinSet<()>>,
}

/// The session service. Cheap to clone (`FromRef<AppState>`).
#[derive(Clone)]
pub struct SessionService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SessionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionService")
            .field("issuer", &self.inner.settings.issuer)
            .finish_non_exhaustive()
    }
}

impl SessionService {
    /// Builds the service. Fails when the settings are unusable (no
    /// audience, empty issuer).
    pub fn new(deps: SessionServiceDeps, settings: SessionSettings) -> Result<Self, AuthError> {
        if settings.issuer.is_empty() || settings.own_audience().is_empty() {
            return Err(AuthError::internal(
                "session issuer and audience must not be empty",
            ));
        }
        let keys = KeyCache::new(
            deps.pool.clone(),
            deps.envelopes.clone(),
            deps.clock.clone(),
            settings.session.signing_key_cache_ttl,
        );
        let csrf = CsrfProtector::new(deps.keys.clone(), settings.allowed_origins.clone());
        let revoker = PgSessionRevoker::new(
            deps.clock.clone(),
            deps.audit.clone(),
            deps.events.clone(),
            deps.mfa.clone(),
        );
        Ok(Self {
            inner: Arc::new(Inner {
                deps,
                settings,
                keys,
                csrf,
                revoker,
                jobs: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
            }),
        })
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &SessionSettings {
        &self.inner.settings
    }

    /// The current time from the injected clock.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    /// The database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    /// Begins a transaction (ARC-06).
    pub async fn begin(&self) -> Result<PgTx, AuthError> {
        authn_store::begin(self.pool()).await
    }

    /// CSRF tokens and origin checks (SES-04).
    #[must_use]
    pub fn csrf(&self) -> &CsrfProtector {
        &self.inner.csrf
    }

    /// The revoker used by this service (the same implementation the
    /// server exposes as the `SessionRevoker` port).
    #[must_use]
    pub fn revoker(&self) -> PgSessionRevoker {
        self.inner.revoker.clone()
    }

    /// Drops the cached signing keys (next use reloads them). Call after
    /// an in-process emergency key rotation. Other instances learn about
    /// the rotation from [`Self::run_signing_key_listener`].
    pub fn invalidate_signing_keys(&self) {
        self.inner.keys.invalidate();
    }

    /// K-58: listens for signing-key changes (PostgreSQL `LISTEN` on
    /// [`crate::SIGNING_KEYS_CHANNEL`], sent by a trigger on every change
    /// of `signing_keys` — from this instance, another instance or the CLI)
    /// and drops this instance's signing-key cache at once, so an
    /// emergency-revoked key stops verifying everywhere within the
    /// notification latency. Runs until `shutdown` completes; reconnects
    /// with backoff (1 s … 30 s); drops the cache on every (re)connection,
    /// and while disconnected the cache lifetime shrinks to 5 s. Uses one
    /// dedicated database connection of its own (not one of the pool's).
    ///
    /// The server spawns it once per process at startup, e.g.
    /// `tokio::spawn(async move { sessions.run_signing_key_listener(token.cancelled_owned()).await })`.
    pub async fn run_signing_key_listener<S>(&self, shutdown: S)
    where
        S: std::future::Future<Output = ()> + Send,
    {
        self.inner.keys.run_listener(shutdown).await;
    }

    /// Whether [`Self::run_signing_key_listener`] runs and is connected
    /// (readiness / diagnostics).
    #[must_use]
    pub fn signing_key_listener_connected(&self) -> bool {
        self.inner.keys.listener_connected()
    }

    /// Waits for the background work of passwordless requests (tests,
    /// graceful shutdown).
    pub async fn drain_background_jobs(&self) {
        let mut jobs = self.inner.jobs.lock().await;
        while jobs.join_next().await.is_some() {}
    }

    /// Runs `job` in the background (bounded: a full backlog drops it).
    pub(crate) async fn spawn_job<F>(&self, job: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut jobs = self.inner.jobs.lock().await;
        while jobs.try_join_next().is_some() {}
        if jobs.len() >= MAX_PENDING_JOBS {
            return false;
        }
        jobs.spawn(job);
        true
    }

    pub(crate) fn deps(&self) -> &SessionServiceDeps {
        &self.inner.deps
    }

    pub(crate) fn key_cache(&self) -> &KeyCache {
        &self.inner.keys
    }

    pub(crate) fn pg_revoker(&self) -> &PgSessionRevoker {
        &self.inner.revoker
    }
}

/// Largest number of queued passwordless background jobs.
const MAX_PENDING_JOBS: usize = 1024;

/// `now + duration`, saturating at the far future.
pub(crate) fn after(now: OffsetDateTime, duration: std::time::Duration) -> OffsetDateTime {
    time::Duration::try_from(duration)
        .ok()
        .and_then(|d| now.checked_add(d))
        .unwrap_or(time::macros::datetime!(9999-12-31 0:00 UTC))
}

/// The positive remaining time from `now` until `until` (zero if past).
pub(crate) fn remaining(now: OffsetDateTime, until: OffsetDateTime) -> std::time::Duration {
    let diff = until - now;
    if diff.is_negative() {
        std::time::Duration::ZERO
    } else {
        diff.unsigned_abs()
    }
}

/// [`remaining`] in whole seconds.
pub(crate) fn remaining_secs(now: OffsetDateTime, until: OffsetDateTime) -> u64 {
    remaining(now, until).as_secs()
}
