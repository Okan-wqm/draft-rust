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
use authn_core::ports::{AuditSink, Clock, EventPublisher, Notifier, RateLimiter};
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::kdf::KeyRing;
use authn_mfa::MfaService;
use authn_org::OrgService;
use authn_password::PasswordService;
use authn_store::PgTx;
use authn_webauthn::WebauthnService;
use sqlx::PgPool;
use time::OffsetDateTime;

pub use self::authenticate::Authenticated;
pub use self::challenge::{
    CHALLENGE_LOCK_TIMEOUT, ChallengeKind, ChallengeProgress, ChallengeState, IssuedChallenge,
    NewChallenge,
};
pub use self::establish::{ClientChannel, EstablishSession, VerifiedOrg};
pub use self::introspect::IntrospectionResponse;
pub use self::issuer::org_mfa_policy;
pub use self::maintenance::PurgeReport;
pub use self::manage::{MeResponse, SessionSummary};
pub use self::org_switch::OrgSwitch;
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
}

struct Inner {
    deps: SessionServiceDeps,
    settings: SessionSettings,
    keys: KeyCache,
    csrf: CsrfProtector,
    revoker: PgSessionRevoker,
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
    /// an in-process emergency key rotation.
    pub fn invalidate_signing_keys(&self) {
        self.inner.keys.invalidate();
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
