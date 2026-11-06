//! The provider service: client registry, authorization, tokens and the
//! resource endpoints.

mod authorize;
mod clients;
mod resource;
mod token;

use std::sync::Arc;
use std::time::Duration;

use authn_account::AccountService;
use authn_core::error::AuthError;
use authn_core::ports::{AuditSink, Clock, RateLimitKey, RateLimitPolicy, RateLimiter};
use authn_crypto::envelope::EnvelopeCipher;
use sqlx::PgPool;
use time::OffsetDateTime;

pub use authorize::{
    AuthorizeOutcome, ClientSummary, ConsentView, InteractionView, RedirectTarget,
};
pub use clients::{ClientInput, ClientPatch, ClientView, CreatedClient};
pub use resource::{IntrospectionResponse, UserInfo};
pub use token::{ClientCredentials, TokenResponse};

use crate::hooks::{ClientAdminAuthorizer, SessionLiveness};
use crate::keys::KeyCache;
use crate::settings::OidcProviderSettings;

/// Everything the provider needs.
#[derive(Clone)]
pub struct OidcProviderDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Clock.
    pub clock: Arc<dyn Clock>,
    /// Audit sink.
    pub audit: Arc<dyn AuditSink>,
    /// Rate limiter.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Envelope cipher (opens the signing key).
    pub envelopes: EnvelopeCipher,
    /// Accounts (UserInfo claims).
    pub accounts: AccountService,
    /// Session liveness (server adapter over authn-session).
    pub liveness: Arc<dyn SessionLiveness>,
    /// Client registry authorization (server adapter over authn-admin).
    pub client_admin: Arc<dyn ClientAdminAuthorizer>,
}

struct Inner {
    deps: OidcProviderDeps,
    settings: OidcProviderSettings,
    keys: KeyCache,
}

/// The OAuth 2.1 / OIDC provider. Cheap to clone.
#[derive(Clone)]
pub struct OidcProviderService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for OidcProviderService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcProviderService")
            .field("issuer", &self.inner.settings.issuer)
            .finish_non_exhaustive()
    }
}

/// Adds `duration` to `t`, saturating.
pub(crate) fn after(t: OffsetDateTime, duration: Duration) -> OffsetDateTime {
    time::Duration::try_from(duration)
        .ok()
        .and_then(|d| t.checked_add(d))
        .unwrap_or(t)
}

impl OidcProviderService {
    /// Builds the service.
    #[must_use]
    pub fn new(deps: OidcProviderDeps, settings: OidcProviderSettings) -> Self {
        let keys = KeyCache::new(
            deps.pool.clone(),
            deps.envelopes.clone(),
            deps.clock.clone(),
        );
        Self {
            inner: Arc::new(Inner {
                deps,
                settings,
                keys,
            }),
        }
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &OidcProviderSettings {
        &self.inner.settings
    }

    pub(crate) fn deps(&self) -> &OidcProviderDeps {
        &self.inner.deps
    }

    pub(crate) fn keys(&self) -> &KeyCache {
        &self.inner.keys
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    /// The current time.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    /// Drops the cached signing keys (after an in-process emergency
    /// rotation, ADM-06).
    pub fn invalidate_signing_keys(&self) {
        self.inner.keys.invalidate();
    }

    /// Consumes one unit of `policy` for `key`; `429 rate_limited` with
    /// `Retry-After` when exhausted.
    pub(crate) async fn limit(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<(), AuthError> {
        self.inner
            .deps
            .rate_limiter
            .check(key, policy, 1)
            .await?
            .into_result()
            .map(|_| ())
    }

    /// Deletes expired interactions and access-token records and grants
    /// that expired or were revoked more than a day ago (their codes and
    /// refresh tokens cascade). Background job (OPS-06; `SKIP LOCKED`, safe
    /// on many instances). Returns the number of deleted rows.
    pub async fn purge_expired(&self, limit: i64) -> Result<u64, AuthError> {
        let now = self.now();
        let retention_before = now - time::Duration::days(1);
        let mut conn = self.pool().acquire().await?;
        Ok(crate::store::purge_expired(&mut conn, now, retention_before, limit).await?)
    }
}
