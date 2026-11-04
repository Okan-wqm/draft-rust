//! Settings of the social-login service, derived once from [`AppConfig`].

use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::oidc_client::OidcClientConfig;
use authn_core::ports::RateLimitPolicy;
use url::Url;

/// Shortest gap between two JWKS downloads forced by an unknown `kid`
/// (SOC-03): a flood of tokens with random `kid` values cannot turn into a
/// flood of requests to the provider.
pub const DEFAULT_JWKS_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Lifetime of a generated Apple `client_secret` JWT (SOC-07). Apple accepts
/// up to six months; a short lifetime limits the value of a leaked secret.
pub const DEFAULT_APPLE_CLIENT_SECRET_TTL: Duration = Duration::from_secs(3600);

/// Everything the service reads from the configuration.
///
/// The fields after `step_up_max_age` have no configuration key yet (a
/// contract change request asks for them in `[oidc_client]`); their
/// defaults are the documented values and the server may override them.
#[derive(Debug, Clone)]
pub struct OidcClientSettings {
    /// `[oidc_client]`.
    pub config: OidcClientConfig,
    /// `server.public_base_url`: callback URLs (`redirect_uri`) and relative
    /// `return_to` targets are built from it, never from the `Host` header.
    pub public_base_url: Url,
    /// Exact absolute `return_to` targets: `protect.redirect_allow_list` plus
    /// `oidc_client.allowed_return_to` (PRT-10, SOC-02).
    pub redirect_allow_list: Vec<String>,
    /// Clock-skew tolerance for `exp` / `iat` / `nbf` (`crypto.jwt_leeway`).
    pub jwt_leeway: Duration,
    /// Step-up window for linking and unlinking (`session.step_up_max_age`,
    /// SES-13, SOC-06).
    pub step_up_max_age: Duration,
    /// Microsoft tenant allow-list (`tid`); empty = every tenant admitted by
    /// `oidc_client.microsoft.tenant` (SOC-03).
    pub microsoft_allowed_tenants: Vec<String>,
    /// Web flow starts per client IP (default 60 / 10 min).
    pub start_per_ip: RateLimitPolicy,
    /// Native nonces and native logins per client IP (default 60 / 10 min).
    pub native_per_ip: RateLimitPolicy,
    /// Web callbacks per client IP (default 60 / 10 min): checked before
    /// the state lookup, so anonymous callers cannot run unlimited database
    /// work or grow the audit chain with made-up `state` values.
    pub callback_per_ip: RateLimitPolicy,
    /// Minimum gap between forced JWKS refreshes (default 60 s).
    pub jwks_refresh_min_interval: Duration,
    /// Lifetime of the Apple `client_secret` JWT (default 1 h; it is
    /// regenerated when less than a quarter of it is left).
    pub apple_client_secret_ttl: Duration,
}

impl OidcClientSettings {
    /// Settings from a validated configuration.
    #[must_use]
    pub fn from_app_config(config: &AppConfig) -> Self {
        let mut redirect_allow_list = config.protect.redirect_allow_list.clone();
        for entry in &config.oidc_client.allowed_return_to {
            if !redirect_allow_list.contains(entry) {
                redirect_allow_list.push(entry.clone());
            }
        }
        Self {
            config: config.oidc_client.clone(),
            public_base_url: config.server.public_base_url.clone(),
            redirect_allow_list,
            jwt_leeway: config.crypto.jwt_leeway,
            step_up_max_age: config.session.step_up_max_age,
            microsoft_allowed_tenants: Vec::new(),
            start_per_ip: RateLimitPolicy::new(60, Duration::from_secs(600)),
            native_per_ip: RateLimitPolicy::new(60, Duration::from_secs(600)),
            callback_per_ip: RateLimitPolicy::new(60, Duration::from_secs(600)),
            jwks_refresh_min_interval: DEFAULT_JWKS_REFRESH_MIN_INTERVAL,
            apple_client_secret_ttl: DEFAULT_APPLE_CLIENT_SECRET_TTL,
        }
    }
}
