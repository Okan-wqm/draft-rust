//! Settings of the provider, derived once from [`AppConfig`] (OIDP-13).

use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::oidc_provider::STANDARD_SCOPES;
use authn_core::error::AuthError;
use authn_core::ports::RateLimitPolicy;
use url::Url;

/// Path of the authorization endpoint.
pub const AUTHORIZE_PATH: &str = "/v1/oauth2/authorize";
/// Path of the token endpoint.
pub const TOKEN_PATH: &str = "/v1/oauth2/token";
/// Path of the UserInfo endpoint.
pub const USERINFO_PATH: &str = "/v1/oauth2/userinfo";
/// Path of the revocation endpoint (RFC 7009).
pub const REVOCATION_PATH: &str = "/v1/oauth2/revoke";
/// Path of the introspection endpoint (RFC 7662).
pub const INTROSPECTION_PATH: &str = "/v1/oauth2/introspect";
/// Path of the JWKS (served by authn-session, SES-09).
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Everything the provider reads from the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProviderSettings {
    /// Whether the endpoints are mounted.
    pub enabled: bool,
    /// `iss` / discovery `issuer`.
    pub issuer: String,
    /// `server.public_base_url` without trailing slash (endpoint URLs).
    pub base_url: String,
    /// The login / consent page (`None` only while disabled).
    pub interaction_url: Option<Url>,
    /// Pending authorization request lifetime.
    pub authorization_request_ttl: Duration,
    /// Authorization code lifetime.
    pub authorization_code_ttl: Duration,
    /// Access token lifetime.
    pub access_token_ttl: Duration,
    /// ID token lifetime.
    pub id_token_ttl: Duration,
    /// Refresh token idle lifetime.
    pub refresh_token_idle_ttl: Duration,
    /// Grant absolute lifetime.
    pub refresh_token_absolute_ttl: Duration,
    /// Every scope a client may be registered for.
    pub supported_scopes: Vec<String>,
    /// Audiences of the native (first-party) access tokens
    /// (`session.audiences`): never used as a provider token audience
    /// (token-type confusion, OIDP-08).
    pub reserved_audiences: Vec<String>,
    /// JWT clock-skew tolerance (`crypto.jwt_leeway`).
    pub jwt_leeway: Duration,
    /// Per-IP limit of the authorization endpoint.
    pub authorize_per_ip: RateLimitPolicy,
    /// Per-IP limit of the token-family endpoints.
    pub token_per_ip: RateLimitPolicy,
    /// Per-client limit of the token-family endpoints.
    pub token_per_client: RateLimitPolicy,
    /// Per-IP limit of `userinfo`.
    pub userinfo_per_ip: RateLimitPolicy,
    /// Whether the deployment is production or staging (secure cookies
    /// are always set; this only tightens checks).
    pub hardened: bool,
}

impl OidcProviderSettings {
    /// Derives the settings. Fails when the provider is enabled without an
    /// interaction URL, or when the issuer collides with a native token
    /// audience.
    pub fn from_app_config(config: &AppConfig) -> Result<Self, AuthError> {
        let section = &config.oidc_provider;
        let base_url = config
            .server
            .public_base_url
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let issuer = section
            .issuer
            .clone()
            .or_else(|| config.session.issuer.clone())
            .unwrap_or_else(|| base_url.clone());
        let interaction_url = match &section.interaction_url {
            Some(url) => Some(Url::parse(url).map_err(|_| {
                AuthError::internal("oidc_provider.interaction_url is not a valid URL")
            })?),
            None => None,
        };
        if section.enabled && interaction_url.is_none() {
            return Err(AuthError::internal(
                "oidc_provider.interaction_url is required when the provider is enabled",
            ));
        }
        let mut supported_scopes: Vec<String> =
            STANDARD_SCOPES.iter().map(|s| (*s).to_owned()).collect();
        for scope in &section.custom_scopes {
            if !supported_scopes.contains(scope) {
                supported_scopes.push(scope.clone());
            }
        }
        let reserved_audiences = config.session.audiences.clone();
        let settings = Self {
            enabled: section.enabled,
            issuer,
            base_url,
            interaction_url,
            authorization_request_ttl: section.authorization_request_ttl,
            authorization_code_ttl: section.authorization_code_ttl,
            access_token_ttl: section.access_token_ttl,
            id_token_ttl: section.id_token_ttl,
            refresh_token_idle_ttl: section.refresh_token_idle_ttl,
            refresh_token_absolute_ttl: section.refresh_token_absolute_ttl,
            supported_scopes,
            reserved_audiences,
            jwt_leeway: config.crypto.jwt_leeway,
            authorize_per_ip: section.authorize_per_ip,
            token_per_ip: section.token_per_ip,
            token_per_client: section.token_per_client,
            userinfo_per_ip: section.userinfo_per_ip,
            hardened: matches!(
                config.server.environment,
                authn_core::config::Environment::Production
                    | authn_core::config::Environment::Staging
            ),
        };
        if settings.is_reserved_audience(&settings.userinfo_url()) {
            return Err(AuthError::internal(
                "session.audiences must not contain the provider's userinfo URL",
            ));
        }
        Ok(settings)
    }

    /// Absolute URL of an endpoint path.
    #[must_use]
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// The `userinfo` URL; also the audience that lets an access token be
    /// used there.
    #[must_use]
    pub fn userinfo_url(&self) -> String {
        self.endpoint(USERINFO_PATH)
    }

    /// Whether `aud` is an audience of native tokens.
    #[must_use]
    pub fn is_reserved_audience(&self, aud: &str) -> bool {
        self.reserved_audiences.iter().any(|a| a == aud) || aud == "first-party"
    }
}
