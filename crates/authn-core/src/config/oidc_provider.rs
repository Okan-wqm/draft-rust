//! `[oidc_provider]` — OAuth 2.1 / OpenID Connect provider (owner:
//! authn-oidc-provider). OIDP-01 … OIDP-13.
//!
//! The provider is **off by default** (`enabled = false`): its routes are
//! not mounted at all until an operator turns it on and names the
//! `interaction_url` of the login / consent front end.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours, mins, secs};
use crate::ports::RateLimitPolicy;

/// Scopes the provider always knows (OIDC Core §5.4). `openid` asks for
/// an ID token.
pub const STANDARD_SCOPES: &[&str] = &["openid", "profile", "email"];

/// Longest scope token accepted in configuration and requests.
pub const MAX_SCOPE_LEN: usize = 64;

/// `[oidc_provider]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcProviderConfig {
    /// Mount the provider endpoints (OIDP-13). Default `false`.
    pub enabled: bool,
    /// The `iss` of ID tokens and provider access tokens and the
    /// `issuer` of the discovery documents. Default: `session.issuer`,
    /// or `server.public_base_url` without a trailing slash. Discovery is
    /// served at `/.well-known/openid-configuration` of the server, so the
    /// issuer must not carry a path the reverse proxy does not strip.
    pub issuer: Option<String>,
    /// Absolute URL of the operator's login / consent page (OIDP-04).
    /// `GET /v1/oauth2/authorize` sends the browser there with
    /// `?interaction_id=<id>` when the user must sign in or consent.
    /// Required when `enabled`; `https` in production and staging.
    pub interaction_url: Option<String>,
    /// Lifetime of a pending authorization request (interaction).
    /// Default `10m`, 1 min – 30 min.
    #[serde(with = "super::duration")]
    pub authorization_request_ttl: Duration,
    /// Lifetime of an authorization code. Default `60s`, 10 s – 10 min
    /// (RFC 6749 §4.1.2 recommends at most 10 minutes).
    #[serde(with = "super::duration")]
    pub authorization_code_ttl: Duration,
    /// Lifetime of a provider access token (JWT, RFC 9068). Default `5m`,
    /// 1 min – 1 h. Resource servers that verify it locally see a
    /// revocation only after this long; introspection and `userinfo`
    /// see it at once.
    #[serde(with = "super::duration")]
    pub access_token_ttl: Duration,
    /// Lifetime of an ID token. Default `5m`, 1 min – 1 h.
    #[serde(with = "super::duration")]
    pub id_token_ttl: Duration,
    /// A refresh token expires when unused this long (each rotation
    /// starts a new period). Default `1d`, 1 h – 90 d.
    #[serde(with = "super::duration")]
    pub refresh_token_idle_ttl: Duration,
    /// Absolute lifetime of a grant (its refresh-token family). Default
    /// `30d`, at least `refresh_token_idle_ttl`, at most 400 d. A grant
    /// also ends with the user session that created it (OIDP-12).
    #[serde(with = "super::duration")]
    pub refresh_token_absolute_ttl: Duration,
    /// Additional scopes clients may be registered for, besides
    /// [`STANDARD_SCOPES`] (`[a-z][a-z0-9_.:-]{0,63}`). Default empty.
    pub custom_scopes: Vec<String>,
    /// `GET /v1/oauth2/authorize` per client IP. Default 60 / 1 min.
    pub authorize_per_ip: RateLimitPolicy,
    /// Token, revocation and introspection requests per client IP.
    /// Default 120 / 1 min.
    pub token_per_ip: RateLimitPolicy,
    /// Token, revocation and introspection requests per client. Default
    /// 600 / 1 min.
    pub token_per_client: RateLimitPolicy,
    /// `userinfo` requests per client IP. Default 120 / 1 min.
    pub userinfo_per_ip: RateLimitPolicy,
}

impl Default for OidcProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: None,
            interaction_url: None,
            authorization_request_ttl: mins(10),
            authorization_code_ttl: secs(60),
            access_token_ttl: mins(5),
            id_token_ttl: mins(5),
            refresh_token_idle_ttl: days(1),
            refresh_token_absolute_ttl: days(30),
            custom_scopes: Vec::new(),
            authorize_per_ip: RateLimitPolicy::new(60, mins(1)),
            token_per_ip: RateLimitPolicy::new(120, mins(1)),
            token_per_client: RateLimitPolicy::new(600, mins(1)),
            userinfo_per_ip: RateLimitPolicy::new(120, mins(1)),
        }
    }
}

/// Whether `scope` is a well-formed custom scope token.
#[must_use]
pub fn is_valid_custom_scope(scope: &str) -> bool {
    let mut bytes = scope.bytes();
    scope.len() <= MAX_SCOPE_LEN
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b':' | b'-')
        })
}

fn is_absolute_http_url(value: &str, require_https: bool) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    let scheme_ok = if require_https {
        url.scheme() == "https"
    } else {
        matches!(url.scheme(), "https" | "http")
    };
    scheme_ok
        && url.host_str().is_some()
        && url.fragment().is_none()
        && url.query().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

impl OidcProviderConfig {
    /// Validates the section (environment-independent rules).
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require_range(
            self.authorization_request_ttl,
            mins(1),
            mins(30),
            "oidc_provider.authorization_request_ttl",
        );
        p.require_range(
            self.authorization_code_ttl,
            secs(10),
            mins(10),
            "oidc_provider.authorization_code_ttl",
        );
        p.require_range(
            self.access_token_ttl,
            mins(1),
            hours(1),
            "oidc_provider.access_token_ttl",
        );
        p.require_range(
            self.id_token_ttl,
            mins(1),
            hours(1),
            "oidc_provider.id_token_ttl",
        );
        p.require_range(
            self.refresh_token_idle_ttl,
            hours(1),
            days(90),
            "oidc_provider.refresh_token_idle_ttl",
        );
        p.require_range(
            self.refresh_token_absolute_ttl,
            self.refresh_token_idle_ttl,
            days(400),
            "oidc_provider.refresh_token_absolute_ttl",
        );
        for scope in &self.custom_scopes {
            p.require(
                is_valid_custom_scope(scope) && !STANDARD_SCOPES.contains(&scope.as_str()),
                "oidc_provider.custom_scopes",
                "each scope must match [a-z][a-z0-9_.:-]{0,63} and not repeat a standard scope",
            );
        }
        if let Some(issuer) = &self.issuer {
            p.require(
                is_absolute_http_url(issuer, false) && !issuer.ends_with('/'),
                "oidc_provider.issuer",
                "must be an absolute http(s) URL without query, fragment or trailing slash",
            );
        }
        if let Some(url) = &self.interaction_url {
            p.require(
                is_absolute_http_url(url, false),
                "oidc_provider.interaction_url",
                "must be an absolute http(s) URL without query or fragment",
            );
        }
        p.require(
            !self.enabled || self.interaction_url.is_some(),
            "oidc_provider.interaction_url",
            "is required when oidc_provider.enabled = true",
        );
        for (policy, key) in [
            (self.authorize_per_ip, "oidc_provider.authorize_per_ip"),
            (self.token_per_ip, "oidc_provider.token_per_ip"),
            (self.token_per_client, "oidc_provider.token_per_client"),
            (self.userinfo_per_ip, "oidc_provider.userinfo_per_ip"),
        ] {
            p.require(
                policy.limit > 0 && !policy.period.is_zero(),
                key,
                "limit and period must be positive",
            );
        }
    }

    /// Production / staging rules (called from `AppConfig`'s cross-section
    /// validation): the issuer and the interaction page use `https`.
    pub fn validate_hardened(&self, p: &mut ConfigProblems) {
        if let Some(url) = &self.interaction_url {
            p.require(
                is_absolute_http_url(url, true),
                "oidc_provider.interaction_url",
                "must use https in production and staging",
            );
        }
        if let Some(issuer) = &self.issuer {
            p.require(
                is_absolute_http_url(issuer, true),
                "oidc_provider.issuer",
                "must use https in production and staging",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(config: &OidcProviderConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    #[test]
    fn oidp_13_defaults_are_valid_and_disabled() {
        let config = OidcProviderConfig::default();
        assert!(!config.enabled);
        assert!(problems(&config).is_empty(), "{:?}", problems(&config));
        assert_eq!(config.authorization_code_ttl, secs(60));
        assert_eq!(config.access_token_ttl, mins(5));
    }

    #[test]
    fn oidp_13_enabling_requires_an_interaction_url() {
        let config = OidcProviderConfig {
            enabled: true,
            ..OidcProviderConfig::default()
        };
        assert!(
            problems(&config)
                .iter()
                .any(|p| p.contains("oidc_provider.interaction_url"))
        );
        let config = OidcProviderConfig {
            enabled: true,
            interaction_url: Some("https://app.example.com/oauth/consent".into()),
            ..OidcProviderConfig::default()
        };
        assert!(problems(&config).is_empty());
    }

    #[test]
    fn oidp_13_rejects_bad_values() {
        let config = OidcProviderConfig {
            issuer: Some("https://auth.example.com/".into()),
            interaction_url: Some("https://app.example.com/consent#x".into()),
            authorization_code_ttl: mins(30),
            refresh_token_absolute_ttl: hours(2),
            custom_scopes: vec!["Bad Scope".into(), "openid".into()],
            ..OidcProviderConfig::default()
        };
        let found = problems(&config);
        for key in [
            "oidc_provider.issuer",
            "oidc_provider.interaction_url",
            "oidc_provider.authorization_code_ttl",
            "oidc_provider.refresh_token_absolute_ttl",
            "oidc_provider.custom_scopes",
        ] {
            assert!(found.iter().any(|p| p.contains(key)), "{key}: {found:?}");
        }
    }

    #[test]
    fn oidp_13_hardened_environments_require_https() {
        let config = OidcProviderConfig {
            issuer: Some("http://auth.example.com".into()),
            interaction_url: Some("http://app.example.com/consent".into()),
            ..OidcProviderConfig::default()
        };
        let mut p = ConfigProblems::default();
        config.validate_hardened(&mut p);
        assert_eq!(p.problems().len(), 2, "{:?}", p.problems());
    }

    #[test]
    fn oidp_13_custom_scope_format() {
        assert!(is_valid_custom_scope("orders:read"));
        assert!(is_valid_custom_scope("api.v1"));
        assert!(!is_valid_custom_scope(""));
        assert!(!is_valid_custom_scope("1abc"));
        assert!(!is_valid_custom_scope("a b"));
        assert!(!is_valid_custom_scope(&"a".repeat(65)));
    }
}
