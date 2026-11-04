//! Settings of the session service, derived once from [`AppConfig`].

use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::protect::RiskConfig;
use authn_core::config::session::{Lifetime, SessionConfig};

/// Everything the session service reads from the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSettings {
    /// `[session]`.
    pub session: SessionConfig,
    /// JWT `iss`: `session.issuer` or `server.public_base_url` without the
    /// trailing slash.
    pub issuer: String,
    /// JWT `aud` of issued access tokens; the first entry is this API's own
    /// audience (validated on incoming bearer tokens).
    pub audiences: Vec<String>,
    /// Origins allowed for state-changing cookie requests (SES-04): the
    /// origin of `server.public_base_url` plus `session.csrf_allowed_origins`
    /// (ASCII-serialized, lower case).
    pub allowed_origins: Vec<String>,
    /// JWT clock-skew tolerance (`crypto.jwt_leeway`, CRY-09).
    pub jwt_leeway: Duration,
    /// `Cache-Control: max-age` of the JWKS (`crypto.signing_keys.jwks_cache_ttl`).
    pub jwks_max_age: Duration,
    /// Longest impersonation (`admin.impersonation_max_ttl`, ADM-04).
    pub impersonation_max_ttl: Duration,
    /// Honour `PrimaryAuthentication::provider_asserted_mfa`
    /// (`oidc_client.trust_provider_mfa`, SOC-09).
    pub trust_provider_mfa: bool,
    /// Passkey ceremony lifetime (`webauthn.ceremony_ttl`): lifetime of the
    /// step-up binding cookie.
    pub passkey_ceremony_ttl: Duration,
    /// Risk reactions (`protect.risk`, RSK-03).
    pub risk: RiskConfig,
}

impl SessionSettings {
    /// Derives the settings from a validated configuration.
    #[must_use]
    pub fn from_app_config(config: &AppConfig) -> Self {
        let base = &config.server.public_base_url;
        let issuer = config
            .session
            .issuer
            .clone()
            .unwrap_or_else(|| base.as_str().trim_end_matches('/').to_owned());
        let mut allowed_origins = vec![base.origin().ascii_serialization()];
        for origin in &config.session.csrf_allowed_origins {
            let normalized = url::Url::parse(origin).map_or_else(
                |_| origin.to_ascii_lowercase(),
                |u| u.origin().ascii_serialization(),
            );
            if !allowed_origins.contains(&normalized) {
                allowed_origins.push(normalized);
            }
        }
        Self {
            session: config.session.clone(),
            issuer,
            audiences: config.session.audiences.clone(),
            allowed_origins,
            jwt_leeway: config.crypto.jwt_leeway,
            jwks_max_age: config.crypto.signing_keys.jwks_cache_ttl,
            impersonation_max_ttl: config.admin.impersonation_max_ttl,
            trust_provider_mfa: config.oidc_client.trust_provider_mfa,
            passkey_ceremony_ttl: config.webauthn.ceremony_ttl,
            risk: config.protect.risk.clone(),
        }
    }

    /// The audience this API validates on incoming access tokens.
    #[must_use]
    pub fn own_audience(&self) -> &str {
        self.audiences.first().map_or("", String::as_str)
    }

    /// Lifetimes of a session of the given shape (SES-06, SES-07).
    #[must_use]
    pub fn lifetime(&self, shape: SessionShape) -> Lifetime {
        match shape {
            SessionShape::Native => self.session.refresh_token,
            SessionShape::SharedDevice => self.session.shared_device,
            SessionShape::RememberMe => self.session.remember_me,
            SessionShape::Web => self.session.web,
        }
    }
}

/// The lifetime class of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionShape {
    /// Browser session (idle 2h / absolute 12h).
    Web,
    /// "Remember me" browser session (14d / 30d), persistent cookie.
    RememberMe,
    /// "Not my device" browser session (SES-07): browser-session cookie and
    /// short lifetime. Wins over "remember me".
    SharedDevice,
    /// Native refresh-token family (30d / 90d).
    Native,
}

impl SessionShape {
    /// The shape of a new session.
    #[must_use]
    pub const fn of(native: bool, remember_me: bool, shared_device: bool) -> Self {
        if native {
            Self::Native
        } else if shared_device {
            Self::SharedDevice
        } else if remember_me {
            Self::RememberMe
        } else {
            Self::Web
        }
    }
}
