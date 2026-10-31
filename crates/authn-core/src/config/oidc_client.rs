//! `[oidc_client]` — social login providers (owner: authn-oidc-client).
//! SOC-01 … SOC-09.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, hours, mins};
use crate::secret::SecretString;

/// A confidential OAuth/OIDC client registration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderClient {
    /// Client id.
    pub client_id: String,
    /// Client secret.
    pub client_secret: SecretString,
    /// Additional accepted `aud` values for ID tokens obtained natively by
    /// mobile SDKs (SOC-04), e.g. the iOS / Android client ids.
    #[serde(default)]
    pub native_client_ids: Vec<String>,
}

/// Microsoft Entra ID (multi-tenant) settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MicrosoftProvider {
    /// Client registration.
    #[serde(flatten)]
    pub client: ProviderClient,
    /// `common`, `organizations`, `consumers` or a tenant id. Default
    /// `common`.
    #[serde(default = "default_tenant")]
    pub tenant: String,
}

fn default_tenant() -> String {
    "common".to_owned()
}

/// Sign in with Apple (SOC-07).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleProvider {
    /// Services id (web) used as `client_id`.
    pub client_id: String,
    /// Apple developer team id.
    pub team_id: String,
    /// Key id of the Sign in with Apple private key.
    pub key_id: String,
    /// PKCS#8 PEM private key (ES256) used to sign the `client_secret` JWT.
    pub private_key_pem: SecretString,
    /// Bundle ids accepted as `aud` for native ID tokens (SOC-04).
    #[serde(default)]
    pub native_client_ids: Vec<String>,
}

/// A generic OIDC provider using discovery.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericOidcProvider {
    /// URL-safe identifier used in routes (`/v1/oauth/{slug}/…`).
    pub slug: String,
    /// Display name.
    pub display_name: String,
    /// Issuer URL (discovery at `/.well-known/openid-configuration`).
    pub issuer_url: String,
    /// Client registration.
    #[serde(flatten)]
    pub client: ProviderClient,
    /// Scopes. Default `["openid", "email", "profile"]`.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

fn default_scopes() -> Vec<String> {
    ["openid", "email", "profile"].map(str::to_owned).to_vec()
}

/// `[oidc_client]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcClientConfig {
    /// Authorization state lifetime (SOC-02). Default `10m`.
    #[serde(with = "super::duration")]
    pub state_ttl: Duration,
    /// Native nonce lifetime (SOC-04). Default `10m`.
    #[serde(with = "super::duration")]
    pub native_nonce_ttl: Duration,
    /// Allowed `return_to` values (exact match) in addition to relative
    /// paths (PRT-10). Default none.
    pub allowed_return_to: Vec<String>,
    /// Google.
    pub google: Option<ProviderClient>,
    /// Microsoft.
    pub microsoft: Option<MicrosoftProvider>,
    /// Apple.
    pub apple: Option<AppleProvider>,
    /// GitHub (OAuth2 + `/user/emails`).
    pub github: Option<ProviderClient>,
    /// Generic OIDC providers.
    pub generic: Vec<GenericOidcProvider>,
    /// Auto-link a new identity to an existing account with the same,
    /// provider-verified e-mail (SOC-05). Default `false`.
    pub auto_link_verified_email: bool,
    /// Providers trusted for auto-linking. Default none.
    pub auto_link_trusted_providers: Vec<String>,
    /// Treat provider-asserted MFA as satisfying MFA (SOC-09). Default
    /// `false`.
    pub trust_provider_mfa: bool,
    /// Store provider tokens (encrypted, SOC-08). Default `false`.
    pub store_provider_tokens: bool,
    /// JWKS cache lifetime (refreshed early on unknown `kid`). Default `1h`.
    #[serde(with = "super::duration")]
    pub jwks_cache_ttl: Duration,
}

impl Default for OidcClientConfig {
    fn default() -> Self {
        Self {
            state_ttl: mins(10),
            native_nonce_ttl: mins(10),
            allowed_return_to: Vec::new(),
            google: None,
            microsoft: None,
            apple: None,
            github: None,
            generic: Vec::new(),
            auto_link_verified_email: false,
            auto_link_trusted_providers: Vec::new(),
            trust_provider_mfa: false,
            store_provider_tokens: false,
            jwks_cache_ttl: hours(1),
        }
    }
}

impl OidcClientConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require_range(self.state_ttl, mins(1), mins(30), "oidc_client.state_ttl");
        p.require_range(
            self.native_nonce_ttl,
            mins(1),
            mins(30),
            "oidc_client.native_nonce_ttl",
        );
        p.require_range(
            self.jwks_cache_ttl,
            mins(1),
            hours(24),
            "oidc_client.jwks_cache_ttl",
        );
        let mut slugs = std::collections::HashSet::new();
        for (i, provider) in self.generic.iter().enumerate() {
            let key = format!("oidc_client.generic[{i}]");
            let slug_ok = !provider.slug.is_empty()
                && provider.slug.len() <= 32
                && provider
                    .slug
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !["google", "microsoft", "apple", "github"].contains(&provider.slug.as_str());
            p.require(
                slug_ok,
                &key,
                "slug must be [a-z0-9-]{1,32} and not a built-in provider name",
            );
            p.require(slugs.insert(provider.slug.as_str()), &key, "duplicate slug");
            p.require(
                provider.issuer_url.starts_with("https://"),
                &format!("{key}.issuer_url"),
                "must be https",
            );
        }
        p.require(
            !self.auto_link_verified_email || !self.auto_link_trusted_providers.is_empty(),
            "oidc_client.auto_link_trusted_providers",
            "must list providers when auto_link_verified_email is enabled",
        );
    }
}
