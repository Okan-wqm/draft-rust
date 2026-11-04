//! `[oidc_client]` — social login providers (owner: authn-oidc-client).
//! SOC-01 … SOC-09.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, hours, mins, secs};
use super::password::validate_policy;
use crate::ports::RateLimitPolicy;
use crate::secret::SecretString;

/// Tenant id of Microsoft personal accounts (MSA, the `consumers` tenant).
pub const MICROSOFT_CONSUMERS_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// Whether `value` is a GUID in its 8-4-4-4-12 hex form (any case).
#[must_use]
pub fn is_guid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

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
    /// Tenant ids (GUIDs) whose users may sign in (`tid` allow-list,
    /// SOC-03). Empty = every tenant admitted by [`Self::tenant`]. Required
    /// when `tenant` is a domain name (`contoso.com`), because the `tid` of
    /// such tokens can only be checked against an explicit list.
    #[serde(default)]
    pub allowed_tenants: Vec<String>,
    /// Treat the `email` claim of a Microsoft **personal** account (MSA,
    /// tenant `9188040d-…`) as verified (SOC-05, ADR 0002). Default
    /// `false` — the safe side: Microsoft documents the `email` claim as
    /// optional, mutable and not verified by the identity platform, and
    /// only issues the `xms_edov` ("e-mail domain owner verified") claim for
    /// work accounts. With `false`, an MSA identity never creates an
    /// account or auto-links by e-mail; the user signs up with e-mail (or
    /// another provider) and links Microsoft explicitly while signed in.
    /// Turning it on trusts Microsoft's own address verification at MSA
    /// sign-up; do so only after accepting that trade-off.
    #[serde(default)]
    pub trust_personal_account_email: bool,
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
    /// PKCS#8 PEM private key (ES256) used to sign the `client_secret` JWT,
    /// inline. Exactly one of `private_key_pem`, `private_key_file` and
    /// `private_key_ciphertext` must be set (SOC-07).
    #[serde(default)]
    pub private_key_pem: Option<SecretString>,
    /// Path of a file holding the PKCS#8 PEM private key (SOC-07 "or a
    /// file"; e.g. a mounted secret). Read once at start-up.
    #[serde(default)]
    pub private_key_file: Option<PathBuf>,
    /// The PKCS#8 PEM private key **envelope encrypted** with the `[crypto]`
    /// KEK (SOC-07 "envelope encrypted", K-34): standard base64 of an
    /// authn-crypto envelope sealed for the fixed context
    /// `oidc_client` / `apple_private_key` / `apple`. Decrypted once at
    /// start-up (authn-oidc-client `OidcClientService::build`); produce it
    /// with `authn_oidc_client::apple::seal_private_key`.
    #[serde(default)]
    pub private_key_ciphertext: Option<SecretString>,
    /// Bundle ids accepted as `aud` for native ID tokens (SOC-04).
    #[serde(default)]
    pub native_client_ids: Vec<String>,
    /// Keep the user's Sign in with Apple refresh token (envelope
    /// encrypted, SOC-08) so it can be revoked at Apple when the account
    /// is deleted or Apple is unlinked (K-35). Apple requires apps that
    /// offer account deletion to revoke the user's tokens. Default `true`;
    /// with `false` no Apple token is kept (unless `store_provider_tokens`)
    /// and nothing can be revoked.
    #[serde(default = "default_true")]
    pub revoke_tokens_on_deletion: bool,
}

const fn default_true() -> bool {
    true
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
    /// Trust the provider's `email_verified` claim (SOC-05, ADR 0002
    /// "non-verifying IdP"). Default `false`: an arbitrary OIDC provider
    /// may let its users assert any address, so its addresses are treated
    /// as unverified — the identity never creates an account or auto-links
    /// by e-mail, it can only be linked explicitly by a signed-in user.
    /// Set `true` only for an IdP known to verify addresses.
    #[serde(default)]
    pub trust_email_verified: bool,
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
    /// Shortest gap between two JWKS downloads forced by an unknown `kid`
    /// (SOC-03): random `kid` values cannot become a flood of requests to
    /// the provider. Default `60s`, 10 s – 1 h.
    #[serde(with = "super::duration")]
    pub jwks_refresh_min_interval: Duration,
    /// Web flow starts per client IP (PRT-02). Default 60 / 10 min.
    pub start_per_ip: RateLimitPolicy,
    /// Native nonces and native logins per client IP (PRT-02). Default
    /// 60 / 10 min.
    pub native_per_ip: RateLimitPolicy,
    /// Web callbacks per client IP (PRT-02), checked before the state
    /// lookup. Default 60 / 10 min.
    pub callback_per_ip: RateLimitPolicy,
    /// Where the browser is sent when a web callback fails (K-36): a
    /// same-origin path (`/login/error`) or an absolute URL that is in
    /// `protect.redirect_allow_list` / `allowed_return_to` (checked at
    /// start-up with authn-protect's redirect validator; no open redirect).
    /// The stable error code is appended as `error=<code>`. Default none:
    /// callback errors are answered with the JSON error envelope.
    pub error_redirect: Option<String>,
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
            jwks_refresh_min_interval: secs(60),
            start_per_ip: RateLimitPolicy::new(60, mins(10)),
            native_per_ip: RateLimitPolicy::new(60, mins(10)),
            callback_per_ip: RateLimitPolicy::new(60, mins(10)),
            error_redirect: None,
        }
    }
}

impl MicrosoftProvider {
    fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            self.allowed_tenants.iter().all(|t| is_guid(t)),
            "oidc_client.microsoft.allowed_tenants",
            "entries must be tenant ids (GUIDs)",
        );
        let tenant = self.tenant.to_ascii_lowercase();
        let keyword = matches!(tenant.as_str(), "common" | "organizations" | "consumers");
        p.require(
            !tenant.is_empty(),
            "oidc_client.microsoft.tenant",
            "must not be empty",
        );
        p.require(
            keyword || is_guid(&tenant) || !self.allowed_tenants.is_empty(),
            "oidc_client.microsoft.allowed_tenants",
            "required when tenant is a domain name",
        );
    }
}

impl AppleProvider {
    fn validate(&self, p: &mut ConfigProblems) {
        let sources = [
            self.private_key_pem.is_some(),
            self.private_key_file.is_some(),
            self.private_key_ciphertext.is_some(),
        ];
        p.require(
            sources.iter().filter(|set| **set).count() == 1,
            "oidc_client.apple.private_key_pem",
            "exactly one of private_key_pem, private_key_file and private_key_ciphertext must be set",
        );
        if let Some(path) = &self.private_key_file {
            p.require(
                !path.as_os_str().is_empty(),
                "oidc_client.apple.private_key_file",
                "must not be empty",
            );
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
        p.require_range(
            self.jwks_refresh_min_interval,
            secs(10),
            hours(1),
            "oidc_client.jwks_refresh_min_interval",
        );
        validate_policy(p, &self.start_per_ip, "oidc_client.start_per_ip");
        validate_policy(p, &self.native_per_ip, "oidc_client.native_per_ip");
        validate_policy(p, &self.callback_per_ip, "oidc_client.callback_per_ip");
        if let Some(microsoft) = &self.microsoft {
            microsoft.validate(p);
        }
        if let Some(apple) = &self.apple {
            apple.validate(p);
        }
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
        if let Some(target) = &self.error_redirect {
            let relative =
                target.starts_with('/') && !target.starts_with("//") && !target.starts_with("/\\");
            p.require(
                !target.is_empty()
                    && target.len() <= 2048
                    && (relative || target.starts_with("https://")),
                "oidc_client.error_redirect",
                "must be a same-origin path or an https URL (allow-listed)",
            );
        }
        p.require(
            !self.auto_link_verified_email || !self.auto_link_trusted_providers.is_empty(),
            "oidc_client.auto_link_trusted_providers",
            "must list providers when auto_link_verified_email is enabled",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> OidcClientConfig {
        use figment::Figment;
        use figment::providers::{Format, Toml};
        Figment::new().merge(Toml::string(toml)).extract().unwrap()
    }

    fn problems(config: &OidcClientConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    #[test]
    fn soc_03_new_keys_have_documented_defaults() {
        let c = OidcClientConfig::default();
        assert_eq!(c.jwks_refresh_min_interval, secs(60));
        assert_eq!(c.start_per_ip, RateLimitPolicy::new(60, mins(10)));
        assert_eq!(c.native_per_ip, RateLimitPolicy::new(60, mins(10)));
        assert_eq!(c.callback_per_ip, RateLimitPolicy::new(60, mins(10)));
        assert!(problems(&c).is_empty());
    }

    #[test]
    fn soc_05_trust_settings_default_to_the_safe_side() {
        let c = parse(
            r#"
            [microsoft]
            client_id = "ms"
            client_secret = "s"
            [[generic]]
            slug = "acme"
            display_name = "Acme"
            issuer_url = "https://idp.example"
            client_id = "acme"
            client_secret = "s"
            "#,
        );
        let ms = c.microsoft.as_ref().unwrap();
        assert!(!ms.trust_personal_account_email);
        assert!(ms.allowed_tenants.is_empty());
        assert!(!c.generic[0].trust_email_verified);
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
    }

    #[test]
    fn soc_03_every_new_key_parses_and_validates() {
        let c = parse(
            r#"
            jwks_refresh_min_interval = "30s"
            start_per_ip = { limit = 10, period = "1m" }
            native_per_ip = { limit = 20, period = "1m" }
            callback_per_ip = { limit = 30, period = "1m" }
            [microsoft]
            client_id = "ms"
            client_secret = "s"
            tenant = "contoso.com"
            allowed_tenants = ["72F988BF-86F1-41AF-91AB-2D7CD011DB47"]
            trust_personal_account_email = true
            [apple]
            client_id = "com.example.web"
            team_id = "TEAM"
            key_id = "KEY"
            private_key_file = "/run/secrets/apple.p8"
            [[generic]]
            slug = "acme"
            display_name = "Acme"
            issuer_url = "https://idp.example"
            client_id = "acme"
            client_secret = "s"
            trust_email_verified = true
            "#,
        );
        assert_eq!(c.jwks_refresh_min_interval, secs(30));
        assert_eq!(c.start_per_ip, RateLimitPolicy::new(10, mins(1)));
        assert_eq!(c.native_per_ip, RateLimitPolicy::new(20, mins(1)));
        assert_eq!(c.callback_per_ip, RateLimitPolicy::new(30, mins(1)));
        let ms = c.microsoft.as_ref().unwrap();
        assert_eq!(ms.allowed_tenants.len(), 1);
        assert!(ms.trust_personal_account_email);
        let apple = c.apple.as_ref().unwrap();
        assert!(apple.private_key_pem.is_none());
        assert_eq!(
            apple.private_key_file.as_deref(),
            Some(std::path::Path::new("/run/secrets/apple.p8"))
        );
        assert!(c.generic[0].trust_email_verified);
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
    }

    #[test]
    fn soc_03_invalid_new_keys_are_rejected() {
        let mut c = parse(
            r#"
            jwks_refresh_min_interval = "1s"
            start_per_ip = { limit = 0, period = "1m" }
            [microsoft]
            client_id = "ms"
            client_secret = "s"
            tenant = "contoso.com"
            allowed_tenants = ["contoso.com"]
            [apple]
            client_id = "com.example.web"
            team_id = "TEAM"
            key_id = "KEY"
            "#,
        );
        let found = problems(&c);
        for key in [
            "oidc_client.jwks_refresh_min_interval",
            "oidc_client.start_per_ip",
            "oidc_client.microsoft.allowed_tenants: entries must be tenant ids",
            "oidc_client.apple.private_key_pem: exactly one",
        ] {
            assert!(found.iter().any(|p| p.starts_with(key)), "{key}: {found:?}");
        }
        // A domain-form tenant without an allow-list cannot be enforced.
        if let Some(ms) = c.microsoft.as_mut() {
            ms.allowed_tenants.clear();
        }
        assert!(
            problems(&c)
                .iter()
                .any(|p| p.starts_with("oidc_client.microsoft.allowed_tenants: required"))
        );
        // Both key sources at once are refused too.
        if let Some(apple) = c.apple.as_mut() {
            apple.private_key_pem = Some(SecretString::from("pem".to_owned()));
            apple.private_key_file = Some(PathBuf::from("/k.p8"));
        }
        assert!(
            problems(&c)
                .iter()
                .any(|p| p.starts_with("oidc_client.apple.private_key_pem: exactly one"))
        );
    }

    /// The commented `[oidc_client]` lines of `config/example.toml`,
    /// uncommented, parse and document the defaults of the new keys.
    #[test]
    fn soc_03_documented_example_parses() {
        let example = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/example.toml"),
        )
        .unwrap();
        // The `[oidc_client]` block: from its header to the next section.
        let toml: String = example
            .lines()
            .skip_while(|l| !l.starts_with("[oidc_client]"))
            .skip(1)
            .take_while(|l| !l.starts_with('['))
            .filter_map(|l| l.strip_prefix("# "))
            .map(|l| {
                // Section headers are relative to `[oidc_client]`.
                l.replace("[oidc_client.", "[")
                    .replace("[[oidc_client.", "[[")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut c = parse(&toml);
        let defaults = OidcClientConfig::default();
        assert_eq!(
            c.jwks_refresh_min_interval,
            defaults.jwks_refresh_min_interval
        );
        assert_eq!(c.start_per_ip, defaults.start_per_ip);
        assert_eq!(c.native_per_ip, defaults.native_per_ip);
        assert_eq!(c.callback_per_ip, defaults.callback_per_ip);
        let ms = c.microsoft.as_ref().unwrap();
        assert!(ms.allowed_tenants.is_empty() && !ms.trust_personal_account_email);
        assert!(!c.generic[0].trust_email_verified);
        // The example shows every Apple key source; exactly one is allowed.
        if let Some(apple) = c.apple.as_mut() {
            assert!(apple.private_key_ciphertext.is_some());
            assert!(apple.revoke_tokens_on_deletion);
            apple.private_key_pem = None;
            apple.private_key_ciphertext = None;
        }
        assert_eq!(c.error_redirect.as_deref(), Some("/login/error"));
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
    }

    #[test]
    fn soc_07_apple_key_secret_is_redacted_in_debug() {
        let c = parse(
            r#"
            [apple]
            client_id = "com.example.web"
            team_id = "TEAM"
            key_id = "KEY"
            private_key_pem = "-----BEGIN PRIVATE KEY-----TOPSECRET"
            "#,
        );
        assert!(!format!("{c:?}").contains("TOPSECRET"));
    }

    #[test]
    fn soc_07_apple_key_ciphertext_is_a_third_exclusive_source() {
        let mut c = parse(
            r#"
            [apple]
            client_id = "com.example.web"
            team_id = "TEAM"
            key_id = "KEY"
            private_key_ciphertext = "AAAA-sealed-TOPSECRET"
            "#,
        );
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
        let apple = c.apple.as_ref().unwrap();
        assert!(apple.revoke_tokens_on_deletion, "default on (K-35)");
        assert!(!format!("{c:?}").contains("TOPSECRET"));
        if let Some(apple) = c.apple.as_mut() {
            apple.private_key_file = Some(PathBuf::from("/k.p8"));
        }
        assert!(
            problems(&c)
                .iter()
                .any(|p| p.starts_with("oidc_client.apple.private_key_pem: exactly one"))
        );
    }

    #[test]
    fn soc_02_error_redirect_must_be_a_path_or_https() {
        for ok in ["/login/error", "https://app.example.com/oops"] {
            let c = OidcClientConfig {
                error_redirect: Some(ok.to_owned()),
                ..OidcClientConfig::default()
            };
            assert!(problems(&c).is_empty(), "{ok}: {:?}", problems(&c));
        }
        for bad in [
            "",
            "//evil.example",
            "/\\evil.example",
            "http://app.example.com/oops",
            "javascript:alert(1)",
            "evil.example/x",
        ] {
            let c = OidcClientConfig {
                error_redirect: Some(bad.to_owned()),
                ..OidcClientConfig::default()
            };
            assert!(
                problems(&c)
                    .iter()
                    .any(|p| p.starts_with("oidc_client.error_redirect")),
                "{bad:?} accepted"
            );
        }
    }
}
