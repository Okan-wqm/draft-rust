//! The provider registry (SOC-01): Google, Apple, Microsoft (multi-tenant),
//! GitHub (OAuth 2.0) and generic OIDC providers (discovery), each enabled by
//! its `[oidc_client]` section.
//!
//! Built-in providers use their published, fixed endpoints (operator-trusted
//! destinations); a generic provider's endpoints come from its discovery
//! document ([`crate::discovery`]) and are called as *user-supplied* URLs
//! through the SSRF-safe client (a compromised discovery document cannot
//! point the server at internal addresses).

use std::collections::BTreeMap;
use std::fmt;

use authn_core::config::oidc_client::{GenericOidcProvider, ProviderClient};
use authn_core::error::AuthError;
use authn_core::ports::OutboundTarget;
use authn_core::secret::SecretString;
use url::Url;

use crate::apple::AppleClientSecret;
use crate::settings::OidcClientSettings;

pub use authn_core::config::oidc_client::{MICROSOFT_CONSUMERS_TENANT, is_guid};

/// Which protocol family a provider belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Google (OIDC).
    Google,
    /// Sign in with Apple (OIDC, `form_post`, ES256 client secret).
    Apple,
    /// Microsoft Entra ID / personal accounts (OIDC, tenant-specific issuer).
    Microsoft,
    /// GitHub (OAuth 2.0 + REST API; no ID token).
    Github,
    /// Any OIDC provider with discovery.
    Generic,
}

impl ProviderKind {
    /// Whether the provider issues ID tokens (OIDC).
    #[must_use]
    pub const fn is_oidc(self) -> bool {
        !matches!(self, Self::Github)
    }
}

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuthMethod {
    /// `client_id` + `client_secret` in the form body.
    ClientSecretPost,
    /// HTTP Basic (RFC 6749 §2.3.1).
    ClientSecretBasic,
}

/// Concrete endpoints of a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Browser-facing authorization endpoint.
    pub authorization: Url,
    /// Token endpoint.
    pub token: Url,
    /// JWKS (OIDC providers).
    pub jwks: Option<Url>,
    /// REST API base (GitHub: `https://api.github.com/`).
    pub api_base: Option<Url>,
    /// Client authentication at the token endpoint.
    pub token_auth: TokenAuthMethod,
    /// Trust level of the token / JWKS / API destinations.
    pub target: OutboundTarget,
}

/// How the `iss` claim is checked (SOC-03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerRule {
    /// `iss` must equal one of these values byte for byte.
    Exact(Vec<String>),
    /// Microsoft multi-tenant: `iss` must equal `prefix + tid + suffix`,
    /// where `tid` is the token's own `tid` claim (a GUID) and the tenant is
    /// admitted by the policy.
    MicrosoftTenant {
        /// `https://login.microsoftonline.com/`.
        prefix: String,
        /// `/v2.0`.
        suffix: String,
        /// Which tenants are admitted.
        policy: TenantPolicy,
    },
}

/// Tenants admitted for Microsoft sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPolicy {
    /// `oidc_client.microsoft.tenant` (lower case).
    pub configured: String,
    /// Optional explicit `tid` allow-list (lower case).
    pub allowed: Vec<String>,
}

impl TenantPolicy {
    /// Whether a token of tenant `tid` (a validated GUID) is admitted.
    #[must_use]
    pub fn admits(&self, tid: &str) -> bool {
        let tid = tid.to_ascii_lowercase();
        let by_setting = match self.configured.as_str() {
            "common" => true,
            "organizations" => tid != MICROSOFT_CONSUMERS_TENANT,
            "consumers" => tid == MICROSOFT_CONSUMERS_TENANT,
            other if is_guid(other) => tid == other,
            // A domain-form tenant cannot be compared with `tid`; only the
            // explicit allow-list (required at start-up) decides.
            _ => !self.allowed.is_empty(),
        };
        by_setting && (self.allowed.is_empty() || self.allowed.contains(&tid))
    }
}

/// Where a provider's endpoints come from.
#[derive(Debug, Clone)]
pub enum EndpointSource {
    /// Fixed endpoints (built-in providers, tests).
    Static(Box<Endpoints>),
    /// OIDC discovery of the configured issuer (generic providers).
    Discovery {
        /// The configured issuer; discovery must report exactly this value.
        issuer: String,
    },
}

/// The client credential presented at the token endpoint.
#[derive(Clone)]
pub enum ClientCredential {
    /// A configured client secret.
    Secret(SecretString),
    /// Apple: an ES256-signed JWT generated on demand (SOC-07).
    Apple(AppleClientSecret),
}

impl fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(_) => f.write_str("ClientCredential::Secret([REDACTED])"),
            Self::Apple(_) => f.write_str("ClientCredential::Apple([REDACTED])"),
        }
    }
}

/// One configured provider.
#[derive(Debug, Clone)]
pub struct Provider {
    /// Protocol family.
    pub kind: ProviderKind,
    /// Route segment (`/v1/oauth/{provider}/…`): `google`, `apple`,
    /// `microsoft`, `github` or the generic provider's slug.
    pub slug: String,
    /// Value of `identities.provider` / `oauth_states.provider`: the slug,
    /// or `oidc:<slug>` for generic providers.
    pub storage_id: String,
    /// Display name for login buttons.
    pub display_name: String,
    /// Web client id (`client_id`, the `aud` of web-flow ID tokens).
    pub client_id: String,
    /// Client credential.
    pub credential: ClientCredential,
    /// Accepted `aud` values of native ID tokens (SOC-04); empty = no
    /// native flow.
    pub native_client_ids: Vec<String>,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Endpoints.
    pub endpoints: EndpointSource,
    /// Issuer rule (for generic providers the configured issuer).
    pub issuer: IssuerRule,
    /// Whether the provider's own e-mail verification is trusted (SOC-05,
    /// ADR 0002). Generic providers: `trust_email_verified` (default
    /// `false`). Microsoft: whether a personal-account (MSA) address counts
    /// as verified, `trust_personal_account_email` (default `false`; work
    /// accounts still need `xms_edov`). Google, Apple, GitHub: `true` (they
    /// verify addresses; the claim / API flag is still required).
    pub trust_email_verified: bool,
}

impl Provider {
    /// Whether the provider supports the native flow (SOC-04).
    #[must_use]
    pub fn supports_native(&self) -> bool {
        self.kind.is_oidc() && !self.native_client_ids.is_empty()
    }
}

fn url(value: &str) -> Result<Url, AuthError> {
    Url::parse(value).map_err(|_| AuthError::internal("invalid built-in provider URL"))
}

fn static_endpoints(
    authorization: &str,
    token: &str,
    jwks: Option<&str>,
    api_base: Option<&str>,
) -> Result<Endpoints, AuthError> {
    Ok(Endpoints {
        authorization: url(authorization)?,
        token: url(token)?,
        jwks: jwks.map(url).transpose()?,
        api_base: api_base.map(url).transpose()?,
        token_auth: TokenAuthMethod::ClientSecretPost,
        target: OutboundTarget::Trusted,
    })
}

fn scopes(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn simple(
    kind: ProviderKind,
    slug: &str,
    display_name: &str,
    client: &ProviderClient,
    endpoints: Endpoints,
    issuer: IssuerRule,
    requested: &[&str],
) -> Provider {
    Provider {
        kind,
        slug: slug.to_owned(),
        storage_id: slug.to_owned(),
        display_name: display_name.to_owned(),
        client_id: client.client_id.clone(),
        credential: ClientCredential::Secret(client.client_secret.clone()),
        native_client_ids: client.native_client_ids.clone(),
        scopes: scopes(requested),
        endpoints: EndpointSource::Static(Box::new(endpoints)),
        issuer,
        trust_email_verified: true,
    }
}

fn generic(provider: &GenericOidcProvider) -> Provider {
    Provider {
        kind: ProviderKind::Generic,
        slug: provider.slug.clone(),
        storage_id: format!("oidc:{}", provider.slug),
        display_name: provider.display_name.clone(),
        client_id: provider.client.client_id.clone(),
        credential: ClientCredential::Secret(provider.client.client_secret.clone()),
        native_client_ids: provider.client.native_client_ids.clone(),
        scopes: provider.scopes.clone(),
        endpoints: EndpointSource::Discovery {
            issuer: provider.issuer_url.clone(),
        },
        issuer: IssuerRule::Exact(vec![provider.issuer_url.clone()]),
        trust_email_verified: provider.trust_email_verified,
    }
}

/// Every enabled provider, by route slug.
#[derive(Debug, Clone, Default)]
pub struct ProviderRegistry {
    providers: BTreeMap<String, Provider>,
}

impl ProviderRegistry {
    /// Builds the registry from the settings. Fails fast (ARC-07) on an
    /// unusable Apple key or a Microsoft tenant that cannot be enforced.
    pub fn from_settings(settings: &OidcClientSettings) -> Result<Self, AuthError> {
        let cfg = &settings.config;
        let mut providers = BTreeMap::new();
        if let Some(google) = &cfg.google {
            let endpoints = static_endpoints(
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                Some("https://www.googleapis.com/oauth2/v3/certs"),
                None,
            )?;
            providers.insert(
                "google".to_owned(),
                simple(
                    ProviderKind::Google,
                    "google",
                    "Google",
                    google,
                    endpoints,
                    // Google documents both spellings of its issuer.
                    IssuerRule::Exact(vec![
                        "https://accounts.google.com".to_owned(),
                        "accounts.google.com".to_owned(),
                    ]),
                    &["openid", "email", "profile"],
                ),
            );
        }
        if let Some(microsoft) = &cfg.microsoft {
            let tenant = microsoft.tenant.to_ascii_lowercase();
            let allowed: Vec<String> = settings
                .microsoft_allowed_tenants
                .iter()
                .map(|t| t.to_ascii_lowercase())
                .collect();
            if allowed.iter().any(|t| !is_guid(t)) {
                return Err(AuthError::internal(
                    "microsoft tenant allow-list entries must be tenant ids (GUIDs)",
                ));
            }
            let keyword = matches!(tenant.as_str(), "common" | "organizations" | "consumers");
            if !keyword && !is_guid(&tenant) && allowed.is_empty() {
                return Err(AuthError::internal(
                    "a domain-form microsoft tenant needs an explicit tenant id allow-list",
                ));
            }
            let base = format!("https://login.microsoftonline.com/{tenant}");
            let endpoints = static_endpoints(
                &format!("{base}/oauth2/v2.0/authorize"),
                &format!("{base}/oauth2/v2.0/token"),
                Some(&format!("{base}/discovery/v2.0/keys")),
                None,
            )?;
            let mut provider = simple(
                ProviderKind::Microsoft,
                "microsoft",
                "Microsoft",
                &microsoft.client,
                endpoints,
                IssuerRule::MicrosoftTenant {
                    prefix: "https://login.microsoftonline.com/".to_owned(),
                    suffix: "/v2.0".to_owned(),
                    policy: TenantPolicy {
                        configured: tenant,
                        allowed,
                    },
                },
                &["openid", "email", "profile"],
            );
            provider.trust_email_verified = microsoft.trust_personal_account_email;
            providers.insert("microsoft".to_owned(), provider);
        }
        if let Some(apple) = &cfg.apple {
            let secret = AppleClientSecret::from_config(apple, settings.apple_client_secret_ttl)?;
            let endpoints = static_endpoints(
                "https://appleid.apple.com/auth/authorize",
                "https://appleid.apple.com/auth/token",
                Some("https://appleid.apple.com/auth/keys"),
                None,
            )?;
            providers.insert(
                "apple".to_owned(),
                Provider {
                    kind: ProviderKind::Apple,
                    slug: "apple".to_owned(),
                    storage_id: "apple".to_owned(),
                    display_name: "Apple".to_owned(),
                    client_id: apple.client_id.clone(),
                    credential: ClientCredential::Apple(secret),
                    native_client_ids: apple.native_client_ids.clone(),
                    scopes: scopes(&["openid", "email", "name"]),
                    endpoints: EndpointSource::Static(Box::new(endpoints)),
                    issuer: IssuerRule::Exact(vec!["https://appleid.apple.com".to_owned()]),
                    trust_email_verified: true,
                },
            );
        }
        if let Some(github) = &cfg.github {
            let endpoints = static_endpoints(
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                None,
                Some("https://api.github.com/"),
            )?;
            let mut provider = simple(
                ProviderKind::Github,
                "github",
                "GitHub",
                github,
                endpoints,
                IssuerRule::Exact(Vec::new()),
                &["read:user", "user:email"],
            );
            // GitHub has no ID tokens, hence no native ID-token flow.
            provider.native_client_ids.clear();
            providers.insert("github".to_owned(), provider);
        }
        for g in &cfg.generic {
            providers.insert(g.slug.clone(), generic(g));
        }
        Ok(Self { providers })
    }

    /// The provider with route slug `slug`.
    #[must_use]
    pub fn get(&self, slug: &str) -> Option<&Provider> {
        self.providers.get(slug)
    }

    /// The provider whose storage id (`identities.provider`) is `id`.
    #[must_use]
    pub fn by_storage_id(&self, id: &str) -> Option<&Provider> {
        self.providers.values().find(|p| p.storage_id == id)
    }

    /// Every enabled provider, by slug.
    pub fn iter(&self) -> impl Iterator<Item = &Provider> {
        self.providers.values()
    }

    /// Replaces a provider's endpoints and issuer rule (tests against fake
    /// providers, private deployments with mirrored endpoints). Returns
    /// whether the provider exists.
    pub fn override_endpoints(
        &mut self,
        slug: &str,
        endpoints: Endpoints,
        issuer: Option<IssuerRule>,
    ) -> bool {
        let Some(provider) = self.providers.get_mut(slug) else {
            return false;
        };
        provider.endpoints = EndpointSource::Static(Box::new(endpoints));
        if let Some(issuer) = issuer {
            provider.issuer = issuer;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_03_microsoft_tenant_policy() {
        let tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let common = TenantPolicy {
            configured: "common".to_owned(),
            allowed: Vec::new(),
        };
        assert!(common.admits(tid));
        assert!(common.admits(MICROSOFT_CONSUMERS_TENANT));
        let orgs = TenantPolicy {
            configured: "organizations".to_owned(),
            allowed: Vec::new(),
        };
        assert!(orgs.admits(tid));
        assert!(!orgs.admits(MICROSOFT_CONSUMERS_TENANT));
        let consumers = TenantPolicy {
            configured: "consumers".to_owned(),
            allowed: Vec::new(),
        };
        assert!(!consumers.admits(tid));
        assert!(consumers.admits(MICROSOFT_CONSUMERS_TENANT));
        let single = TenantPolicy {
            configured: tid.to_owned(),
            allowed: Vec::new(),
        };
        assert!(single.admits(&tid.to_ascii_uppercase()));
        assert!(!single.admits(MICROSOFT_CONSUMERS_TENANT));
        let listed = TenantPolicy {
            configured: "common".to_owned(),
            allowed: vec![tid.to_owned()],
        };
        assert!(listed.admits(tid));
        assert!(!listed.admits("00000000-0000-0000-0000-000000000001"));
        let domain = TenantPolicy {
            configured: "contoso.onmicrosoft.com".to_owned(),
            allowed: vec![tid.to_owned()],
        };
        assert!(domain.admits(tid));
        assert!(!domain.admits(MICROSOFT_CONSUMERS_TENANT));
    }

    #[test]
    fn soc_03_guid_shape() {
        assert!(is_guid("72f988bf-86f1-41af-91ab-2d7cd011db47"));
        assert!(!is_guid("72f988bf86f141af91ab2d7cd011db47"));
        assert!(!is_guid("72f988bf-86f1-41af-91ab-2d7cd011db4/"));
        assert!(!is_guid("evil.example/../x"));
    }
}
