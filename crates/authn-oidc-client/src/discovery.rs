//! OIDC discovery of generic providers (SOC-01), cached.
//!
//! * The document is read from `{issuer}/.well-known/openid-configuration`
//!   (the configured issuer is an operator-trusted destination).
//! * Its `issuer` must equal the configured issuer **byte for byte**
//!   (OpenID Connect Discovery §4.3; prevents issuer mix-up); ID tokens are
//!   later checked against the same value.
//! * The endpoints it names are provider-controlled, so token and JWKS
//!   requests go to them as *user-supplied* URLs (SSRF rules: `https`,
//!   public addresses only, pinned DNS). An `https` issuer may not name
//!   plain-`http` endpoints.
//! * The document is cached for `oidc_client.jwks_cache_ttl`; when a
//!   refresh fails a stale document is still used.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use authn_core::error::{AuthError, codes};
use authn_core::ports::{HttpClient, OutboundTarget};
use serde::Deserialize;
use time::OffsetDateTime;
use url::Url;

use crate::outbound;
use crate::provider::{Endpoints, TokenAuthMethod};

#[derive(Debug, Deserialize)]
struct Document {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

#[derive(Clone)]
struct Entry {
    endpoints: Endpoints,
    fetched_at: OffsetDateTime,
}

/// Cache of discovered endpoints, by issuer. Cheap to clone.
#[derive(Clone)]
pub struct DiscoveryCache {
    entries: Arc<tokio::sync::Mutex<HashMap<String, Entry>>>,
    ttl: Duration,
}

impl std::fmt::Debug for DiscoveryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryCache")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

fn unavailable(context: &'static str) -> AuthError {
    tracing::warn!(context, "OIDC discovery failed");
    AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_context(context)
}

/// The discovery URL of `issuer`.
pub fn discovery_url(issuer: &str) -> Result<Url, AuthError> {
    let base = issuer.trim_end_matches('/');
    Url::parse(&format!("{base}/.well-known/openid-configuration"))
        .map_err(|_| unavailable("issuer is not a URL"))
}

fn endpoint(value: &str, issuer: &Url) -> Result<Url, AuthError> {
    let url = Url::parse(value).map_err(|_| unavailable("discovered endpoint is not a URL"))?;
    let scheme_ok = match url.scheme() {
        "https" => true,
        // Only a plain-http issuer (local development / tests) may use http.
        "http" => issuer.scheme() == "http",
        _ => false,
    };
    if !scheme_ok || url.host_str().is_none() || !url.username().is_empty() {
        return Err(unavailable("discovered endpoint is not an https URL"));
    }
    Ok(url)
}

/// Parses and checks a discovery document for `issuer`.
pub fn parse_document(body: &[u8], issuer: &str) -> Result<Endpoints, AuthError> {
    let doc: Document =
        serde_json::from_slice(body).map_err(|_| unavailable("malformed discovery document"))?;
    if doc.issuer != issuer {
        return Err(unavailable(
            "discovery issuer does not match the configured issuer",
        ));
    }
    let issuer_url = Url::parse(issuer).map_err(|_| unavailable("issuer is not a URL"))?;
    let methods = doc
        .token_endpoint_auth_methods_supported
        .unwrap_or_default();
    // RFC 8414 / OIDC Discovery: absent means client_secret_basic.
    let token_auth = if methods.iter().any(|m| m == "client_secret_basic") || methods.is_empty() {
        TokenAuthMethod::ClientSecretBasic
    } else if methods.iter().any(|m| m == "client_secret_post") {
        TokenAuthMethod::ClientSecretPost
    } else {
        return Err(unavailable(
            "provider supports no client-secret authentication",
        ));
    };
    Ok(Endpoints {
        authorization: endpoint(&doc.authorization_endpoint, &issuer_url)?,
        token: endpoint(&doc.token_endpoint, &issuer_url)?,
        jwks: Some(endpoint(&doc.jwks_uri, &issuer_url)?),
        api_base: None,
        revocation: None,
        token_auth,
        target: OutboundTarget::UserSupplied,
    })
}

impl DiscoveryCache {
    /// A cache keeping documents for `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// The endpoints of `issuer`.
    pub async fn endpoints(
        &self,
        http: &dyn HttpClient,
        issuer: &str,
        now: OffsetDateTime,
    ) -> Result<Endpoints, AuthError> {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get(issuer) {
            let age = now - entry.fetched_at;
            if !age.is_negative() && age.unsigned_abs() < self.ttl {
                return Ok(entry.endpoints.clone());
            }
        }
        let fetched = async {
            let response = outbound::get(
                http,
                discovery_url(issuer)?,
                OutboundTarget::Trusted,
                None,
                None,
            )
            .await?;
            if !response.status.is_success() {
                return Err(unavailable("discovery request failed"));
            }
            parse_document(&response.body, issuer)
        }
        .await;
        match fetched {
            Ok(endpoints) => {
                entries.insert(
                    issuer.to_owned(),
                    Entry {
                        endpoints: endpoints.clone(),
                        fetched_at: now,
                    },
                );
                Ok(endpoints)
            }
            Err(err) => entries.get(issuer).map(|e| e.endpoints.clone()).ok_or(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn doc(issuer: &str) -> Vec<u8> {
        json!({
            "issuer": issuer,
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://idp.example/jwks",
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn soc_01_discovery_issuer_must_match_exactly() {
        assert!(parse_document(&doc("https://idp.example"), "https://idp.example").is_ok());
        assert!(parse_document(&doc("https://idp.example/"), "https://idp.example").is_err());
        assert!(parse_document(&doc("https://evil.example"), "https://idp.example").is_err());
    }

    #[test]
    fn soc_01_discovered_endpoints_are_user_supplied_https() {
        let endpoints = parse_document(&doc("https://idp.example"), "https://idp.example").unwrap();
        assert_eq!(endpoints.target, OutboundTarget::UserSupplied);
        assert_eq!(endpoints.token_auth, TokenAuthMethod::ClientSecretBasic);
        let plain = json!({
            "issuer": "https://idp.example",
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "http://169.254.169.254/latest",
            "jwks_uri": "https://idp.example/jwks",
        });
        assert!(parse_document(plain.to_string().as_bytes(), "https://idp.example").is_err());
        let post_only = json!({
            "issuer": "https://idp.example",
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://idp.example/jwks",
            "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt"],
        });
        assert_eq!(
            parse_document(post_only.to_string().as_bytes(), "https://idp.example")
                .unwrap()
                .token_auth,
            TokenAuthMethod::ClientSecretPost
        );
    }

    #[test]
    fn soc_01_discovery_url() {
        assert_eq!(
            discovery_url("https://idp.example/tenant/")
                .unwrap()
                .as_str(),
            "https://idp.example/tenant/.well-known/openid-configuration"
        );
    }
}
