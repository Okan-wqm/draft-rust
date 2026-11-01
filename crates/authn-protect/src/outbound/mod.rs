//! SSRF-safe outbound HTTP (PRT-12): the [`HttpClient`] port implementation.
//!
//! Two `reqwest` clients share the rules below; they differ in how they
//! resolve names:
//!
//! | target | resolution | scheme | destinations |
//! |--------|-----------|--------|--------------|
//! | [`OutboundTarget::Trusted`] (HIBP, OIDC, CAPTCHA, SMS: operator-configured) | system | `http`/`https` | any |
//! | [`OutboundTarget::UserSupplied`] (webhooks, tenant URLs) | [`VettingResolver`]: resolve once, refuse if *any* address is non-public, connect to exactly those addresses | `https` only | public unicast only |
//!
//! Common to both:
//! * no proxy (a proxy would resolve the name itself and bypass the
//!   pinning), no automatic redirects (3xx is returned to the caller; every
//!   hop would otherwise need re-vetting), no automatic decompression;
//! * connect timeout and total timeout (`[protect.outbound]`), per-request
//!   overrides capped at 2 minutes;
//! * the response body is read incrementally and the request fails as soon
//!   as it exceeds the size limit (also when `Content-Length` announces
//!   more);
//! * URLs are never logged (query strings may carry secrets) — only hosts;
//! * caller-supplied `Host` headers are dropped.
//!
//! IP-literal URLs never reach a resolver, so they are classified up front by
//! [`validate_user_supplied_url`]. `protect.outbound.allow_private_networks`
//! (refused in production) relaxes the address and `https` rules for local
//! mock servers.

pub mod ip;
pub mod resolver;

use std::error::Error as _;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::protect::OutboundHttpConfig;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{HttpClient, OutboundRequest, OutboundResponse, OutboundTarget};
use http::HeaderMap;
use url::{Host, Url};

pub use ip::{AddressClass, classify, is_public};
pub use resolver::{
    BlockedDestination, HostResolver, PlainResolver, StaticResolver, SystemResolver,
    VettingResolver, vet_addresses,
};

/// Hard cap of per-request timeout overrides.
const MAX_TIMEOUT: Duration = Duration::from_secs(120);
/// Hard cap of per-request response-size overrides (50 MiB).
const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
/// User agent of every outbound request.
const USER_AGENT: &str = "rust-authentication";

fn not_allowed(reason: &'static str) -> AuthError {
    AuthError::new(codes::protect::OUTBOUND_DESTINATION_NOT_ALLOWED).with_context(reason)
}

/// Syntactic and address checks of a user-supplied URL that need no DNS:
/// scheme (`https`, or `http` only under the development switch), no
/// credentials, a host, no port 0, and — for IP literals — a public address.
/// Callers storing a URL (webhook endpoints) should run this at save time
/// too, and again (with DNS) on every delivery via [`SsrfSafeHttpClient`].
pub fn validate_user_supplied_url(url: &Url, allow_private: bool) -> Result<(), AuthError> {
    match url.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => return Err(not_allowed("user-supplied URL must use https")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(not_allowed("user-supplied URL must not carry credentials"));
    }
    if url.port() == Some(0) {
        return Err(not_allowed("port 0"));
    }
    let ip = match url.host() {
        None => return Err(not_allowed("URL without host")),
        Some(Host::Domain(domain)) => {
            if domain.is_empty() || domain.len() > 253 {
                return Err(not_allowed("invalid host name"));
            }
            return Ok(());
        }
        Some(Host::Ipv4(v4)) => std::net::IpAddr::V4(v4),
        Some(Host::Ipv6(v6)) => std::net::IpAddr::V6(v6),
    };
    vet_addresses(&[ip], allow_private).map_err(|_| not_allowed("IP literal is not public"))
}

/// The SSRF-safe [`HttpClient`]. Cheap to clone.
#[derive(Clone)]
pub struct SsrfSafeHttpClient {
    trusted: reqwest::Client,
    user_supplied: reqwest::Client,
    config: OutboundHttpConfig,
}

impl std::fmt::Debug for SsrfSafeHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsrfSafeHttpClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SsrfSafeHttpClient {
    /// A client using the system DNS configuration.
    pub fn new(config: &OutboundHttpConfig) -> Result<Self, AuthError> {
        Self::with_resolver(config, Arc::new(SystemResolver::new()))
    }

    /// A client using `resolver` for every name lookup (tests, air-gapped
    /// deployments).
    pub fn with_resolver(
        config: &OutboundHttpConfig,
        resolver: Arc<dyn HostResolver>,
    ) -> Result<Self, AuthError> {
        authn_core::tls::install_crypto_provider();
        let base = || {
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .referer(false)
                .connect_timeout(config.connect_timeout)
                .timeout(config.timeout)
                .pool_idle_timeout(Duration::from_secs(30))
                .user_agent(USER_AGENT)
        };
        let trusted = base()
            .dns_resolver(Arc::new(PlainResolver(resolver.clone())))
            .build()
            .map_err(|e| AuthError::internal("building trusted HTTP client").with_source(e))?;
        let user_supplied = base()
            .https_only(!config.allow_private_networks)
            .dns_resolver(Arc::new(VettingResolver::new(
                resolver,
                config.allow_private_networks,
            )))
            .build()
            .map_err(|e| AuthError::internal("building SSRF-safe HTTP client").with_source(e))?;
        Ok(Self {
            trusted,
            user_supplied,
            config: *config,
        })
    }

    fn check_url(&self, request: &OutboundRequest) -> Result<(), AuthError> {
        match request.target {
            OutboundTarget::UserSupplied => {
                validate_user_supplied_url(&request.url, self.config.allow_private_networks)
            }
            OutboundTarget::Trusted => {
                if matches!(request.url.scheme(), "http" | "https") && request.url.host().is_some()
                {
                    Ok(())
                } else {
                    Err(AuthError::internal(
                        "trusted outbound URL must be absolute http(s)",
                    ))
                }
            }
        }
    }
}

fn chain_has_blocked(err: &reqwest::Error) -> bool {
    let mut source = err.source();
    let mut depth = 0;
    while let Some(e) = source {
        if e.downcast_ref::<BlockedDestination>().is_some() {
            return true;
        }
        depth += 1;
        if depth > 16 {
            break;
        }
        source = e.source();
    }
    false
}

fn map_send_error(err: reqwest::Error, host: &str) -> AuthError {
    if chain_has_blocked(&err) {
        tracing::warn!(host, "outbound request to a non-public address refused");
        return not_allowed("resolved address is not public");
    }
    let context = if err.is_timeout() {
        "outbound request timed out"
    } else if err.is_connect() {
        "outbound connection failed"
    } else {
        "outbound request failed"
    };
    tracing::warn!(host, "{context}");
    AuthError::new(codes::common::SERVICE_UNAVAILABLE)
        .with_context(context)
        .with_source(err.without_url())
}

#[async_trait]
impl HttpClient for SsrfSafeHttpClient {
    async fn execute(&self, request: OutboundRequest) -> Result<OutboundResponse, AuthError> {
        self.check_url(&request)?;
        let host = request.url.host_str().unwrap_or_default().to_owned();
        let client = match request.target {
            OutboundTarget::Trusted => &self.trusted,
            OutboundTarget::UserSupplied => &self.user_supplied,
        };
        let limit = request
            .max_response_bytes
            .unwrap_or(self.config.max_response_bytes)
            .min(MAX_RESPONSE_BYTES);
        let timeout = request
            .timeout
            .unwrap_or(self.config.timeout)
            .min(MAX_TIMEOUT);

        let mut headers = request.headers;
        headers.remove(http::header::HOST);
        let mut builder = client
            .request(request.method, request.url)
            .headers(headers)
            .timeout(timeout);
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await.map_err(|e| map_send_error(e, &host))?;

        if response
            .content_length()
            .is_some_and(|len| len > u64::try_from(limit).unwrap_or(u64::MAX))
        {
            return Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("outbound response exceeds the size limit"));
        }
        let status = response.status();
        let mut response_headers = HeaderMap::new();
        for (name, value) in response.headers() {
            response_headers.append(name.clone(), value.clone());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| map_send_error(e, &host))?
        {
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                    .with_context("outbound response exceeds the size limit"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(OutboundResponse {
            status,
            headers: response_headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn prt_12_user_supplied_urls_must_be_https_public_and_credential_free() {
        assert!(validate_user_supplied_url(&url("https://hooks.example.com/x?y=1"), false).is_ok());
        assert!(validate_user_supplied_url(&url("https://8.8.8.8/x"), false).is_ok());
        assert!(validate_user_supplied_url(&url("https://[2606:4700::1]/x"), false).is_ok());
        for bad in [
            "http://hooks.example.com/x",
            "ftp://hooks.example.com/x",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_",
            "https://user:pw@hooks.example.com/",
            "https://user@hooks.example.com/",
            "https://127.0.0.1/",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://0177.0.0.1/",
            "https://127.1/",
            "https://0/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:a9fe:a9fe]/",
            "https://[fd00:ec2::254]/",
            "https://[fe80::1]/",
            "https://[64:ff9b::a00:1]/",
            "https://10.0.0.1:443/",
            "https://100.100.100.200/",
            "https://168.63.129.16/",
            "https://hooks.example.com:0/",
        ] {
            let err = validate_user_supplied_url(&url(bad), false).unwrap_err();
            assert_eq!(
                err.code(),
                codes::protect::OUTBOUND_DESTINATION_NOT_ALLOWED,
                "{bad}"
            );
        }
        // The development switch relaxes only scheme and address checks.
        assert!(validate_user_supplied_url(&url("http://127.0.0.1:8080/"), true).is_ok());
        assert!(validate_user_supplied_url(&url("https://u:p@127.0.0.1/"), true).is_err());
    }

    #[test]
    fn prt_12_client_debug_does_not_leak() {
        let client = SsrfSafeHttpClient::with_resolver(
            &OutboundHttpConfig::default(),
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("SsrfSafeHttpClient"));
    }
}
