//! `[server]` — HTTP server, environment, proxies, logging (owner:
//! authn-server; the PRT-06 settings are consumed by the authn-core request
//! context middleware).
//!
//! `public_base_url` is the only required key: it is security relevant
//! (every e-mailed link is built from it, NTF-02 / PWD-08) and has no safe
//! default.

use std::net::SocketAddr;
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

use super::common::{ConfigProblems, Environment, secs};
use crate::domain::Locale;
use crate::http::{ClientIpHeader, RequestContextConfig};

text_enum! {
    /// Log output format (OPS-03).
    #[derive(Default)]
    pub enum LogFormat {
        /// Structured JSON lines (default).
        #[default]
        Json => "json",
        /// Human-readable (development).
        Pretty => "pretty",
    }
}

/// Request limits (PRT-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestLimitsConfig {
    /// Maximum request body. Default 64 KiB.
    pub body_limit_bytes: usize,
    /// Request timeout. Default `30s`.
    #[serde(with = "super::duration")]
    pub request_timeout: Duration,
    /// Concurrent in-flight requests per instance. Default 1024.
    pub max_concurrent_requests: usize,
}

impl Default for RequestLimitsConfig {
    fn default() -> Self {
        Self {
            body_limit_bytes: 64 * 1024,
            request_timeout: secs(30),
            max_concurrent_requests: 1024,
        }
    }
}

mod defaults {
    use std::net::SocketAddr;
    use std::time::Duration;

    pub(super) fn bind_addr() -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 8080))
    }
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn metrics_bind_addr() -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], 9090)))
    }
    pub(super) const fn yes() -> bool {
        true
    }
    pub(super) const fn shutdown_grace_period() -> Duration {
        Duration::from_secs(30)
    }
    pub(super) fn log_filter() -> String {
        "info".to_owned()
    }
}

/// `[server]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Deployment environment. Default `production` (strictest).
    #[serde(default)]
    pub environment: Environment,
    /// Public API listener. Default `0.0.0.0:8080`.
    #[serde(default = "defaults::bind_addr")]
    pub bind_addr: SocketAddr,
    /// Prometheus metrics listener (OPS-04), separate port. Default
    /// `127.0.0.1:9090`.
    #[serde(default = "defaults::metrics_bind_addr")]
    pub metrics_bind_addr: Option<SocketAddr>,
    /// **Required.** The only base URL used to build links (NTF-02, PWD-08);
    /// also the default JWT issuer. Must be `https` in production.
    pub public_base_url: Url,
    /// CIDRs of reverse proxies allowed to set forwarding headers (PRT-06).
    /// Default: none (forwarding headers ignored).
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    /// Forwarding header maintained by the trusted proxies. Default
    /// `x-forwarded-for`.
    #[serde(default)]
    pub client_ip_header: ClientIpHeader,
    /// Locale when `Accept-Language` matches nothing supported. Default `en`.
    #[serde(default)]
    pub default_locale: Locale,
    /// Serve `GET /openapi.json` (OPS-09). Default `true`.
    #[serde(default = "defaults::yes")]
    pub openapi_enabled: bool,
    /// Graceful shutdown deadline (OPS-07). Default `30s`.
    #[serde(default = "defaults::shutdown_grace_period", with = "super::duration")]
    pub shutdown_grace_period: Duration,
    /// Log format. Default `json`.
    #[serde(default)]
    pub log_format: LogFormat,
    /// `tracing` filter directive. Default `info`.
    #[serde(default = "defaults::log_filter")]
    pub log_filter: String,
    /// Request limits (PRT-11).
    #[serde(default)]
    pub limits: RequestLimitsConfig,
}

impl ServerConfig {
    /// A configuration with every default and the given base URL.
    #[must_use]
    pub fn with_public_base_url(public_base_url: Url) -> Self {
        Self {
            environment: Environment::default(),
            bind_addr: defaults::bind_addr(),
            metrics_bind_addr: defaults::metrics_bind_addr(),
            public_base_url,
            trusted_proxies: Vec::new(),
            client_ip_header: ClientIpHeader::default(),
            default_locale: Locale::default(),
            openapi_enabled: true,
            shutdown_grace_period: defaults::shutdown_grace_period(),
            log_format: LogFormat::default(),
            log_filter: defaults::log_filter(),
            limits: RequestLimitsConfig::default(),
        }
    }

    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        let url = &self.public_base_url;
        p.require(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "server.public_base_url",
            "must be an absolute http(s) URL",
        );
        p.require(
            url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none(),
            "server.public_base_url",
            "must not contain credentials, query or fragment",
        );
        p.require(
            self.metrics_bind_addr != Some(self.bind_addr),
            "server.metrics_bind_addr",
            "must differ from bind_addr (OPS-04)",
        );
        p.require_range(
            self.shutdown_grace_period,
            Duration::from_secs(1),
            Duration::from_secs(600),
            "server.shutdown_grace_period",
        );
        p.require(
            !self.log_filter.trim().is_empty(),
            "server.log_filter",
            "must not be empty",
        );
        let l = &self.limits;
        p.require(
            (1024..=10 * 1024 * 1024).contains(&l.body_limit_bytes),
            "server.limits.body_limit_bytes",
            "must be between 1 KiB and 10 MiB",
        );
        p.require_range(
            l.request_timeout,
            Duration::from_secs(1),
            Duration::from_secs(300),
            "server.limits.request_timeout",
        );
        p.require(
            l.max_concurrent_requests >= 1,
            "server.limits.max_concurrent_requests",
            "must be >= 1",
        );
    }

    /// The request-context middleware configuration derived from this
    /// section.
    #[must_use]
    pub fn request_context(&self) -> RequestContextConfig {
        RequestContextConfig {
            trusted_proxies: self.trusted_proxies.clone(),
            client_ip_header: self.client_ip_header,
            default_locale: self.default_locale,
        }
    }
}
