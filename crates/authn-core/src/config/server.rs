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
    /// `127.0.0.1:9090`; `"off"` (or `""`) disables the listener (K-109).
    /// Never expose it publicly.
    #[serde(
        default = "defaults::metrics_bind_addr",
        deserialize_with = "deserialize_metrics_bind_addr"
    )]
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
    /// Origins of an admin console served from another origin (ADM-04,
    /// K-12, K-67). Only these origins may send the
    /// `x-impersonation-session` header cross-origin; each must also be in
    /// `protect.cors.allowed_origins`. Default: none (the header is never
    /// allowed cross-origin; a same-origin console needs no entry).
    #[serde(default)]
    pub admin_console_origins: Vec<String>,
}

/// Values of `server.metrics_bind_addr` that disable the listener (K-109).
pub const METRICS_DISABLED: &[&str] = &["off", ""];

/// `server.metrics_bind_addr`: a socket address, or `"off"` / `""` for no
/// listener (TOML has no null, and `AUTHN__SERVER__METRICS_BIND_ADDR` is a
/// string as well).
fn deserialize_metrics_bind_addr<'de, D>(deserializer: D) -> Result<Option<SocketAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    let text = text.trim();
    if METRICS_DISABLED
        .iter()
        .any(|off| text.eq_ignore_ascii_case(off))
    {
        return Ok(None);
    }
    text.parse::<SocketAddr>().map(Some).map_err(|_| {
        serde::de::Error::custom("expected a socket address (e.g. \"127.0.0.1:9090\") or \"off\"")
    })
}

/// Whether `value` is exactly an http(s) origin (`scheme://host[:port]`,
/// optionally with a trailing `/`).
fn is_origin(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
    })
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
            admin_console_origins: Vec::new(),
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
        // K-57 (PRT-06): a catch-all entry trusts every peer and every
        // forwarding hop; the client IP would be whatever the client writes
        // into the forwarding header (rate limits, risk, audit and
        // organization IP allow-lists all depend on it). Near-catch-alls
        // (`0.0.0.0/1` + `128.0.0.0/1`, `2000::/3`…) are refused as well.
        for (i, net) in self.trusted_proxies.iter().enumerate() {
            p.require(
                !is_overly_broad_proxy_range(net),
                &format!("server.trusted_proxies[{i}]"),
                "is too broad (IPv4 shorter than /8 or public IPv6 shorter than /16): \
                 the client IP would be spoofable",
            );
        }
        for origin in &self.admin_console_origins {
            p.require(
                is_origin(origin),
                "server.admin_console_origins",
                "must be http(s) origins (scheme://host[:port], no path)",
            );
        }
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

/// Whether a `trusted_proxies` entry covers far more than any proxy
/// deployment (K-57, PRT-06): an IPv4 network shorter than `/8` (no private
/// range is larger; published load-balancer and CDN ranges are far
/// narrower) or an IPv6 network shorter than `/16` outside the private
/// ranges `fc00::/7` (unique local) and `fe80::/10` (link-local). Splitting
/// the address space (`0.0.0.0/1` + `128.0.0.0/1`) is caught entry by entry.
fn is_overly_broad_proxy_range(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.prefix_len() < 8,
        IpNet::V6(v6) => {
            let private = |range: &str| {
                range
                    .parse::<ipnet::Ipv6Net>()
                    .is_ok_and(|range| range.contains(v6))
            };
            v6.prefix_len() < 16 && !private("fc00::/7") && !private("fe80::/10")
        }
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)] // figment's error type (test-only)
mod tests {
    use figment::Figment;
    use figment::providers::{Env, Format, Toml};

    use super::*;

    fn parse(extra: &str) -> Result<ServerConfig, figment::Error> {
        Figment::new()
            .merge(Toml::string(&format!(
                "public_base_url = \"https://auth.example.com\"\n{extra}"
            )))
            .extract()
    }

    #[test]
    fn k_109_metrics_listener_defaults_to_loopback() {
        let config = parse("").unwrap();
        assert_eq!(
            config.metrics_bind_addr,
            Some(SocketAddr::from(([127, 0, 0, 1], 9090)))
        );
    }

    #[test]
    fn k_109_metrics_listener_can_be_disabled_from_toml() {
        for value in ["off", "OFF", "", " off "] {
            let config = parse(&format!("metrics_bind_addr = \"{value}\"")).unwrap();
            assert_eq!(config.metrics_bind_addr, None, "{value:?}");
        }
        let config = parse("metrics_bind_addr = \"0.0.0.0:9090\"").unwrap();
        assert_eq!(
            config.metrics_bind_addr,
            Some(SocketAddr::from(([0, 0, 0, 0], 9090)))
        );
        for bad in ["localhost", "9090", "on", "0.0.0.0"] {
            assert!(
                parse(&format!("metrics_bind_addr = \"{bad}\"")).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn k_109_metrics_listener_can_be_set_or_disabled_from_the_environment() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("K109__METRICS_BIND_ADDR", "off");
            let config: ServerConfig = Figment::new()
                .merge(Toml::string(
                    "public_base_url = \"https://auth.example.com\"",
                ))
                .merge(Env::prefixed("K109__"))
                .extract()?;
            assert_eq!(config.metrics_bind_addr, None);
            jail.set_env("K109__METRICS_BIND_ADDR", "0.0.0.0:9090");
            let config: ServerConfig = Figment::new()
                .merge(Toml::string(
                    "public_base_url = \"https://auth.example.com\"",
                ))
                .merge(Env::prefixed("K109__"))
                .extract()?;
            assert_eq!(
                config.metrics_bind_addr,
                Some(SocketAddr::from(([0, 0, 0, 0], 9090)))
            );
            Ok(())
        });
    }
}
