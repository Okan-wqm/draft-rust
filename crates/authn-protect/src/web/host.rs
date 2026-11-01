//! `Host` header validation (PRT-09).
//!
//! Only the configured hosts (`protect.allowed_hosts`, default: the host of
//! `server.public_base_url`) are served; anything else is answered with
//! `421 host_not_allowed` before routing. Both the `Host` header and the
//! request-target authority (absolute-form / HTTP/2 `:authority`) are
//! checked; a request carrying several `Host` headers or none at all is
//! refused. Parsing is strict ASCII — no userinfo, no percent-encoding, no
//! IDNA or numeric-IP normalisation tricks. `/health/…` is exempt by
//! default so load-balancer probes addressed by IP keep working (those
//! responses never contain URLs).
//!
//! Links are never built from the `Host` header anyway (NTF-02, PWD-08);
//! this layer stops cache poisoning and virtual-host confusion.

use std::sync::Arc;

use authn_core::config::protect::ProtectConfig;
use authn_core::error::{AuthError, codes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::HOST;
use url::Url;

/// A parsed `host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Authority {
    host: String,
    port: Option<u16>,
}

fn parse_authority(raw: &str) -> Option<Authority> {
    if raw.is_empty() || raw.len() > 261 || !raw.is_ascii() {
        return None;
    }
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return None;
        }
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (format!("[{}]", inner.to_ascii_lowercase()), port)
    } else {
        let (host, port) = match raw.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (raw, None),
        };
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.is_empty()
            || host.len() > 253
            || host.starts_with('.')
            || host.contains("..")
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return None;
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(p.parse::<u16>().ok()?)
        }
    };
    Some(Authority { host, port })
}

/// Allowed hosts (state of [`validate_host`]).
#[derive(Debug, Clone)]
pub struct HostValidation {
    allowed: Arc<[Authority]>,
    exempt_prefixes: Arc<[String]>,
}

impl HostValidation {
    /// From `protect.allowed_hosts`, defaulting to the host (and explicit
    /// port) of `public_base_url`.
    pub fn from_config(config: &ProtectConfig, public_base_url: &Url) -> Result<Self, AuthError> {
        if config.allowed_hosts.is_empty() {
            let host = public_base_url
                .host_str()
                .ok_or_else(|| AuthError::internal("server.public_base_url has no host"))?;
            let entry = match public_base_url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            };
            Self::new(&[entry])
        } else {
            Self::new(&config.allowed_hosts)
        }
    }

    /// From explicit `host` / `host:port` entries.
    pub fn new(hosts: &[String]) -> Result<Self, AuthError> {
        let allowed = hosts
            .iter()
            .map(|h| {
                parse_authority(h).ok_or_else(|| {
                    AuthError::internal("protect.allowed_hosts contains an invalid entry")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if allowed.is_empty() {
            return Err(AuthError::internal("no allowed host configured"));
        }
        Ok(Self {
            allowed: Arc::from(allowed),
            exempt_prefixes: Arc::from(vec!["/health/".to_owned()]),
        })
    }

    /// Replaces the exempt path prefixes (default `/health/`).
    #[must_use]
    pub fn with_exempt_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.exempt_prefixes = Arc::from(prefixes);
        self
    }

    /// Whether a `Host` / authority value is served. An entry without a
    /// port also matches the default ports 80 and 443.
    #[must_use]
    pub fn is_allowed(&self, authority: &str) -> bool {
        let Some(requested) = parse_authority(authority) else {
            return false;
        };
        self.allowed.iter().any(|entry| {
            entry.host == requested.host
                && match (entry.port, requested.port) {
                    (Some(a), Some(b)) => a == b,
                    (None, None | Some(80 | 443)) => true,
                    (Some(_), None) | (None, Some(_)) => false,
                }
        })
    }

    fn check(&self, request: &Request) -> bool {
        let mut hosts = request.headers().get_all(HOST).iter();
        let host = hosts.next();
        if hosts.next().is_some() {
            return false;
        }
        let host_ok = host.map(|h| h.to_str().is_ok_and(|h| self.is_allowed(h)));
        let authority_ok = request
            .uri()
            .authority()
            .map(|a| self.is_allowed(a.as_str()));
        match (host_ok, authority_ok) {
            (None, None) => false,
            (Some(h), None) => h,
            (None, Some(a)) => a,
            (Some(h), Some(a)) => h && a,
        }
    }
}

/// The middleware. Install with
/// `axum::middleware::from_fn_with_state(HostValidation::from_config(..)?, validate_host)`.
pub async fn validate_host(
    State(validation): State<HostValidation>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if validation
        .exempt_prefixes
        .iter()
        .any(|p| path.starts_with(p.as_str()))
        || validation.check(&request)
    {
        return next.run(request).await;
    }
    tracing::debug!("request for a host that is not served");
    AuthError::new(codes::protect::HOST_NOT_ALLOWED).into_response()
}

#[cfg(test)]
mod tests {
    use authn_testkit::http::{TestRequest, with_request_context};
    use axum::Router;
    use axum::routing::get;
    use http::StatusCode;

    use super::*;

    fn validation() -> HostValidation {
        HostValidation::new(&[
            "auth.example.com".to_owned(),
            "localhost:8080".to_owned(),
            "[2001:db8::1]".to_owned(),
        ])
        .unwrap()
    }

    #[test]
    fn prt_09_host_matching_is_exact_and_strict() {
        let v = validation();
        for ok in [
            "auth.example.com",
            "AUTH.Example.COM",
            "auth.example.com.",
            "auth.example.com:443",
            "auth.example.com:80",
            "localhost:8080",
            "[2001:db8::1]",
            "[2001:DB8::1]:443",
        ] {
            assert!(v.is_allowed(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.com",
            "auth.example.com.evil.com",
            "evil.com#auth.example.com",
            "auth.example.com:8443",
            "auth.example.com:",
            "auth.example.com:+443",
            "auth.example.com:0443x",
            "auth.example.com:99999",
            "localhost",
            "localhost:8081",
            "user@auth.example.com",
            "auth.example.com/path",
            "auth.example.com\\@evil",
            "auth%2eexample.com",
            "auth.example.com ",
            "аuth.example.com",
            "xn--uth-8cd.example.com",
            "auth..example.com",
            "[2001:db8::2]",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(!v.is_allowed(bad), "{bad}");
        }
    }

    fn app(v: HostValidation) -> Router {
        let router = Router::new()
            .route("/v1/thing", get(|| async { "ok" }))
            .route("/health/live", get(|| async { "live" }))
            .layer(axum::middleware::from_fn_with_state(v, validate_host));
        with_request_context(router)
    }

    #[tokio::test]
    async fn prt_09_foreign_host_headers_are_refused_with_421() {
        let app = app(validation());
        TestRequest::get("/v1/thing")
            .header("host", "auth.example.com")
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
        let res = TestRequest::get("/v1/thing")
            .header("host", "evil.example")
            .send(&app)
            .await;
        res.assert_error(StatusCode::MISDIRECTED_REQUEST, "host_not_allowed");
        // Missing Host, duplicated Host, absolute-form with another host.
        TestRequest::get("/v1/thing")
            .send(&app)
            .await
            .assert_error(StatusCode::MISDIRECTED_REQUEST, "host_not_allowed");
        TestRequest::get("/v1/thing")
            .header("host", "auth.example.com")
            .header("host", "evil.example")
            .send(&app)
            .await
            .assert_error(StatusCode::MISDIRECTED_REQUEST, "host_not_allowed");
        TestRequest::get("http://evil.example/v1/thing")
            .header("host", "auth.example.com")
            .send(&app)
            .await
            .assert_error(StatusCode::MISDIRECTED_REQUEST, "host_not_allowed");
        TestRequest::get("http://auth.example.com/v1/thing")
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
        // Probes by IP still reach /health/.
        TestRequest::get("/health/live")
            .header("host", "10.0.0.7:8080")
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
    }

    #[test]
    fn prt_09_default_is_the_public_base_url_host() {
        let base = Url::parse("https://auth.example.com").unwrap();
        let v = HostValidation::from_config(&ProtectConfig::default(), &base).unwrap();
        assert!(v.is_allowed("auth.example.com"));
        assert!(!v.is_allowed("other.example.com"));
        let dev = Url::parse("http://localhost:8080").unwrap();
        let v = HostValidation::from_config(&ProtectConfig::default(), &dev).unwrap();
        assert!(v.is_allowed("localhost:8080"));
        assert!(!v.is_allowed("localhost:9090"));
        assert!(HostValidation::new(&["*.example.com".to_owned()]).is_err());
        assert!(HostValidation::new(&[]).is_err());
    }
}
