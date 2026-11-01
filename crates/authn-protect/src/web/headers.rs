//! Security response headers (PRT-07).
//!
//! | Header | Value | Overridable by the handler |
//! |--------|-------|----------------------------|
//! | `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (+ `; preload`) | no |
//! | `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | yes |
//! | `X-Content-Type-Options` | `nosniff` | no |
//! | `Referrer-Policy` | `no-referrer` | no |
//! | `Cross-Origin-Opener-Policy` | `same-origin` | no |
//! | `Cross-Origin-Resource-Policy` | `same-site` | yes |
//! | `Permissions-Policy` | `protect.security_headers.permissions_policy` | no |
//! | `Cache-Control` | `no-store` | yes (e.g. JWKS sets its own caching) |
//!
//! `Cache-Control: no-store` is the default for *every* response, so auth
//! responses (tokens, sessions, errors) are never cached by browsers or
//! intermediaries unless a handler opts in explicitly.

use authn_core::config::protect::SecurityHeadersConfig;
use authn_core::error::AuthError;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderName, HeaderValue};

/// `Content-Security-Policy` of API responses.
pub const CSP: &str = "default-src 'none'; frame-ancestors 'none'";

const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

/// Precomputed header values (state of [`security_headers`]).
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    hsts: HeaderValue,
    permissions_policy: HeaderValue,
}

impl SecurityHeaders {
    /// Builds the values from `[protect.security_headers]`; fails fast on a
    /// `permissions_policy` that is not a valid header value.
    pub fn from_config(config: &SecurityHeadersConfig) -> Result<Self, AuthError> {
        let mut hsts = format!("max-age={}", config.hsts_max_age.as_secs());
        if config.hsts_include_subdomains {
            hsts.push_str("; includeSubDomains");
        }
        if config.hsts_preload {
            hsts.push_str("; preload");
        }
        let hsts = HeaderValue::from_str(&hsts)
            .map_err(|_| AuthError::internal("invalid HSTS header value"))?;
        let permissions_policy =
            HeaderValue::from_str(&config.permissions_policy).map_err(|_| {
                AuthError::internal(
                    "protect.security_headers.permissions_policy is not a valid header value",
                )
            })?;
        Ok(Self {
            hsts,
            permissions_policy,
        })
    }
}

/// The middleware. Install with
/// `axum::middleware::from_fn_with_state(SecurityHeaders::from_config(..)?, security_headers)`.
pub async fn security_headers(
    State(values): State<SecurityHeaders>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(STRICT_TRANSPORT_SECURITY, values.hsts.clone());
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(COOP, HeaderValue::from_static("same-origin"));
    headers.insert(PERMISSIONS_POLICY, values.permissions_policy.clone());
    if !headers.contains_key(CONTENT_SECURITY_POLICY) {
        headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    }
    if !headers.contains_key(&CORP) {
        headers.insert(CORP, HeaderValue::from_static("same-site"));
    }
    if !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use authn_testkit::http::{TestRequest, with_request_context};
    use axum::Router;
    use axum::routing::get;
    use http::StatusCode;

    use super::*;

    fn app(config: &SecurityHeadersConfig) -> Router {
        let router = Router::new()
            .route("/v1/thing", get(|| async { "ok" }))
            .route(
                "/.well-known/jwks.json",
                get(|| async { ([(CACHE_CONTROL, "public, max-age=3600")], "{}") }),
            )
            .route(
                "/v1/fail",
                get(|| async { AuthError::new(authn_core::error::codes::common::FORBIDDEN) }),
            )
            .layer(axum::middleware::from_fn_with_state(
                SecurityHeaders::from_config(config).unwrap(),
                security_headers,
            ));
        with_request_context(router)
    }

    #[tokio::test]
    async fn prt_07_security_headers_have_the_specified_values() {
        let app = app(&SecurityHeadersConfig::default());
        for path in ["/v1/thing", "/v1/fail", "/nope"] {
            let res = TestRequest::get(path).send(&app).await;
            assert_eq!(
                res.header("strict-transport-security"),
                Some("max-age=63072000; includeSubDomains"),
                "{path}"
            );
            assert_eq!(
                res.header("content-security-policy"),
                Some("default-src 'none'; frame-ancestors 'none'")
            );
            assert_eq!(res.header("x-content-type-options"), Some("nosniff"));
            assert_eq!(res.header("referrer-policy"), Some("no-referrer"));
            assert_eq!(
                res.header("cross-origin-opener-policy"),
                Some("same-origin")
            );
            assert_eq!(
                res.header("cross-origin-resource-policy"),
                Some("same-site")
            );
            assert_eq!(
                res.header("permissions-policy"),
                Some(
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()"
                )
            );
            assert_eq!(res.header("cache-control"), Some("no-store"), "{path}");
        }
        let res = TestRequest::get("/v1/fail").send(&app).await;
        res.assert_error(StatusCode::FORBIDDEN, "forbidden");
    }

    #[tokio::test]
    async fn prt_07_hsts_preload_and_handler_cache_policy() {
        let config = SecurityHeadersConfig {
            hsts_max_age: Duration::from_secs(31_536_000),
            hsts_include_subdomains: false,
            hsts_preload: true,
            ..SecurityHeadersConfig::default()
        };
        let app = app(&config);
        let res = TestRequest::get("/.well-known/jwks.json").send(&app).await;
        assert_eq!(
            res.header("strict-transport-security"),
            Some("max-age=31536000; preload")
        );
        assert_eq!(res.header("cache-control"), Some("public, max-age=3600"));
    }

    #[test]
    fn prt_07_invalid_permissions_policy_fails_fast() {
        let config = SecurityHeadersConfig {
            permissions_policy: "camera=()\r\nSet-Cookie: x=1".to_owned(),
            ..SecurityHeadersConfig::default()
        };
        assert!(SecurityHeaders::from_config(&config).is_err());
    }
}
