//! Strict CORS (PRT-08).
//!
//! * Only origins on the explicit allow-list (`protect.cors.allowed_origins`,
//!   normalised to their ASCII serialisation) are answered, by **exact**
//!   byte comparison with the `Origin` header. Never `*`, never an echo of
//!   an arbitrary origin, never `null`.
//! * Credentials are allowed only together with an allow-listed origin.
//! * Preflights are answered here (204) and never reach handlers; a
//!   preflight from another origin, or asking for a method / header outside
//!   the fixed lists, gets `403 cors_origin_not_allowed`.
//! * `Access-Control-Max-Age` is bounded by configuration (≤ 2 h).
//! * `Vary: Origin` is added to every response so caches never serve one
//!   origin's CORS answer to another.
//!
//! CORS is not CSRF protection: same-origin and non-browser requests pass
//! through untouched; CSRF is enforced by authn-session (SES-04).

use std::sync::Arc;

use authn_core::config::protect::CorsConfig;
use authn_core::error::{AuthError, codes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use http::{HeaderValue, Method, StatusCode};

/// Methods allowed cross-origin.
pub const ALLOWED_METHODS: &[Method] = &[
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
];

/// Request headers allowed cross-origin (lowercase).
pub const ALLOWED_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "authorization",
    "content-language",
    "content-type",
    "x-csrf-token",
    "x-device-id",
];

/// Response headers readable cross-origin.
pub const EXPOSED_HEADERS: &str = "x-request-id, retry-after";

/// Allow-list and precomputed headers (state of [`cors`]).
#[derive(Debug, Clone)]
pub struct CorsPolicy {
    origins: Arc<[String]>,
    max_age: HeaderValue,
    methods: HeaderValue,
    headers: HeaderValue,
}

fn normalize_origin(origin: &str) -> Result<String, AuthError> {
    let url = url::Url::parse(origin)
        .map_err(|_| AuthError::internal("protect.cors.allowed_origins: invalid origin"))?;
    let serialized = url.origin().ascii_serialization();
    if serialized == "null" || !matches!(url.scheme(), "http" | "https") {
        return Err(AuthError::internal(
            "protect.cors.allowed_origins: only http(s) origins are allowed",
        ));
    }
    Ok(serialized)
}

impl CorsPolicy {
    /// Builds the policy from `[protect.cors]`.
    pub fn from_config(config: &CorsConfig) -> Result<Self, AuthError> {
        let origins = config
            .allowed_origins
            .iter()
            .map(|o| normalize_origin(o))
            .collect::<Result<Vec<_>, _>>()?;
        let methods = ALLOWED_METHODS
            .iter()
            .map(Method::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self {
            origins: Arc::from(origins),
            max_age: HeaderValue::from(config.max_age.as_secs()),
            methods: HeaderValue::from_str(&methods)
                .map_err(|_| AuthError::internal("cors methods"))?,
            headers: HeaderValue::from_str(&ALLOWED_HEADERS.join(", "))
                .map_err(|_| AuthError::internal("cors headers"))?,
        })
    }

    /// Whether any origin is allowed (otherwise the layer is a no-op and
    /// need not be installed).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.origins.is_empty()
    }

    /// The allow-listed origin equal to `origin`, if any.
    fn matching(&self, origin: &HeaderValue) -> Option<HeaderValue> {
        let origin = origin.to_str().ok()?;
        self.origins
            .iter()
            .find(|allowed| allowed.as_str() == origin)
            .and_then(|allowed| HeaderValue::from_str(allowed).ok())
    }
}

fn single_origin(request: &Request) -> Option<HeaderValue> {
    let mut values = request.headers().get_all(ORIGIN).iter();
    let first = values.next()?.clone();
    values.next().is_none().then_some(first)
}

fn preflight_allowed(request: &Request) -> bool {
    let method_ok = request
        .headers()
        .get(ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| v.to_str().ok())
        .and_then(|m| Method::from_bytes(m.as_bytes()).ok())
        .is_some_and(|m| ALLOWED_METHODS.contains(&m));
    let headers_ok = request
        .headers()
        .get_all(ACCESS_CONTROL_REQUEST_HEADERS)
        .iter()
        .all(|value| {
            value.to_str().is_ok_and(|list| {
                list.split(',')
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .all(|h| ALLOWED_HEADERS.contains(&h.as_str()))
            })
        });
    method_ok && headers_ok
}

fn strip_cors_headers(response: &mut Response) {
    let headers = response.headers_mut();
    for name in [
        ACCESS_CONTROL_ALLOW_ORIGIN,
        ACCESS_CONTROL_ALLOW_CREDENTIALS,
        ACCESS_CONTROL_ALLOW_METHODS,
        ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ACCESS_CONTROL_MAX_AGE,
    ] {
        headers.remove(name);
    }
}

/// The middleware. Install with
/// `axum::middleware::from_fn_with_state(CorsPolicy::from_config(..)?, cors)`.
pub async fn cors(State(policy): State<CorsPolicy>, request: Request, next: Next) -> Response {
    if !policy.is_enabled() {
        return next.run(request).await;
    }
    let allowed_origin = single_origin(&request).and_then(|o| policy.matching(&o));
    let is_preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(ACCESS_CONTROL_REQUEST_METHOD);

    if is_preflight {
        let mut response = match allowed_origin {
            Some(origin) if preflight_allowed(&request) => {
                let mut response = StatusCode::NO_CONTENT.into_response();
                let headers = response.headers_mut();
                headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                headers.insert(
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
                headers.insert(ACCESS_CONTROL_ALLOW_METHODS, policy.methods.clone());
                headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, policy.headers.clone());
                headers.insert(ACCESS_CONTROL_MAX_AGE, policy.max_age.clone());
                response
            }
            _ => AuthError::new(codes::protect::CORS_ORIGIN_NOT_ALLOWED).into_response(),
        };
        response.headers_mut().append(
            VARY,
            HeaderValue::from_static(
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            ),
        );
        return response;
    }

    let mut response = next.run(request).await;
    strip_cors_headers(&mut response);
    let headers = response.headers_mut();
    headers.append(VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = allowed_origin {
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(EXPOSED_HEADERS),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use authn_testkit::http::{TestRequest, with_request_context};
    use axum::Router;
    use axum::routing::{get, post};

    use super::*;

    fn app() -> Router {
        let config = CorsConfig {
            allowed_origins: vec![
                "https://app.example.com".to_owned(),
                "https://Admin.Example.com:8443".to_owned(),
            ],
            max_age: Duration::from_secs(600),
        };
        let router = Router::new()
            .route("/v1/me", get(|| async { "me" }))
            .route(
                "/v1/evil",
                get(|| async { ([(ACCESS_CONTROL_ALLOW_ORIGIN, "*")], "x") }),
            )
            .route("/v1/login", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                CorsPolicy::from_config(&config).unwrap(),
                cors,
            ));
        with_request_context(router)
    }

    #[tokio::test]
    async fn prt_08_allow_listed_origin_gets_exact_credentialed_cors() {
        let app = app();
        let res = TestRequest::get("/v1/me")
            .header("origin", "https://app.example.com")
            .send(&app)
            .await;
        res.assert_status(StatusCode::OK);
        assert_eq!(
            res.header("access-control-allow-origin"),
            Some("https://app.example.com")
        );
        assert_eq!(res.header("access-control-allow-credentials"), Some("true"));
        assert_eq!(
            res.header("access-control-expose-headers"),
            Some("x-request-id, retry-after")
        );
        assert_eq!(res.header("vary"), Some("Origin"));
        // Configured origins are normalised (case, default port).
        let res = TestRequest::get("/v1/me")
            .header("origin", "https://admin.example.com:8443")
            .send(&app)
            .await;
        assert_eq!(
            res.header("access-control-allow-origin"),
            Some("https://admin.example.com:8443")
        );
    }

    #[tokio::test]
    async fn prt_08_other_origins_are_never_reflected_or_wildcarded() {
        let app = app();
        for origin in [
            "https://evil.example",
            "null",
            "https://app.example.com.evil.example",
            "https://evil-app.example.com",
            "http://app.example.com",
            "https://app.example.com:444",
            "https://APP.example.com",
            "https://app.example.com/",
            "*",
        ] {
            let res = TestRequest::get("/v1/me")
                .header("origin", origin)
                .send(&app)
                .await;
            res.assert_status(StatusCode::OK);
            assert_eq!(res.header("access-control-allow-origin"), None, "{origin}");
            assert_eq!(res.header("access-control-allow-credentials"), None);
            assert_eq!(res.header("vary"), Some("Origin"));
        }
        // A handler cannot sneak in a wildcard.
        let res = TestRequest::get("/v1/evil")
            .header("origin", "https://evil.example")
            .send(&app)
            .await;
        assert_eq!(res.header("access-control-allow-origin"), None);
        let res = TestRequest::get("/v1/evil")
            .header("origin", "https://app.example.com")
            .send(&app)
            .await;
        assert_eq!(
            res.header("access-control-allow-origin"),
            Some("https://app.example.com")
        );
        // Duplicate Origin headers are ambiguous → no CORS.
        let res = TestRequest::get("/v1/me")
            .header("origin", "https://app.example.com")
            .header("origin", "https://evil.example")
            .send(&app)
            .await;
        assert_eq!(res.header("access-control-allow-origin"), None);
    }

    #[tokio::test]
    async fn prt_08_preflight_is_strict_and_cache_bounded() {
        let app = app();
        let res = TestRequest::new(Method::OPTIONS, "/v1/login")
            .header("origin", "https://app.example.com")
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "Content-Type, X-CSRF-Token",
            )
            .send(&app)
            .await;
        res.assert_status(StatusCode::NO_CONTENT);
        assert_eq!(
            res.header("access-control-allow-origin"),
            Some("https://app.example.com")
        );
        assert_eq!(res.header("access-control-allow-credentials"), Some("true"));
        assert_eq!(res.header("access-control-max-age"), Some("600"));
        assert!(
            res.header("access-control-allow-methods")
                .unwrap()
                .contains("POST")
        );
        assert!(
            !res.header("access-control-allow-headers")
                .unwrap()
                .contains('*')
        );

        for (origin, method, headers) in [
            ("https://evil.example", "POST", "content-type"),
            ("https://app.example.com", "TRACE", "content-type"),
            ("https://app.example.com", "POST", "x-evil-header"),
            ("null", "GET", ""),
        ] {
            let res = TestRequest::new(Method::OPTIONS, "/v1/login")
                .header("origin", origin)
                .header("access-control-request-method", method)
                .header("access-control-request-headers", headers)
                .send(&app)
                .await;
            res.assert_error(StatusCode::FORBIDDEN, "cors_origin_not_allowed");
            assert_eq!(res.header("access-control-allow-origin"), None);
        }
    }

    #[test]
    fn prt_08_wildcard_or_null_origins_are_refused_at_start_up() {
        for bad in ["*", "null", "file:///x", "not a url"] {
            let config = CorsConfig {
                allowed_origins: vec![bad.to_owned()],
                max_age: Duration::from_secs(60),
            };
            assert!(CorsPolicy::from_config(&config).is_err(), "{bad}");
        }
        assert!(
            !CorsPolicy::from_config(&CorsConfig::default())
                .unwrap()
                .is_enabled()
        );
    }
}
