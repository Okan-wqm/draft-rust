//! HTTP test helpers: build a request, send it through a `Router` with
//! `tower::ServiceExt::oneshot`, inspect the response and the error
//! envelope.
//!
//! ```ignore
//! let app = authn_testkit::http::with_request_context(my_crate::router().with_state(state));
//! let res = TestRequest::post("/v1/password/reset").json(&json!({"email": "a@b.co"})).send(&app).await;
//! res.assert_status(StatusCode::ACCEPTED);
//! let res = TestRequest::get("/v1/me").send(&app).await;
//! res.assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use authn_core::error::ErrorBody;
use authn_core::error::ErrorEnvelope;
use authn_core::http::{RequestContextConfig, request_context_middleware};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use bytes::Bytes;
use http::header::{ACCEPT_LANGUAGE, AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tower::ServiceExt;

/// Default peer address of test requests.
pub const DEFAULT_PEER: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 40_000);

/// Wraps a router with the request-context middleware (default config).
pub fn with_request_context(router: Router) -> Router {
    with_request_context_config(router, RequestContextConfig::default())
}

/// Wraps a router with the request-context middleware and a custom config
/// (trusted proxies, default locale).
pub fn with_request_context_config(router: Router, config: RequestContextConfig) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        Arc::new(config),
        request_context_middleware,
    ))
}

/// A request under construction.
#[derive(Debug, Clone)]
pub struct TestRequest {
    method: Method,
    uri: String,
    headers: HeaderMap,
    body: Bytes,
    peer: SocketAddr,
}

impl TestRequest {
    /// A request with an arbitrary method.
    #[must_use]
    pub fn new(method: Method, uri: &str) -> Self {
        Self {
            method,
            uri: uri.to_owned(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            peer: DEFAULT_PEER,
        }
    }

    /// `GET`.
    #[must_use]
    pub fn get(uri: &str) -> Self {
        Self::new(Method::GET, uri)
    }

    /// `POST`.
    #[must_use]
    pub fn post(uri: &str) -> Self {
        Self::new(Method::POST, uri)
    }

    /// `PUT`.
    #[must_use]
    pub fn put(uri: &str) -> Self {
        Self::new(Method::PUT, uri)
    }

    /// `PATCH`.
    #[must_use]
    pub fn patch(uri: &str) -> Self {
        Self::new(Method::PATCH, uri)
    }

    /// `DELETE`.
    #[must_use]
    pub fn delete(uri: &str) -> Self {
        Self::new(Method::DELETE, uri)
    }

    /// JSON body (sets `Content-Type: application/json`).
    #[must_use]
    pub fn json(mut self, body: &impl Serialize) -> Self {
        self.body = Bytes::from(serde_json::to_vec(body).expect("serializable test body"));
        self.headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        self
    }

    /// Raw body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Adds a header (appends; repeated names are kept).
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
        self.headers.append(
            name,
            HeaderValue::from_str(value).expect("valid header value"),
        );
        self
    }

    /// `Authorization: Bearer <token>`.
    #[must_use]
    pub fn bearer(self, token: &str) -> Self {
        self.header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
    }

    /// Adds a cookie.
    #[must_use]
    pub fn cookie(self, name: &str, value: &str) -> Self {
        self.header(COOKIE.as_str(), &format!("{name}={value}"))
    }

    /// `Accept-Language`.
    #[must_use]
    pub fn accept_language(self, value: &str) -> Self {
        self.header(ACCEPT_LANGUAGE.as_str(), value)
    }

    /// TCP peer IP (port 40000).
    #[must_use]
    pub fn peer_ip(mut self, ip: IpAddr) -> Self {
        self.peer = SocketAddr::new(ip, 40_000);
        self
    }

    /// The `http::Request` (with `ConnectInfo` extension).
    #[must_use]
    pub fn build(self) -> Request<Body> {
        let mut builder = Request::builder().method(self.method).uri(self.uri);
        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }
        let mut request = builder
            .body(Body::from(self.body))
            .expect("valid test request");
        request.extensions_mut().insert(ConnectInfo(self.peer));
        request
    }

    /// Sends the request through a clone of `router`.
    pub async fn send(self, router: &Router) -> TestResponse {
        let response = router
            .clone()
            .oneshot(self.build())
            .await
            .expect("router is infallible");
        let (parts, body) = response.into_parts();
        let body = body.collect().await.expect("readable body").to_bytes();
        TestResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }
}

/// A buffered response.
#[derive(Debug, Clone)]
pub struct TestResponse {
    /// Status.
    pub status: StatusCode,
    /// Headers.
    pub headers: HeaderMap,
    /// Body.
    pub body: Bytes,
}

impl TestResponse {
    /// Deserializes the JSON body.
    #[must_use]
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("body is not the expected JSON ({e}): {}", self.text()))
    }

    /// The body as text (lossy).
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// A header value as string.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// All `Set-Cookie` values.
    #[must_use]
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect()
    }

    /// Parses the standard error envelope (panics if the body is not one).
    #[must_use]
    pub fn error(&self) -> ErrorBody {
        self.json::<ErrorEnvelope>().error
    }

    /// Asserts the status code.
    pub fn assert_status(&self, expected: StatusCode) -> &Self {
        assert_eq!(
            self.status,
            expected,
            "unexpected status; body: {}",
            self.text()
        );
        self
    }

    /// Asserts an error response with the given status and code.
    pub fn assert_error(&self, status: StatusCode, code: &str) -> ErrorBody {
        self.assert_status(status);
        let error = self.error();
        assert_eq!(
            error.code,
            code,
            "unexpected error code; body: {}",
            self.text()
        );
        error
    }
}

#[cfg(test)]
mod tests {
    use authn_core::error::{AuthError, codes};
    use authn_core::http::RequestContext;
    use axum::routing::{get, post};

    use super::*;

    fn app() -> Router {
        with_request_context(
            Router::new()
                .route("/ip", get(|ctx: RequestContext| async move { ctx.client_ip.to_string() }))
                .route("/echo", post(|authn_core::http::Json(v): authn_core::http::Json<serde_json::Value>| async move { axum::Json(v) }))
                .route("/denied", get(|| async { AuthError::new(codes::common::FORBIDDEN) })),
        )
    }

    #[tokio::test]
    async fn tst_01_requests_flow_through_router_with_context() {
        let res = TestRequest::get("/ip")
            .peer_ip("198.51.100.1".parse().unwrap())
            .send(&app())
            .await;
        res.assert_status(StatusCode::OK);
        assert_eq!(res.text(), "198.51.100.1");
        assert!(res.header("x-request-id").is_some());

        let res = TestRequest::post("/echo")
            .json(&serde_json::json!({"a": 1}))
            .send(&app())
            .await;
        assert_eq!(res.json::<serde_json::Value>()["a"], 1);

        let err = TestRequest::get("/denied")
            .accept_language("tr")
            .send(&app())
            .await
            .assert_error(StatusCode::FORBIDDEN, "forbidden");
        assert_eq!(err.message, "Bu işlemi yapma yetkiniz yok.");
        assert!(err.request_id.is_some());
    }
}
