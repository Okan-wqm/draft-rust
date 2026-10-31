//! Per-request context and the middleware that builds it.
//!
//! [`request_context_middleware`] must be the outermost application layer
//! (OPS-02: "request id → …"). For every request it:
//!
//! 1. generates a fresh UUIDv7 request id (client-supplied `x-request-id`
//!    values are ignored — they would allow log forgery),
//! 2. resolves the client IP from the TCP peer and trusted proxies (PRT-06),
//! 3. captures a bounded, sanitized user agent and a validated device id,
//! 4. negotiates the locale from `Accept-Language`,
//! 5. inserts a [`RequestContext`] into the request extensions and runs the
//!    rest of the stack inside a `tracing` span carrying the request id,
//! 6. on the way out, re-renders every error envelope in the negotiated
//!    locale with the request id, converts foreign (non-JSON) error
//!    responses into the standard envelope so nothing internal leaks, and
//!    sets the `x-request-id` response header.
//!
//! The TCP peer address comes from `axum::extract::ConnectInfo<SocketAddr>`
//! (`into_make_service_with_connect_info`). Without it the request is
//! rejected with `internal_error`: failing closed is better than keying rate
//! limits on a made-up address.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{ACCEPT_LANGUAGE, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, USER_AGENT};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue};
use ipnet::IpNet;
use tracing::Instrument;

use crate::domain::Locale;
use crate::error::{AuthError, RenderedError, codes, render_envelope};
use crate::http::client_ip::{ClientIpHeader, resolve_client_ip};
use crate::id::RequestId;

/// Response / request header carrying the request id.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
/// Header carrying the device id for native clients.
pub const DEVICE_ID_HEADER: HeaderName = HeaderName::from_static("x-device-id");
/// Cookie carrying the device id for browsers (set by authn-session).
pub const DEVICE_ID_COOKIE: &str = "__Host-authn_device";

/// Longest user agent kept (bytes); longer values are truncated.
const MAX_USER_AGENT_BYTES: usize = 512;
/// Device ids are 16–128 URL-safe characters.
const DEVICE_ID_LEN: std::ops::RangeInclusive<usize> = 16..=128;
/// Longest `Accept-Language` value inspected.
const MAX_ACCEPT_LANGUAGE_BYTES: usize = 512;

/// Facts about the current request, available to every handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// Fresh UUIDv7 per request.
    pub request_id: RequestId,
    /// Client IP after trusted-proxy resolution (PRT-06).
    pub client_ip: IpAddr,
    /// Raw TCP peer (the nearest proxy when deployed behind one).
    pub peer_ip: IpAddr,
    /// Sanitized user agent (control characters removed, ≤ 512 bytes).
    pub user_agent: Option<String>,
    /// Client-supplied device id (format-validated, otherwise untrusted).
    pub device_id: Option<String>,
    /// Negotiated locale (falls back to the configured default).
    pub locale: Locale,
}

impl RequestContext {
    /// A context for background jobs and CLI commands (no HTTP request).
    #[must_use]
    pub fn system(locale: Locale) -> Self {
        Self {
            request_id: RequestId::generate(),
            client_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_id: None,
            locale,
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<RequestContext>()
            .cloned()
            .ok_or_else(|| AuthError::internal("request context middleware is not installed"))
    }
}

/// Configuration of [`request_context_middleware`] (built from
/// `config::server::ServerConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContextConfig {
    /// CIDRs of reverse proxies whose forwarding headers are trusted.
    pub trusted_proxies: Vec<IpNet>,
    /// Which forwarding header those proxies maintain.
    pub client_ip_header: ClientIpHeader,
    /// Locale used when `Accept-Language` matches nothing supported.
    pub default_locale: Locale,
}

impl Default for RequestContextConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            client_ip_header: ClientIpHeader::XForwardedFor,
            default_locale: Locale::En,
        }
    }
}

/// The request-context middleware. Install with
/// `axum::middleware::from_fn_with_state(Arc::new(config), request_context_middleware)`.
pub async fn request_context_middleware(
    State(config): State<Arc<RequestContextConfig>>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = RequestId::generate();
    let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
    else {
        let err = AuthError::internal("missing ConnectInfo<SocketAddr>; serve with connect info");
        tracing::error!(request_id = %request_id, "{err}");
        return finish(
            render_envelope(
                codes::common::INTERNAL_ERROR,
                None,
                config.default_locale,
                Some(request_id),
            ),
            request_id,
        );
    };

    let headers = request.headers();
    let client_ip = resolve_client_ip(
        peer,
        headers,
        &config.trusted_proxies,
        config.client_ip_header,
    );
    let context = RequestContext {
        request_id,
        client_ip,
        peer_ip: peer.to_canonical(),
        user_agent: sanitize_user_agent(headers),
        device_id: extract_device_id(headers),
        locale: negotiate_locale(headers).unwrap_or(config.default_locale),
    };
    let locale = context.locale;

    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        request.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %request.method(),
        path = %request.uri().path(),
    );
    request.extensions_mut().insert(context);

    let response = next.run(request).instrument(span).await;
    finish(localize_errors(response, locale, request_id), request_id)
}

fn finish(mut response: Response, request_id: RequestId) -> Response {
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

/// Re-renders envelopes in the right locale with the request id and wraps
/// foreign error responses in the standard envelope.
fn localize_errors(response: Response, negotiated: Locale, request_id: RequestId) -> Response {
    let locale = response
        .extensions()
        .get::<Locale>()
        .copied()
        .unwrap_or(negotiated);
    let rendered = response.extensions().get::<RenderedError>().cloned();
    let status = response.status();
    let (code, details) = match rendered {
        Some(r) => (r.code, r.details),
        None => {
            let is_json = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("application/json") || v.ends_with("+json"));
            if !(status.is_client_error() || status.is_server_error()) || is_json {
                return response;
            }
            (codes::common::for_status(status), None)
        }
    };

    let (mut parts, _discarded_body) = response.into_parts();
    let fresh = render_envelope(code, details, locale, Some(request_id));
    let (fresh_parts, body) = fresh.into_parts();
    parts.headers.remove(CONTENT_LENGTH);
    for (name, value) in &fresh_parts.headers {
        parts.headers.insert(name.clone(), value.clone());
    }
    parts.extensions.insert(RenderedError {
        code,
        details: None,
    });
    Response::from_parts(parts, body).into_response()
}

fn negotiate_locale(headers: &HeaderMap) -> Option<Locale> {
    let value = headers.get(ACCEPT_LANGUAGE)?.to_str().ok()?;
    if value.len() > MAX_ACCEPT_LANGUAGE_BYTES {
        return None;
    }
    Locale::negotiate(value)
}

fn sanitize_user_agent(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(USER_AGENT)?;
    let text = String::from_utf8_lossy(raw.as_bytes());
    let mut out = String::with_capacity(text.len().min(MAX_USER_AGENT_BYTES));
    for c in text.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_USER_AGENT_BYTES {
            break;
        }
        out.push(c);
    }
    let out = out.trim().to_owned();
    (!out.is_empty()).then_some(out)
}

fn is_valid_device_id(value: &str) -> bool {
    DEVICE_ID_LEN.contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn extract_device_id(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get(DEVICE_ID_HEADER).and_then(|v| v.to_str().ok()) {
        let value = value.trim();
        if is_valid_device_id(value) {
            return Some(value.to_owned());
        }
    }
    for cookie_header in headers.get_all(COOKIE) {
        let Ok(cookies) = cookie_header.to_str() else {
            continue;
        };
        for pair in cookies.split(';').take(64) {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name == DEVICE_ID_COOKIE
                && is_valid_device_id(value)
            {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use http::{HeaderValue, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::error::codes;

    fn app(config: RequestContextConfig) -> Router {
        Router::new()
            .route(
                "/ctx",
                get(|ctx: RequestContext| async move {
                    axum::Json(serde_json::json!({
                        "ip": ctx.client_ip.to_string(),
                        "ua": ctx.user_agent,
                        "device": ctx.device_id,
                        "locale": ctx.locale.as_str(),
                        "request_id": ctx.request_id.to_string(),
                    }))
                }),
            )
            .route(
                "/fail",
                get(|| async { AuthError::new(codes::session::INVALID_CREDENTIALS) }),
            )
            .route(
                "/fail-tr",
                get(|| async {
                    let mut response = AuthError::new(codes::common::FORBIDDEN).into_response();
                    response.extensions_mut().insert(Locale::Tr);
                    response
                }),
            )
            .route(
                "/boom",
                get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "panic: secret stack trace",
                    )
                }),
            )
            .fallback(crate::http::not_found_fallback)
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(config),
                request_context_middleware,
            ))
    }

    fn request(path: &str, peer: &str) -> http::Request<Body> {
        let mut req = http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 4000)));
        req
    }

    async fn json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn prt_06_context_uses_trusted_proxy_resolution() {
        let config = RequestContextConfig {
            trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
            ..RequestContextConfig::default()
        };
        let mut req = request("/ctx", "10.0.0.5");
        req.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 198.51.100.4"),
        );
        let response = app(config.clone()).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let header_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = json(response).await;
        assert_eq!(body["ip"], "198.51.100.4");
        assert_eq!(body["request_id"], header_id);

        // Same header from an untrusted peer is ignored.
        let mut req = request("/ctx", "203.0.113.1");
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.4"));
        let body = json(app(config).oneshot(req).await.unwrap()).await;
        assert_eq!(body["ip"], "203.0.113.1");
    }

    #[tokio::test]
    async fn ops_03_client_request_id_is_never_trusted() {
        let mut req = request("/ctx", "203.0.113.1");
        req.headers_mut().insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("forged-request-id"),
        );
        let response = app(RequestContextConfig::default())
            .oneshot(req)
            .await
            .unwrap();
        let id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(id.parse::<RequestId>().is_ok());
    }

    #[tokio::test]
    async fn arc_08_errors_are_localized_and_carry_request_id() {
        let mut req = request("/fail", "203.0.113.1");
        req.headers_mut().insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("tr-TR,tr;q=0.9,en;q=0.5"),
        );
        let response = app(RequestContextConfig::default())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let body = json(response).await;
        assert_eq!(body["error"]["code"], "invalid_credentials");
        assert_eq!(body["error"]["message"], "Giriş bilgileri hatalı.");
        assert_eq!(body["error"]["request_id"], id);
    }

    #[tokio::test]
    async fn arc_08_default_locale_applies_without_accept_language() {
        let config = RequestContextConfig {
            default_locale: Locale::Tr,
            ..RequestContextConfig::default()
        };
        let response = app(config)
            .oneshot(request("/fail", "203.0.113.1"))
            .await
            .unwrap();
        assert_eq!(
            json(response).await["error"]["message"],
            "Giriş bilgileri hatalı."
        );
    }

    #[tokio::test]
    async fn arc_08_response_locale_extension_overrides_accept_language() {
        let mut req = request("/fail-tr", "203.0.113.1");
        req.headers_mut()
            .insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en"));
        let body = json(
            app(RequestContextConfig::default())
                .oneshot(req)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["error"]["code"], "forbidden");
        assert_eq!(body["error"]["message"], "Bu işlemi yapma yetkiniz yok.");
    }

    #[tokio::test]
    async fn arc_08_foreign_errors_are_wrapped_without_leaking() {
        let response = app(RequestContextConfig::default())
            .oneshot(request("/boom", "203.0.113.1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = json(response).await;
        assert_eq!(body["error"]["code"], "internal_error");
        assert!(!body.to_string().contains("secret stack trace"));

        let response = app(RequestContextConfig::default())
            .oneshot(request("/nope", "203.0.113.1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json(response).await["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn missing_connect_info_fails_closed() {
        let req = http::Request::builder()
            .uri("/ctx")
            .body(Body::empty())
            .unwrap();
        let response = app(RequestContextConfig::default())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json(response).await["error"]["code"], "internal_error");
    }

    #[tokio::test]
    async fn user_agent_and_device_id_are_sanitized() {
        let mut req = request("/ctx", "203.0.113.1");
        let long_ua = format!("Mozilla/5.0 {}", "x".repeat(2000));
        req.headers_mut()
            .insert(USER_AGENT, HeaderValue::from_str(&long_ua).unwrap());
        req.headers_mut().insert(
            COOKIE,
            HeaderValue::from_static("a=b; __Host-authn_device=abcdefghijklmnop_1234"),
        );
        let body = json(
            app(RequestContextConfig::default())
                .oneshot(req)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["ua"].as_str().unwrap().len(), MAX_USER_AGENT_BYTES);
        assert_eq!(body["device"], "abcdefghijklmnop_1234");

        let mut req = request("/ctx", "203.0.113.1");
        req.headers_mut()
            .insert(DEVICE_ID_HEADER, HeaderValue::from_static("short"));
        req.headers_mut()
            .insert(USER_AGENT, HeaderValue::from_static("ua\twith\ttabs"));
        let body = json(
            app(RequestContextConfig::default())
                .oneshot(req)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["device"], serde_json::Value::Null);
        assert_eq!(body["ua"], "uawithtabs");
    }
}
