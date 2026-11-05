//! Cross-origin admin console (ADM-04, K-12, K-67).
//!
//! A web impersonation session travels in the `x-impersonation-session`
//! request header (authn-session, K-12). authn-protect's strict CORS layer
//! (PRT-08) never allows that header cross-origin, which is the safe
//! default: a console served from the API's own origin needs no CORS.
//!
//! When the console is served from another origin, the operator lists it
//! in `server.admin_console_origins` (each entry must also be in
//! `protect.cors.allowed_origins`). This layer, installed just outside the
//! CORS layer, answers **only** preflights from exactly those origins that
//! ask for `x-impersonation-session` (plus nothing outside the fixed CORS
//! lists), adding the header to `Access-Control-Allow-Headers`. Every other
//! request — other origins, other preflights, actual requests — goes to the
//! CORS layer unchanged, so other allowed origins still cannot send the
//! header.

use std::sync::Arc;

use authn_core::config::AppConfig;
use authn_core::error::AuthError;
use authn_protect::web::{ALLOWED_HEADERS, ALLOWED_METHODS};
use authn_session::IMPERSONATION_SESSION_HEADER;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS,
    ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use http::{HeaderValue, Method, StatusCode};

/// State of [`admin_console_cors`].
#[derive(Debug, Clone)]
pub struct AdminConsoleCors {
    origins: Arc<[String]>,
    methods: HeaderValue,
    headers: HeaderValue,
    max_age: HeaderValue,
}

/// The ASCII serialisation of an http(s) origin (`None` otherwise).
fn origin_of(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    (origin != "null").then_some(origin)
}

impl AdminConsoleCors {
    /// Builds the policy; fails when a console origin is not a valid
    /// origin or not also a CORS-allowed origin (fail fast, ARC-07).
    pub fn from_config(config: &AppConfig) -> Result<Self, AuthError> {
        let allowed: Vec<String> = config
            .protect
            .cors
            .allowed_origins
            .iter()
            .filter_map(|o| origin_of(o))
            .collect();
        let mut origins = Vec::new();
        for entry in &config.server.admin_console_origins {
            let origin = origin_of(entry).ok_or_else(|| {
                AuthError::internal("server.admin_console_origins: invalid origin")
            })?;
            if !allowed.contains(&origin) {
                return Err(AuthError::internal(
                    "server.admin_console_origins: every console origin must also be in protect.cors.allowed_origins",
                ));
            }
            origins.push(origin);
        }
        let methods = ALLOWED_METHODS
            .iter()
            .map(Method::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        let mut headers: Vec<&str> = ALLOWED_HEADERS.to_vec();
        headers.push(IMPERSONATION_SESSION_HEADER);
        Ok(Self {
            origins: Arc::from(origins),
            methods: HeaderValue::from_str(&methods)
                .map_err(|_| AuthError::internal("cors methods"))?,
            headers: HeaderValue::from_str(&headers.join(", "))
                .map_err(|_| AuthError::internal("cors headers"))?,
            max_age: HeaderValue::from(config.protect.cors.max_age.as_secs()),
        })
    }

    /// Whether any console origin is configured (otherwise a no-op).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.origins.is_empty()
    }

    /// The console origin equal to the request's single `Origin` header.
    fn matching(&self, request: &Request) -> Option<HeaderValue> {
        let mut values = request.headers().get_all(ORIGIN).iter();
        let first = values.next()?;
        if values.next().is_some() {
            return None;
        }
        let origin = first.to_str().ok()?;
        self.origins
            .iter()
            .find(|allowed| allowed.as_str() == origin)
            .and_then(|allowed| HeaderValue::from_str(allowed).ok())
    }
}

/// The requested headers of a preflight, lowercase; `None` when a value
/// is not text.
fn requested_headers(request: &Request) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for value in request.headers().get_all(ACCESS_CONTROL_REQUEST_HEADERS) {
        let list = value.to_str().ok()?;
        out.extend(
            list.split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty()),
        );
    }
    Some(out)
}

/// Whether this is a console preflight this layer answers: exactly one
/// allowed method, the impersonation header requested, and every other
/// requested header on the fixed CORS list.
fn is_console_preflight(request: &Request) -> bool {
    let method_ok = request
        .headers()
        .get(ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| v.to_str().ok())
        .and_then(|m| Method::from_bytes(m.as_bytes()).ok())
        .is_some_and(|m| ALLOWED_METHODS.contains(&m));
    let Some(headers) = requested_headers(request) else {
        return false;
    };
    method_ok
        && headers.iter().any(|h| h == IMPERSONATION_SESSION_HEADER)
        && headers
            .iter()
            .all(|h| h == IMPERSONATION_SESSION_HEADER || ALLOWED_HEADERS.contains(&h.as_str()))
}

/// The middleware (see the module docs).
pub async fn admin_console_cors(
    State(policy): State<AdminConsoleCors>,
    request: Request,
    next: Next,
) -> Response {
    if !policy.is_enabled()
        || request.method() != Method::OPTIONS
        || !request
            .headers()
            .contains_key(ACCESS_CONTROL_REQUEST_METHOD)
    {
        return next.run(request).await;
    }
    let Some(origin) = policy.matching(&request) else {
        return next.run(request).await;
    };
    if !is_console_preflight(&request) {
        return next.run(request).await;
    }
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
    headers.append(
        VARY,
        HeaderValue::from_static(
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
    );
    response
}
