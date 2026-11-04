//! Router assembly and middleware stack (OPS-02, contracts §15.3 / §15.4).
//!
//! Order, outermost first:
//!
//! 1. request context (request id, client IP, locale; error envelopes) — authn-core
//! 2. tracing (`TraceLayer`, path only — query strings may carry OAuth codes)
//! 3. panic catcher (500 → standard envelope)
//! 4. timeout (PRT-11)
//! 5. global concurrency limit (PRT-11)
//! 6. body size limit (PRT-11)
//! 7. host validation → security headers → CORS → per-IP rate limit (authn-protect)
//! 8. authentication + CSRF (`authn_session::authenticate`; it replaces
//!    `authn_org::api_key_middleware` — never install both)
//! 9. handler
//!
//! axum applies `.layer()` calls inside-out, so the code lists them from
//! innermost to outermost.

use std::sync::Arc;

use authn_core::error::AuthError;
use authn_core::http::{REQUEST_ID_HEADER, not_found_fallback, request_context_middleware};
use authn_protect::rate_limit::{HttpRateLimit, http_rate_limit};
use authn_protect::web::{
    CorsPolicy, HostValidation, SecurityHeaders, cors, security_headers, validate_host,
};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use http::StatusCode;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::routes::{example, health};
use crate::state::AppState;

/// Every module router, merged (no layers).
pub fn module_routes() -> Router<AppState> {
    Router::new()
        .merge(health::router::<AppState>())
        .merge(example::router::<AppState>())
        .merge(authn_session::router::<AppState>())
        .merge(authn_password::router::<AppState>())
        .merge(authn_account::router::<AppState>())
        .merge(authn_mfa::router::<AppState>())
        .merge(authn_webauthn::router::<AppState>())
        .merge(authn_webauthn::well_known_router::<AppState>())
        .merge(authn_org::router::<AppState>())
        .merge(authn_protect::router::<AppState>())
        .merge(authn_audit::router::<AppState>())
}

/// Builds the complete application router. Fails when a web-protection
/// setting is unusable (fail fast at start-up, ARC-07).
pub fn build_router(state: AppState) -> Result<Router, AuthError> {
    let config = state.config.clone();
    let limits = config.server.limits;
    let protect = &config.protect;

    let mut router = module_routes();
    if config.server.openapi_enabled {
        router = router.route(
            "/openapi.json",
            get(|| async { axum::Json(crate::openapi::document()) }),
        );
    }

    let host = HostValidation::from_config(protect, &config.server.public_base_url)?;
    let headers = SecurityHeaders::from_config(&protect.security_headers)?;
    let cors_policy = CorsPolicy::from_config(&protect.cors)?;
    let rate_limit = HttpRateLimit::new(
        state.services.rate_limiter.clone(),
        protect.rate_limit.requests_per_ip,
    );
    let sessions = state.services.sessions.clone();

    Ok(router
        .fallback(not_found_fallback)
        .with_state(state)
        // (8) authentication + CSRF.
        .layer(from_fn_with_state(sessions, authn_session::authenticate))
        // (7) rate limit ← CORS ← security headers ← host validation.
        .layer(from_fn_with_state(rate_limit, http_rate_limit))
        .layer(from_fn_with_state(cors_policy, cors))
        .layer(from_fn_with_state(headers, security_headers))
        .layer(from_fn_with_state(host, validate_host))
        .layer(DefaultBodyLimit::max(limits.body_limit_bytes))
        .layer(RequestBodyLimitLayer::new(limits.body_limit_bytes))
        .layer(GlobalConcurrencyLimitLayer::new(limits.max_concurrent_requests))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, limits.request_timeout))
        .layer(CatchPanicLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &http::Request<axum::body::Body>| {
                    // The request-context middleware has already replaced
                    // `x-request-id` with a server-generated UUIDv7.
                    let request_id = request
                        .headers()
                        .get(REQUEST_ID_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    tracing::info_span!(
                        "http",
                        request_id = %request_id,
                        method = %request.method(),
                        path = %request.uri().path(),
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(from_fn_with_state(
            Arc::new(config.server.request_context()),
            request_context_middleware,
        )))
}
