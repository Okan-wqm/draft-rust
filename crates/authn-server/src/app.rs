//! Router assembly and middleware stack (OPS-02).
//!
//! Documented order, outermost first:
//!
//! 1. request context (request id, client IP, locale; error envelopes) — authn-core
//! 2. tracing (`TraceLayer`, path only — query strings may carry OAuth codes)
//! 3. panic catcher (500 → standard envelope)
//! 4. timeout (PRT-11)
//! 5. global concurrency limit (PRT-11)
//! 6. body size limit (PRT-11)
//! 7. host validation → security headers → CORS → rate limit (authn-protect)
//! 8. authentication → CSRF (authn-session)
//! 9. handler
//!
//! Layers 7–8 are added by the owning crates' agents; their slots are marked
//! below. axum applies `.layer()` calls inside-out, so the code lists them
//! from innermost to outermost.

use std::sync::Arc;

use authn_core::http::{REQUEST_ID_HEADER, not_found_fallback, request_context_middleware};
use axum::Router;
use axum::extract::DefaultBodyLimit;
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

/// Builds the complete application router.
pub fn build_router(state: AppState) -> Router {
    let config = state.config.clone();
    let limits = config.server.limits;

    let mut router: Router<AppState> = Router::new()
        .merge(health::router::<AppState>())
        .merge(example::router::<AppState>());
    // Module routers are merged here as they land, e.g.:
    //   .merge(authn_password::router::<AppState>())
    if config.server.openapi_enabled {
        router = router.route(
            "/openapi.json",
            get(|| async { axum::Json(crate::openapi::document()) }),
        );
    }

    router
        .fallback(not_found_fallback)
        .with_state(state)
        // (8) authentication → CSRF: authn-session layers go here.
        // (7) host validation → security headers → CORS → rate limit: authn-protect.
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
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(config.server.request_context()),
            request_context_middleware,
        ))
}

#[cfg(test)]
mod tests {
    use authn_testkit::FakeClock;
    use authn_testkit::config::TestConfigBuilder;
    use authn_testkit::http::TestRequest;
    use sqlx::PgPool;

    use super::*;

    fn app(pool: PgPool, openapi: bool) -> Router {
        let mut config = TestConfigBuilder::new().build();
        config.server.openapi_enabled = openapi;
        build_router(AppState::new(
            Arc::new(config),
            pool,
            Arc::new(FakeClock::new()),
        ))
    }

    #[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
    async fn ops_05_health_probes_report_ready_after_migrations(pool: PgPool) {
        let app = app(pool, true);
        let res = TestRequest::get("/health/live").send(&app).await;
        res.assert_status(StatusCode::OK);
        assert_eq!(res.header("cache-control"), Some("no-store"));
        let res = TestRequest::get("/health/ready").send(&app).await;
        res.assert_status(StatusCode::OK);
        let body: serde_json::Value = res.json();
        assert_eq!(
            body,
            serde_json::json!({"status": "ready", "database": "ok", "migrations": "up_to_date"})
        );
    }

    #[sqlx::test(migrations = false)]
    async fn ops_05_ready_is_503_when_schema_is_missing(pool: PgPool) {
        let res = TestRequest::get("/health/ready")
            .send(&app(pool, true))
            .await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = res.json();
        assert_eq!(body["status"], "not_ready");
        assert_eq!(body["migrations"], "pending");
    }

    #[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
    async fn arc_03_example_route_through_app_state_from_ref(pool: PgPool) {
        let res = TestRequest::get("/v1/time").send(&app(pool, true)).await;
        res.assert_status(StatusCode::OK);
        assert!(res.header("x-request-id").is_some());
        let body: serde_json::Value = res.json();
        assert_eq!(body["server_time"], "2026-01-01T00:00:00Z");
    }

    #[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
    async fn arc_08_unknown_route_uses_error_envelope(pool: PgPool) {
        let err = TestRequest::get("/v1/nope")
            .accept_language("tr")
            .send(&app(pool, true))
            .await
            .assert_error(StatusCode::NOT_FOUND, "not_found");
        assert_eq!(err.message, "İstenen kaynak bulunamadı.");
    }

    #[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
    async fn prt_11_oversized_body_is_rejected_with_envelope(pool: PgPool) {
        let big = vec![b'a'; 64 * 1024 + 1];
        let res = TestRequest::post("/v1/time")
            .header("content-type", "application/json")
            .header("content-length", &big.len().to_string())
            .body(big)
            .send(&app(pool, true))
            .await;
        res.assert_error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
        assert!(!res.text().contains("aaaa"));
    }

    #[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
    async fn ops_09_openapi_can_be_disabled(pool: PgPool) {
        let res = TestRequest::get("/openapi.json")
            .send(&app(pool.clone(), true))
            .await;
        res.assert_status(StatusCode::OK);
        let doc: serde_json::Value = res.json();
        assert!(doc["paths"]["/v1/time"].is_object());
        assert!(doc["components"]["schemas"]["ErrorEnvelope"].is_object());
        TestRequest::get("/openapi.json")
            .send(&app(pool, false))
            .await
            .assert_error(StatusCode::NOT_FOUND, "not_found");
    }
}
