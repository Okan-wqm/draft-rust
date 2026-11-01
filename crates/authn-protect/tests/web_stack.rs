#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! The protect layers stacked in the OPS-02 order, as authn-server installs
//! them (PRT-04, PRT-07, PRT-08, PRT-09, TST-02 host header poisoning).

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::protect::{CorsConfig, ProtectConfig, SecurityHeadersConfig};
use authn_core::ports::{RateLimitPolicy, RateLimiter};
use authn_crypto::kdf::KeyRing;
use authn_protect::KeyHasher;
use authn_protect::rate_limit::{HttpRateLimit, MemoryRateLimiter, http_rate_limit};
use authn_protect::web::{
    CorsPolicy, HostValidation, SecurityHeaders, cors, security_headers, validate_host,
};
use authn_testkit::FakeClock;
use authn_testkit::http::{TestRequest, with_request_context};
use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use http::{Method, StatusCode};
use url::Url;

fn app() -> Router {
    let config = ProtectConfig {
        cors: CorsConfig {
            allowed_origins: vec!["https://app.example.com".to_owned()],
            max_age: Duration::from_secs(600),
        },
        ..ProtectConfig::default()
    };
    let base = Url::parse("https://auth.example.com").unwrap();
    let clock = Arc::new(FakeClock::new());
    let hasher = KeyHasher::new(&KeyRing::derive(&[4_u8; 32]).unwrap()).unwrap();
    let limiter: Arc<dyn RateLimiter> = Arc::new(MemoryRateLimiter::new(clock, hasher));

    // axum applies `.layer` inside-out: the last call is the outermost.
    let router = Router::new()
        .route("/v1/me", get(|| async { "me" }))
        .route("/v1/login", post(|| async { "ok" }))
        .layer(from_fn_with_state(
            HttpRateLimit::new(limiter, RateLimitPolicy::new(2, Duration::from_secs(60))),
            http_rate_limit,
        ))
        .layer(from_fn_with_state(
            CorsPolicy::from_config(&config.cors).unwrap(),
            cors,
        ))
        .layer(from_fn_with_state(
            SecurityHeaders::from_config(&SecurityHeadersConfig::default()).unwrap(),
            security_headers,
        ))
        .layer(from_fn_with_state(
            HostValidation::from_config(&config, &base).unwrap(),
            validate_host,
        ));
    with_request_context(router)
}

#[tokio::test]
async fn prt_09_host_poisoning_is_stopped_before_routing() {
    let app = app();
    let res = TestRequest::get("/v1/me")
        .header("host", "evil.example")
        .header("x-forwarded-host", "auth.example.com")
        .send(&app)
        .await;
    res.assert_error(StatusCode::MISDIRECTED_REQUEST, "host_not_allowed");
    assert!(res.header("x-request-id").is_some());
}

#[tokio::test]
async fn prt_07_prt_08_prt_04_layers_compose() {
    let app = app();
    let ok = TestRequest::get("/v1/me")
        .header("host", "auth.example.com")
        .header("origin", "https://app.example.com")
        .send(&app)
        .await;
    ok.assert_status(StatusCode::OK);
    assert_eq!(ok.header("cache-control"), Some("no-store"));
    assert_eq!(ok.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(
        ok.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );

    // Preflights are answered by the CORS layer (not rate limited, headers set).
    for _ in 0..5 {
        let preflight = TestRequest::new(Method::OPTIONS, "/v1/login")
            .header("host", "auth.example.com")
            .header("origin", "https://app.example.com")
            .header("access-control-request-method", "POST")
            .send(&app)
            .await;
        preflight.assert_status(StatusCode::NO_CONTENT);
        assert!(preflight.header("strict-transport-security").is_some());
    }

    TestRequest::post("/v1/login")
        .header("host", "auth.example.com")
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    // The 429 is readable cross-origin (CORS sits outside the limiter) and
    // carries Retry-After plus the security headers.
    let limited = TestRequest::post("/v1/login")
        .header("host", "auth.example.com")
        .header("origin", "https://app.example.com")
        .send(&app)
        .await;
    limited.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(limited.header("retry-after").is_some());
    assert_eq!(
        limited.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );
    assert_eq!(
        limited.header("access-control-expose-headers"),
        Some("x-request-id, retry-after")
    );
    assert_eq!(limited.header("cache-control"), Some("no-store"));
}
