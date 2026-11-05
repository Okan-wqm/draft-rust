#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-67 (ADM-04, K-12, PRT-08): the `x-impersonation-session` header is
//! allowed cross-origin only for the configured admin console origins;
//! safe default off.

mod common;

use authn_server::app::build_router;
use authn_server::state::AppState;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::App;
use sqlx::PgPool;

const CONSOLE: &str = "https://console.example.com";
const APP: &str = "https://app.example.com";

fn preflight(origin: &str, headers: &str) -> TestRequest {
    TestRequest::new(axum::http::Method::OPTIONS, "/v1/me")
        .header("origin", origin)
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", headers)
}

fn allowed_headers(res: &authn_testkit::http::TestResponse) -> String {
    res.headers
        .get("access-control-allow-headers")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k67_impersonation_header_is_never_allowed_cross_origin_by_default(pool: PgPool) {
    let app = App::with(pool, |c| {
        c.protect.cors.allowed_origins = vec![APP.to_owned(), CONSOLE.to_owned()];
    })
    .await;
    // Ordinary CORS still works…
    let res = app.send(preflight(APP, "content-type, x-csrf-token")).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.text());
    assert!(!allowed_headers(&res).contains("x-impersonation-session"));
    // …but the impersonation header is refused for every origin.
    for origin in [APP, CONSOLE] {
        let res = app
            .send(preflight(origin, "content-type, x-impersonation-session"))
            .await;
        res.assert_error(StatusCode::FORBIDDEN, "cors_origin_not_allowed");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k67_only_the_configured_console_origin_may_send_the_header(pool: PgPool) {
    let app = App::with(pool, |c| {
        c.protect.cors.allowed_origins = vec![APP.to_owned(), CONSOLE.to_owned()];
        c.server.admin_console_origins = vec![CONSOLE.to_owned()];
    })
    .await;
    let res = app
        .send(preflight(CONSOLE, "content-type, X-Impersonation-Session"))
        .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.text());
    assert_eq!(res.headers["access-control-allow-origin"], CONSOLE);
    assert_eq!(res.headers["access-control-allow-credentials"], "true");
    assert!(allowed_headers(&res).contains("x-impersonation-session"));
    assert!(res.headers["vary"].to_str().unwrap().contains("Origin"));
    // Security headers still apply to the answer (layer order).
    assert!(res.headers.contains_key("x-content-type-options"));

    // Another CORS-allowed origin still cannot.
    app.send(preflight(APP, "x-impersonation-session"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "cors_origin_not_allowed");
    // Look-alike origins are not the console.
    for origin in [
        "https://console.example.com.evil.example",
        "http://console.example.com",
        "https://console.example.com:8443",
        "null",
    ] {
        let res = app.send(preflight(origin, "x-impersonation-session")).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{origin}");
    }
    // Only headers on the fixed list ride along.
    app.send(preflight(CONSOLE, "x-impersonation-session, x-evil"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "cors_origin_not_allowed");
    // A disallowed method is not answered either.
    let res = app
        .send(
            TestRequest::new(axum::http::Method::OPTIONS, "/v1/me")
                .header("origin", CONSOLE)
                .header("access-control-request-method", "TRACE")
                .header("access-control-request-headers", "x-impersonation-session"),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    // Ordinary console requests keep the normal CORS answer.
    let res = app
        .send(TestRequest::get("/v1/time").header("origin", CONSOLE))
        .await;
    assert_eq!(res.headers["access-control-allow-origin"], CONSOLE);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k67_console_origin_must_also_be_a_cors_origin(pool: PgPool) {
    let app = App::new(pool).await;
    let mut config = (*app.services.config).clone();
    config.protect.cors.allowed_origins = vec![APP.to_owned()];
    config.server.admin_console_origins = vec![CONSOLE.to_owned()];
    let mut services = app.services.clone();
    services.config = std::sync::Arc::new(config);
    let err = build_router(AppState::new(services)).unwrap_err();
    assert!(
        err.to_string().contains("admin_console_origins")
            || format!("{err:?}").contains("admin_console_origins")
    );

    // Configuration validation refuses anything but an origin.
    for bad in [
        "https://console.example.com/path",
        "ftp://console.example.com",
        "console.example.com",
        "https://user@console.example.com",
    ] {
        let mut config = (*app.services.config).clone();
        config.server.admin_console_origins = vec![bad.to_owned()];
        assert!(config.validate().is_err(), "{bad}");
    }
    let mut config = (*app.services.config).clone();
    config.protect.cors.allowed_origins = vec![CONSOLE.to_owned()];
    config.server.admin_console_origins = vec![format!("{CONSOLE}/")];
    config.validate().unwrap();
}
