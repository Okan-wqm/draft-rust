#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! The assembled application: every module router behind the full
//! middleware stack (OPS-02, ARC-03, ARC-09) and HTTP-level security
//! regressions (TST-02).

mod common;

use authn_server::routes::health::{self, HealthState};
use authn_testkit::http::TestRequest;
use axum::Router;
use axum::http::StatusCode;
use common::{App, ORIGIN, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_05_health_probes_report_ready_after_migrations(pool: PgPool) {
    let app = App::new(pool).await;
    let res = app.send(TestRequest::get("/health/live")).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let res = app.send(TestRequest::get("/health/ready")).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(
        res.json::<Value>(),
        json!({"status": "ready", "database": "ok", "migrations": "up_to_date"})
    );
}

#[sqlx::test(migrations = false)]
async fn ops_05_ready_is_503_when_schema_is_missing(pool: PgPool) {
    let router: Router = Router::new()
        .merge(health::router::<HealthState>())
        .with_state(HealthState { db: pool });
    let router = authn_testkit::http::with_request_context(router);
    let res = TestRequest::get("/health/ready").send(&router).await;
    res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = res.json();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["migrations"], "pending");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_03_example_route_through_app_state_from_ref(pool: PgPool) {
    let app = App::new(pool).await;
    let res = app.send(TestRequest::get("/v1/time")).await;
    res.assert_status(StatusCode::OK);
    assert!(res.header("x-request-id").is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_08_unknown_route_uses_error_envelope(pool: PgPool) {
    let app = App::new(pool).await;
    let err = app
        .send(TestRequest::get("/v1/nope").accept_language("tr"))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    assert_eq!(err.message, "İstenen kaynak bulunamadı.");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_11_oversized_body_is_rejected_with_envelope(pool: PgPool) {
    let app = App::new(pool).await;
    let big = vec![b'a'; 64 * 1024 + 1];
    let res = app
        .send(
            TestRequest::post("/v1/time")
                .header("content-type", "application/json")
                .header("content-length", &big.len().to_string())
                .body(big),
        )
        .await;
    res.assert_error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    assert!(!res.text().contains("aaaa"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_09_openapi_documents_every_module(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let doc: Value = app.send(TestRequest::get("/openapi.json")).await.json();
    for path in [
        "/v1/time",
        "/v1/login/password",
        "/v1/login/challenge/verify",
        "/v1/login/magic-link",
        "/v1/me/sessions",
        "/v1/signup",
        "/v1/password/forgot",
        "/v1/me/mfa/totp",
        "/v1/me/passkeys",
        "/v1/orgs",
        "/v1/captcha/challenge",
        "/v1/me/security-events",
    ] {
        assert!(
            doc["paths"][path].is_object(),
            "{path} missing from the OpenAPI document"
        );
    }
    assert!(doc["components"]["schemas"]["ErrorEnvelope"].is_object());
    let disabled = App::with(pool, |c| c.server.openapi_enabled = false).await;
    disabled
        .send(TestRequest::get("/openapi.json"))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_09_host_header_poisoning_is_refused(pool: PgPool) {
    let app = App::new(pool).await;
    for path in ["/v1/time", "/v1/login/password", "/v1/me"] {
        let res = TestRequest::get(path)
            .header("host", "evil.example")
            .send(&app.router)
            .await;
        res.assert_error(StatusCode::MISDIRECTED_REQUEST, "host_not_allowed");
    }
    // Load-balancer probes are exempt by design.
    TestRequest::get("/health/live")
        .header("host", "10.0.0.7:8080")
        .send(&app.router)
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_07_security_headers_on_every_response(pool: PgPool) {
    let app = App::new(pool).await;
    for path in ["/health/live", "/v1/nope", "/v1/me"] {
        let res = app.send(TestRequest::get(path)).await;
        assert!(res.header("strict-transport-security").is_some(), "{path}");
        assert_eq!(
            res.header("x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert!(res.header("content-security-policy").is_some(), "{path}");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_04_csrf_protects_other_modules_behind_the_session_layer(pool: PgPool) {
    let app = App::new(pool).await;
    app.user("alice@example.com").await;
    let mut browser = app.browser();
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    // A state-changing request of another module without the CSRF token.
    let mut request = TestRequest::post("/v1/me/mfa/totp")
        .json(&json!({}))
        .header("origin", ORIGIN);
    for (name, value) in &browser.cookies {
        request = request.cookie(name, value);
    }
    app.send(request)
        .await
        .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    // Cross-site origin with the token.
    let mut request = TestRequest::patch("/v1/me/profile")
        .json(&json!({"display_name": "Mallory"}))
        .header("origin", "https://evil.example")
        .header("x-csrf-token", browser.csrf.as_deref().unwrap());
    for (name, value) in &browser.cookies {
        request = request.cookie(name, value);
    }
    app.send(request)
        .await
        .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn crv_09_forged_tokens_are_refused_through_the_stack(pool: PgPool) {
    let app = App::new(pool).await;
    // alg none / garbage tokens.
    let none = "eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJ4In0.";
    for token in [none, "garbage", "a.b.c"] {
        let res = app.send(TestRequest::get("/v1/me").bearer(token)).await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        assert!(
            res.header("www-authenticate")
                .is_some_and(|h| h.contains("invalid_token")),
            "{token}"
        );
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_02_one_time_reset_token_is_consumed_exactly_once_under_concurrency(pool: PgPool) {
    let app = App::new(pool).await;
    app.user("alice@example.com").await;
    let mut b = app.browser();
    b.csrf(&app).await;
    b.send(
        &app,
        b.post(
            "/v1/password/forgot",
            &json!({"email": "alice@example.com"}),
        ),
    )
    .await;
    app.drain().await;
    let authn_core::ports::NotificationKind::PasswordReset { token, .. } =
        app.last_notification("password_reset")
    else {
        panic!()
    };
    let token = token.expose().to_owned();
    let requests = (0..8).map(|i| {
        app.send(b.post(
            "/v1/password/reset",
            &json!({"token": token, "new_password": format!("brand new passphrase number {i}")}),
        ))
    });
    let results = futures::future::join_all(requests).await;
    let ok = results.iter().filter(|r| r.status.is_success()).count();
    assert_eq!(
        ok,
        1,
        "exactly one reset wins: {:?}",
        results.iter().map(|r| r.status).collect::<Vec<_>>()
    );
}
