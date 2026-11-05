#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OPS-04: the Prometheus metrics the requirement lists are produced by
//! the real application — login success/failure by reason code, MFA usage,
//! registrations, reset requests, rate-limit triggers, token reuse
//! detections, outbox queue depth and request latency histograms — and
//! carry no user data.
//!
//! The recorder is process-global, so this test binary holds this single
//! test (it installs the same exporter `serve` installs, without the HTTP
//! listener).

mod common;

use std::time::Duration;

use authn_core::ports::RateLimitPolicy;
use common::{App, PASSWORD};
use http::StatusCode;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use serde_json::json;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_04_metrics_cover_the_required_signals(pool: PgPool) {
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(authn_server::metrics::HTTP_REQUEST_DURATION.to_owned()),
            authn_server::metrics::LATENCY_BUCKETS,
        )
        .unwrap()
        .build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).unwrap();

    let app = App::new(pool.clone()).await;
    app.user("alice@example.com").await;

    // Login failure (by reason code) and success.
    let mut browser = app.browser();
    browser.csrf(&app).await;
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/login/password",
                &json!({"email": "alice@example.com", "password": "wrong password 1234"}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");

    // MFA usage: an e-mail code sent for an enrollment.
    let r = browser
        .send(&app, browser.post("/v1/me/mfa/email", &json!({})))
        .await;
    assert!(r.status.is_success(), "{}", r.text());

    // Registration and a password-reset request.
    let mut stranger = app.browser();
    stranger.csrf(&app).await;
    let r = stranger
        .send(
            &app,
            stranger.post(
                "/v1/signup",
                &json!({"email": "bob@example.com", "password": PASSWORD, "accepted_terms": []}),
            ),
        )
        .await;
    assert!(
        r.status.is_client_error() || r.status.is_success(),
        "{}",
        r.text()
    );
    let r = stranger
        .send(
            &app,
            stranger.post(
                "/v1/password/forgot",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;

    // Refresh-token reuse (SES-05); a user without a login history, so no
    // new-device confirmation (RSK-03) is asked.
    app.user("carol@example.com").await;
    let mut native = app.native();
    let r = app
        .send(native.post(
            "/v1/login/password",
            &json!({"email": "carol@example.com", "password": PASSWORD}),
        ))
        .await;
    native.absorb(&r.json());
    let first = native.refresh.clone().unwrap();
    let r = app
        .send(native.post("/v1/token/refresh", &json!({"refresh_token": first})))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.advance(Duration::from_secs(120));
    let r = app
        .send(native.post("/v1/token/refresh", &json!({"refresh_token": first})))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());

    // Per-IP rate limit (PRT-01) on a second instance with a tiny budget.
    let limited = App::with(pool.clone(), |config| {
        config.protect.rate_limit.requests_per_ip =
            RateLimitPolicy::new(2, Duration::from_secs(60));
    })
    .await;
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(
            limited
                .send(authn_testkit::http::TestRequest::get("/v1/terms"))
                .await
                .status,
        );
    }
    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );

    // Outbox queue depth: published by the outbox worker of the jobs.
    let shutdown = CancellationToken::new();
    let mut jobs = authn_server::jobs::spawn(app.services.clone(), shutdown.clone()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !handle.render().contains("authn_outbox_queue_depth")
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    shutdown.cancel();
    while jobs.join_next().await.is_some() {}

    let text = handle.render();
    for family in [
        "authn_logins_total",
        "authn_login_failures_total",
        "authn_mfa_codes_sent_total",
        "authn_account_registrations_total",
        "authn_password_reset_requests_total",
        "authn_rate_limit_triggered_total",
        "authn_refresh_token_reuse_total",
        "authn_outbox_queue_depth",
        "authn_http_request_duration_seconds_bucket",
    ] {
        assert!(text.contains(family), "missing {family}:\n{text}");
    }
    // Failures are counted by stable reason code.
    assert!(
        text.lines()
            .any(|l| l.starts_with("authn_login_failures_total{") && l.contains("reason=")),
        "{text}"
    );
    // Latency is labelled by route template and status class only.
    assert!(
        text.contains(r#"route="/v1/login/password""#) && text.contains(r#"status="4xx""#),
        "{text}"
    );
    assert!(text.contains(r#"route="/v1/terms""#), "{text}");
    // No user data in any series.
    for secret in ["alice", "bob", "carol", "example.com", PASSWORD] {
        assert!(!text.contains(secret), "{secret} leaked into metrics");
    }
}
