#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! HTTP level (router + `oneshot`): PWD-05 check endpoint, PWD-07/08
//! enumeration safety (status, body, timing) and Host-header independence,
//! PWD-09 reset endpoint, PWD-06/10/11 self-service endpoints.

mod common;

use std::time::Duration;

use authn_core::domain::LoginMethod;
use authn_core::ports::{NotificationKind, RateLimitPolicy};
use authn_password::PasswordApi;
use authn_testkit::http::TestRequest;
use authn_testkit::timing::compare_timings;
use common::{Harness, STRONG, STRONG_2};
use http::StatusCode;
use serde_json::{Value, json};
use utoipa::OpenApi as _;

fn generous(s: &mut authn_password::PasswordServiceSettings) {
    let lots = RateLimitPolicy::new(100_000, Duration::from_secs(3600));
    s.password.reset.per_email = lots;
    s.password.reset.per_ip = lots;
    s.password.reset.verify_per_ip = lots;
    s.password.reset.code_attempts_per_email = lots;
    s.password.reset.code_max_attempts = 100;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_05_check_endpoint_returns_verdict_with_localized_feedback(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let app = h.app();
    let res = TestRequest::post("/v1/password/check")
        .accept_language("tr-TR")
        .json(&json!({"password": "password1234", "email": "ali@example.com"}))
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: Value = res.json();
    assert_eq!(body["acceptable"], false);
    assert_eq!(body["violations"][0]["code"], "too_weak");
    assert_eq!(body["violations"][0]["min_score"], 3);
    assert!(
        body["feedback"]
            .as_array()
            .unwrap()
            .contains(&json!("Bu şifre çok kolay tahmin edilebilir."))
    );
    assert!(!res.text().contains("password1234"));

    let res = TestRequest::post("/v1/password/check")
        .json(&json!({"password": STRONG, "display_name": "Ali Veli"}))
        .send(&app)
        .await;
    let body: Value = res.json();
    assert_eq!(body["acceptable"], true);
    assert_eq!(body["violations"], json!([]));
    assert_eq!(body["breach_check_skipped"], false);
    assert!(body["score"].as_u64().unwrap() >= 3);

    let res = TestRequest::post("/v1/password/check")
        .json(&json!({"password": "short"}))
        .send(&app)
        .await;
    let body: Value = res.json();
    assert_eq!(
        body["violations"][0],
        json!({"code": "too_short", "min": 12})
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_05_check_endpoint_is_rate_limited_per_ip(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let app = h.app();
    let attacker: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    for _ in 0..30 {
        TestRequest::post("/v1/password/check")
            .peer_ip(attacker)
            .json(&json!({"password": "anything at all 123"}))
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
    }
    let res = TestRequest::post("/v1/password/check")
        .peer_ip(attacker)
        .json(&json!({"password": "anything at all 123"}))
        .send(&app)
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
    TestRequest::post("/v1/password/check")
        .peer_ip("198.51.100.8".parse().unwrap())
        .json(&json!({"password": "anything at all 123"}))
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_05_malformed_bodies_get_envelopes_that_never_echo_the_password(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let app = h.app();
    let res = TestRequest::post("/v1/password/check")
        .header("content-type", "text/plain")
        .body("hunter2hunter2")
        .send(&app)
        .await;
    res.assert_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    let res = TestRequest::post("/v1/password/check")
        .header("content-type", "application/json")
        .body("{\"password\": \"hunter2hunter2\"")
        .send(&app)
        .await;
    res.assert_error(StatusCode::BAD_REQUEST, "bad_request");
    assert!(!res.text().contains("hunter2"));
    let res = TestRequest::post("/v1/password/check")
        .json(&json!({"password": 987_654_321_123_u64}))
        .send(&app)
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert!(!res.text().contains("987654321123"));
    let res = TestRequest::post("/v1/password/check")
        .json(&json!({"password": "x", "role": "admin"}))
        .send(&app)
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    let res = TestRequest::post("/v1/password/check")
        .json(&json!({"password": "x", "display_name": "n".repeat(300)}))
        .send(&app)
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_forgot_answers_identically_for_known_and_unknown_accounts(pool: sqlx::PgPool) {
    let h = Harness::with(pool, generous).await;
    h.user("known@example.com", Some(STRONG)).await;
    h.user("nopassword@example.com", None).await;
    let app = h.app();
    let send = |address: &'static str| {
        let app = app.clone();
        async move {
            TestRequest::post("/v1/password/forgot")
                .json(&json!({ "email": address }))
                .send(&app)
                .await
        }
    };
    let known = send("known@example.com").await;
    let unknown = send("unknown@example.com").await;
    let passwordless = send("nopassword@example.com").await;
    for res in [&known, &unknown, &passwordless] {
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.body, known.body);
        assert_eq!(res.json::<Value>(), json!({"status": "accepted"}));
        let mut names: Vec<_> = res
            .headers
            .keys()
            .filter(|n| n.as_str() != "x-request-id")
            .map(|n| n.as_str().to_owned())
            .collect();
        names.sort();
        let mut expected: Vec<_> = known
            .headers
            .keys()
            .filter(|n| n.as_str() != "x-request-id")
            .map(|n| n.as_str().to_owned())
            .collect();
        expected.sort();
        assert_eq!(names, expected);
        assert_eq!(res.header("content-length"), known.header("content-length"));
    }
    h.service.drain_background_jobs().await;
    assert_eq!(h.ports.notifier.with_template("password_reset").len(), 1);

    // Timing: the account lookup happens after the response.
    let report = compare_timings(
        31,
        || async {
            send("known@example.com").await;
        },
        || async {
            send("unknown@example.com").await;
        },
    )
    .await;
    report.assert_indistinguishable(0.3);
    h.service.drain_background_jobs().await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_forgot_rate_limits_answer_429_alike(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    h.user("known@example.com", Some(STRONG)).await;
    let app = h.app();
    let mut bodies = Vec::new();
    for address in ["known@example.com", "unknown@example.com"] {
        for _ in 0..3 {
            TestRequest::post("/v1/password/forgot")
                .json(&json!({ "email": address }))
                .send(&app)
                .await
                .assert_status(StatusCode::ACCEPTED);
        }
        let res = TestRequest::post("/v1/password/forgot")
            .json(&json!({ "email": address }))
            .send(&app)
            .await;
        let err = res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        bodies.push((
            err.code,
            err.message,
            res.header("retry-after").map(str::to_owned),
        ));
    }
    assert_eq!(bodies[0], bodies[1]);
    h.service.drain_background_jobs().await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_08_reset_email_never_depends_on_the_host_header(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    h.user("victim@example.com", Some(STRONG)).await;
    let app = h.app();
    TestRequest::post("/v1/password/forgot")
        .header("host", "evil.example")
        .header("x-forwarded-host", "evil.example")
        .header("forwarded", "host=evil.example;proto=http")
        .header("origin", "https://evil.example")
        .json(&json!({"email": "victim@example.com"}))
        .send(&app)
        .await
        .assert_status(StatusCode::ACCEPTED);
    h.service.drain_background_jobs().await;
    let sent = h.ports.notifier.with_template("password_reset");
    assert_eq!(sent.len(), 1);
    // The notifier gets the raw token only; authn-notify builds the link from
    // server.public_base_url. Nothing request-derived ends up in the e-mail.
    let NotificationKind::PasswordReset { token, code, .. } = &sent[0].kind else {
        panic!("unexpected notification");
    };
    assert_eq!(token.len(), 43);
    assert!(code.is_some());
    let serialized = serde_json::to_string(&sent[0]).unwrap();
    assert!(!serialized.contains("evil"), "{serialized}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_08_code_errors_are_identical_for_known_and_unknown_accounts(pool: sqlx::PgPool) {
    let h = Harness::with(pool, generous).await;
    h.user("known@example.com", Some(STRONG)).await;
    let (_, code) = h.forgot("known@example.com").await;
    let code = code.unwrap();
    let bad = if code == "000000" { "111111" } else { "000000" };
    let app = h.app();
    let mut errors = Vec::new();
    for address in ["known@example.com", "unknown@example.com"] {
        let res = TestRequest::post("/v1/password/reset")
            .json(&json!({"email": address, "code": bad, "new_password": STRONG_2}))
            .send(&app)
            .await;
        let err = res.assert_error(StatusCode::BAD_REQUEST, "invalid_code");
        errors.push((err.code, err.message, err.details));
    }
    assert_eq!(errors[0], errors[1]);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_reset_endpoint_replaces_the_password_without_issuing_a_session(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com", Some(STRONG)).await;
    let (token, _) = h.forgot("alice@example.com").await;
    let app = h.app();
    let res = TestRequest::post("/v1/password/reset")
        .json(&json!({"token": token, "new_password": STRONG_2}))
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>(), json!({"status": "password_reset"}));
    assert!(res.set_cookies().is_empty());
    assert_eq!(res.header("cache-control"), Some("no-store"));
    assert!(h.ports.session_issuer.logins().is_empty());
    assert!(h.password_is(user, STRONG_2).await);
    // Replay.
    TestRequest::post("/v1/password/reset")
        .json(&json!({"token": token, "new_password": STRONG}))
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
    // Ambiguous or incomplete proofs.
    for body in [
        json!({"token": token, "email": "alice@example.com", "code": "123456", "new_password": STRONG}),
        json!({"email": "alice@example.com", "new_password": STRONG}),
        json!({"new_password": STRONG}),
    ] {
        TestRequest::post("/v1/password/reset")
            .json(&body)
            .send(&app)
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_06_change_endpoint_requires_a_session_principal(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("bob@example.com", Some(STRONG)).await;
    TestRequest::post("/v1/me/password/change")
        .json(&json!({"current_password": STRONG, "new_password": STRONG_2}))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let app = h.app_as(h.principal(user, Duration::from_secs(3600)));
    TestRequest::post("/v1/me/password/change")
        .json(&json!({"current_password": STRONG_2, "new_password": STRONG}))
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "current_password_incorrect");
    TestRequest::post("/v1/me/password/change")
        .json(&json!({"new_password": STRONG_2}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    let res = TestRequest::post("/v1/me/password/change")
        .json(&json!({"current_password": STRONG, "new_password": STRONG_2}))
        .send(&app)
        .await;
    res.assert_status(StatusCode::NO_CONTENT);
    assert!(h.password_is(user, STRONG_2).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_10_and_pwd_11_add_and_remove_endpoints(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("carol@example.com", None).await;
    let app = h.app_as(h.principal(user, Duration::from_secs(30)));
    TestRequest::post("/v1/me/password")
        .json(&json!({"new_password": STRONG}))
        .send(&app)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    TestRequest::post("/v1/me/password")
        .json(&json!({"new_password": STRONG_2}))
        .send(&app)
        .await
        .assert_error(StatusCode::CONFLICT, "password_already_set");
    TestRequest::delete("/v1/me/password")
        .send(&app)
        .await
        .assert_error(StatusCode::CONFLICT, "password_removal_not_allowed");
    *h.methods.0.lock().unwrap() = vec![LoginMethod::Passkey];
    TestRequest::delete("/v1/me/password")
        .send(&app)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let stale = h.app_as(h.principal(user, Duration::from_secs(3600)));
    TestRequest::post("/v1/me/password")
        .json(&json!({"new_password": STRONG}))
        .send(&stale)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
}

#[test]
fn pwd_05_openapi_documents_every_endpoint() {
    let doc = serde_json::to_value(PasswordApi::openapi()).unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for path in [
        "/v1/password/check",
        "/v1/password/forgot",
        "/v1/password/reset",
        "/v1/me/password/change",
        "/v1/me/password",
    ] {
        assert!(paths.contains_key(path), "{path} missing");
    }
    assert!(paths["/v1/me/password"].get("delete").is_some());
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    assert_eq!(
        schemas["CheckPasswordRequest"]["properties"]["password"]["format"],
        "password"
    );
}
