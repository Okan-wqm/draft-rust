#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! HTTP level (router + `oneshot`): MFA-10 status endpoint, MFA-07 factor
//! management with step-up, MFA-01 TOTP flow, MFA-04 recovery codes,
//! MFA-09 trusted-device endpoints, OpenAPI document, and that error
//! bodies never echo codes or secrets.

mod common;

use std::time::Duration;

use authn_crypto::totp::TotpSecret;
use authn_mfa::MfaApi;
use authn_testkit::http::TestRequest;
use common::Harness;
use http::StatusCode;
use serde_json::{Value, json};
use utoipa::OpenApi as _;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_10_endpoints_require_an_authenticated_principal(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let app = h.app();
    for (method, uri) in [
        ("GET", "/v1/me/mfa"),
        ("POST", "/v1/me/mfa/totp"),
        ("POST", "/v1/me/mfa/email"),
        ("GET", "/v1/me/mfa/recovery-codes"),
        ("GET", "/v1/me/mfa/trusted-devices"),
    ] {
        let req = TestRequest::new(method.parse().unwrap(), uri);
        req.send(&app)
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_http_totp_enrollment_flow(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let app = h.app_as(h.fresh(user));
    let res = TestRequest::post("/v1/me/mfa/totp")
        .json(&json!({"label": "Authenticator"}))
        .send(&app)
        .await;
    res.assert_status(StatusCode::CREATED);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: Value = res.json();
    let factor_id = body["factor"]["id"].as_str().unwrap().to_owned();
    assert_eq!(body["factor"]["status"], "pending");
    assert!(
        body["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    assert!(body["qr_code_svg"].as_str().unwrap().contains("<svg"));
    let secret = TotpSecret::from_base32(body["secret"].as_str().unwrap()).unwrap();

    // A wrong code: 400 invalid_code; the code is not echoed.
    let res = TestRequest::post(&format!("/v1/me/mfa/factors/{factor_id}/confirm"))
        .json(&json!({"code": "000000"}))
        .send(&app)
        .await;
    if res.status != StatusCode::OK {
        res.assert_error(StatusCode::BAD_REQUEST, "invalid_code");
        assert!(!res.text().contains("000000"));
    }
    let code = h.totp_code(&secret, 0);
    let res = TestRequest::post(&format!("/v1/me/mfa/factors/{factor_id}/confirm"))
        .json(&json!({"code": code}))
        .send(&app)
        .await;
    if res.status == StatusCode::OK {
        let body: Value = res.json();
        assert_eq!(body["factor"]["status"], "active");
        assert_eq!(
            body["recovery_codes"]["codes"].as_array().unwrap().len(),
            10
        );
    } else {
        // "000000" happened to be the valid code above.
        res.assert_error(StatusCode::CONFLICT, "mfa_enrollment_not_pending");
    }
    // Status: no secret anywhere.
    let res = TestRequest::get("/v1/me/mfa").send(&app).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let text = res.text();
    assert!(!text.contains(secret.to_base32().as_str()));
    let body: Value = res.json();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["factors"][0]["kind"], "totp");
    assert_eq!(body["factors"][0]["label"], "Authenticator");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_http_step_up_and_removal(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let stale = h.app_as(h.principal(user, Duration::from_secs(3600)));
    TestRequest::delete(&format!("/v1/me/mfa/factors/{}", f.id))
        .send(&stale)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    let app = h.app_as(h.fresh(user));
    TestRequest::delete("/v1/me/mfa/factors/not-a-uuid")
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "bad_request");
    TestRequest::delete(&format!(
        "/v1/me/mfa/factors/{}",
        authn_core::id::FactorId::generate()
    ))
    .send(&app)
    .await
    .assert_error(StatusCode::NOT_FOUND, "not_found");
    h.policy.require_mfa();
    TestRequest::delete(&format!("/v1/me/mfa/factors/{}", f.id))
        .send(&app)
        .await
        .assert_error(StatusCode::CONFLICT, "mfa_last_factor_required");
    *h.policy.org.lock().unwrap() = None;
    TestRequest::delete(&format!("/v1/me/mfa/factors/{}", f.id))
        .send(&app)
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_06_http_sms_enrollment_validation(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let app = h.app_as(h.fresh(user));
    TestRequest::post("/v1/me/mfa/sms")
        .json(&json!({"phone_number": "0555 111 22 33"}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "mfa_invalid_phone_number");
    TestRequest::post("/v1/me/mfa/sms")
        .json(&json!({"phone_number": "+447911123456"}))
        .send(&app)
        .await
        .assert_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "mfa_phone_country_not_allowed",
        );
    let res = TestRequest::post("/v1/me/mfa/sms")
        .json(&json!({"phone_number": "+905551112233", "label": "Mobile"}))
        .send(&app)
        .await;
    res.assert_status(StatusCode::ACCEPTED);
    let body: Value = res.json();
    assert_eq!(body["channel"], "sms");
    assert_eq!(body["destination"], "+90*******233");
    // Unknown fields are refused.
    TestRequest::post("/v1/me/mfa/sms")
        .json(&json!({"phone_number": "+905551112233", "admin": true}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_10_error_bodies_never_echo_codes(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let app = h.app_as(h.fresh(user));
    let pending = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap();
    let uri = format!("/v1/me/mfa/factors/{}/confirm", pending.factor.id);
    // Number instead of string: 422 without the value.
    let res = TestRequest::post(&uri)
        .json(&json!({"code": 987_654}))
        .send(&app)
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert!(!res.text().contains("987654"));
    // Broken JSON: 400 without the content.
    let res = TestRequest::post(&uri)
        .header("content-type", "application/json")
        .body("{\"code\": \"123456")
        .send(&app)
        .await;
    res.assert_error(StatusCode::BAD_REQUEST, "bad_request");
    assert!(!res.text().contains("123456"));
    // Wrong content type.
    TestRequest::post(&uri)
        .header("content-type", "text/plain")
        .body("123456")
        .send(&app)
        .await
        .assert_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_04_http_recovery_codes(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    let app = h.app_as(h.fresh(user));
    let res = TestRequest::get("/v1/me/mfa/recovery-codes")
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["remaining"], 10);
    let res = TestRequest::post("/v1/me/mfa/recovery-codes")
        .send(&app)
        .await;
    res.assert_status(StatusCode::CREATED);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: Value = res.json();
    assert_eq!(body["codes"].as_array().unwrap().len(), 10);
    assert!(body["generated_at"].as_str().is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_http_trusted_devices(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let issued = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    let app = h.app_as(h.fresh(user));
    let res = TestRequest::get("/v1/me/mfa/trusted-devices")
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    assert!(!res.text().contains(issued.token.expose()));
    TestRequest::delete(&format!("/v1/me/mfa/trusted-devices/{}", issued.device_id))
        .send(&app)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    TestRequest::delete(&format!("/v1/me/mfa/trusted-devices/{}", issued.device_id))
        .send(&app)
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    let res = TestRequest::delete("/v1/me/mfa/trusted-devices")
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["revoked"], 0);
}

#[test]
fn mfa_10_openapi_document_lists_every_endpoint() {
    let doc = MfaApi::openapi();
    let json = serde_json::to_value(&doc).unwrap();
    let paths = json["paths"].as_object().unwrap();
    for path in [
        "/v1/me/mfa",
        "/v1/me/mfa/totp",
        "/v1/me/mfa/email",
        "/v1/me/mfa/sms",
        "/v1/me/mfa/factors/{factor_id}",
        "/v1/me/mfa/factors/{factor_id}/confirm",
        "/v1/me/mfa/factors/{factor_id}/resend",
        "/v1/me/mfa/recovery-codes",
        "/v1/me/mfa/trusted-devices",
        "/v1/me/mfa/trusted-devices/{device_id}",
    ] {
        assert!(paths.contains_key(path), "{path} missing");
    }
    assert!(json["components"]["schemas"]["MfaStatus"].is_object());
}
