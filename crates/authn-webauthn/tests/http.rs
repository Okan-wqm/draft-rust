#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! HTTP level: router, error envelopes, OpenAPI, well-known documents
//! (PKY-01, PKY-04, PKY-07, ARC-03).

mod common;

use authn_core::config::webauthn::{AndroidApp, WebauthnConfig};
use authn_testkit::http::{TestRequest, with_request_context};
use authn_webauthn::{WebauthnApi, WellKnownDocuments, well_known_router};
use common::{Harness, ORIGIN, create};
use http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use utoipa::OpenApi;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_http_registration_and_management_flow(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    h.set_password(alice.user).await;
    let app = h.app_as(h.fresh(alice));

    let res = TestRequest::post("/v1/me/passkeys/registration/options")
        .json(&json!({ "name": "My phone" }))
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let start: Value = res.json();
    let ceremony_id = start["ceremony_id"].as_str().unwrap().to_owned();
    assert!(start["options"]["publicKey"]["challenge"].is_string());

    let mut authenticator = SoftPasskey::new(true);
    let credential = create(&mut authenticator, &start["options"], ORIGIN);
    let res = TestRequest::post("/v1/me/passkeys/registration/verify")
        .json(&json!({ "ceremony_id": ceremony_id, "credential": credential }))
        .send(&app)
        .await;
    res.assert_status(StatusCode::CREATED);
    let passkey: Value = res.json();
    assert_eq!(passkey["name"], "My phone");
    assert_eq!(passkey["usage"], "both");
    let id = passkey["id"].as_str().unwrap().to_owned();

    // Replay over HTTP.
    TestRequest::post("/v1/me/passkeys/registration/verify")
        .json(&json!({ "ceremony_id": ceremony_id, "credential": credential }))
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");

    let res = TestRequest::get("/v1/me/passkeys").send(&app).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let list: Value = res.json();
    assert_eq!(list["passkeys"][0]["id"], id);

    let res = TestRequest::patch(&format!("/v1/me/passkeys/{id}"))
        .json(&json!({ "name": "Work phone" }))
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["name"], "Work phone");

    TestRequest::patch(&format!("/v1/me/passkeys/{id}"))
        .json(&json!({ "name": "x", "admin": true }))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");

    let res = TestRequest::delete(&format!("/v1/me/passkeys/{id}"))
        .send(&app)
        .await;
    res.assert_status(StatusCode::NO_CONTENT);
    TestRequest::delete(&format!("/v1/me/passkeys/{id}"))
        .send(&app)
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    TestRequest::delete("/v1/me/passkeys/not-a-uuid")
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "bad_request");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_http_endpoints_require_authentication_and_step_up(pool: PgPool) {
    let h = Harness::new(pool).await;
    let anonymous = h.app();
    TestRequest::get("/v1/me/passkeys")
        .send(&anonymous)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    TestRequest::post("/v1/me/passkeys/registration/options")
        .json(&json!({}))
        .send(&anonymous)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");

    let alice = h.account("alice@example.com").await;
    let stale = h.app_as(h.stale(alice));
    TestRequest::post("/v1/me/passkeys/registration/options")
        .json(&json!({}))
        .send(&stale)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    // Malformed credential JSON never echoes the input.
    let fresh = h.app_as(h.fresh(alice));
    let start: Value = TestRequest::post("/v1/me/passkeys/registration/options")
        .json(&json!({ "usage": "second_factor" }))
        .send(&fresh)
        .await
        .json();
    let res = TestRequest::post("/v1/me/passkeys/registration/verify")
        .json(&json!({ "ceremony_id": start["ceremony_id"], "credential": { "id": "<script>" } }))
        .send(&fresh)
        .await;
    res.assert_error(StatusCode::BAD_REQUEST, "passkey_registration_failed");
    assert!(!res.text().contains("<script>"));
    TestRequest::post("/v1/me/passkeys/registration/options")
        .json(&json!({ "usage": "superuser" }))
        .send(&fresh)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[test]
fn pky_04_openapi_documents_every_endpoint() {
    let doc = serde_json::to_value(WebauthnApi::openapi()).unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for path in [
        "/v1/me/passkeys",
        "/v1/me/passkeys/{passkey_id}",
        "/v1/me/passkeys/registration/options",
        "/v1/me/passkeys/registration/verify",
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/.well-known/webauthn",
    ] {
        assert!(paths.contains_key(path), "{path} missing");
    }
}

const FP: &str = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";

#[tokio::test]
async fn pky_07_well_known_documents_are_served_as_json_without_user_data() {
    let config = WebauthnConfig {
        rp_id: "example.com".to_owned(),
        allowed_origins: vec!["https://example.com".to_owned()],
        apple_app_ids: vec!["ABCDE12345.com.example.app".to_owned()],
        android_apps: vec![AndroidApp {
            package_name: "com.example.app".to_owned(),
            sha256_cert_fingerprints: vec![FP.to_owned()],
        }],
        related_origins: vec!["https://example.co.uk".to_owned()],
        ..WebauthnConfig::default()
    };
    let documents = WellKnownDocuments::from_config(&config).unwrap();
    let app = with_request_context(well_known_router().with_state(documents));

    for path in [
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/.well-known/webauthn",
    ] {
        // Request details (Host, query) cannot influence the document.
        let res = TestRequest::get(&format!("{path}?x=%3Cscript%3E"))
            .header("host", "evil.example")
            .send(&app)
            .await;
        res.assert_status(StatusCode::OK);
        assert_eq!(res.header("content-type"), Some("application/json"));
        assert_eq!(res.header("cache-control"), Some("public, max-age=3600"));
        assert_eq!(res.header("x-content-type-options"), Some("nosniff"));
        let body = res.text();
        assert!(!body.contains("evil") && !body.contains("script"), "{body}");
        let _: Value = res.json();
    }
    let aasa: Value = TestRequest::get("/.well-known/apple-app-site-association")
        .send(&app)
        .await
        .json();
    assert_eq!(
        aasa,
        json!({ "webcredentials": { "apps": ["ABCDE12345.com.example.app"] } })
    );
    let related: Value = TestRequest::get("/.well-known/webauthn")
        .send(&app)
        .await
        .json();
    assert_eq!(related, json!({ "origins": ["https://example.co.uk"] }));
}

#[tokio::test]
async fn pky_07_unconfigured_documents_answer_not_found() {
    let documents = WellKnownDocuments::from_config(&WebauthnConfig::default()).unwrap();
    let app = with_request_context(well_known_router().with_state(documents));
    for path in [
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/.well-known/webauthn",
    ] {
        TestRequest::get(path)
            .send(&app)
            .await
            .assert_error(StatusCode::NOT_FOUND, "not_found");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_07_service_exposes_the_rendered_documents(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.webauthn.apple_app_ids = vec!["ABCDE12345.com.example.app".to_owned()];
    })
    .await;
    let documents = h.service.well_known();
    assert!(documents.apple_app_site_association().is_some());
    assert!(documents.asset_links().is_none());
}
