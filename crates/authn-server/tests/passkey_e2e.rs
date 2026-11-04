#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Passkeys end to end over HTTP (TST-06): registration (PKY-01), passkey
//! step-up — the success path (SES-13) — and username-less passkey login
//! (SES-20, SES-21), with a software authenticator.

mod common;

use axum::http::StatusCode;
use common::{App, ORIGIN, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::{AllowCredentials, CreationChallengeResponse, RequestChallengeResponse};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_06_passkey_registration_step_up_and_login(pool: PgPool) {
    let app = App::new(pool).await;
    let user = app.user("alice@example.com").await;
    let mut browser = app.browser();
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");

    // Registration (fresh login: no step-up needed).
    let r = browser
        .send(
            &app,
            browser.post("/v1/me/passkeys/registration/options", &json!({})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let start: Value = r.json();
    let ccr: CreationChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    let mut key = SoftPasskey::new(true);
    let credential = key
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .unwrap();
    let raw_id = credential.raw_id.clone();
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/me/passkeys/registration/verify",
                &json!({"ceremony_id": start["ceremony_id"], "credential": credential}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());

    // Step-up with the passkey: success path (SES-13).
    app.advance(std::time::Duration::from_secs(3600));
    let r = browser
        .send(&app, browser.post("/v1/reauth/passkey/options", &json!({})))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let options: Value = r.json();
    let rcr: RequestChallengeResponse = serde_json::from_value(options["options"].clone()).unwrap();
    let assertion = key
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .unwrap();
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/reauth",
                &json!({"method": "passkey", "ceremony_id": options["ceremony_id"], "credential": assertion}),
            ),
        )
        .await;
    let body: Value = r.json();
    assert_eq!(r.status, StatusCode::OK, "{body}");
    assert!(
        body["amr"].as_array().unwrap().contains(&json!("hwk")),
        "{body}"
    );
    assert!(
        body["amr"].as_array().unwrap().contains(&json!("mfa")),
        "{body}"
    );

    // Username-less passkey login from a new browser: no password, no
    // challenge (a user-verified passkey is MFA; it is also not risky).
    let (handle,): (Vec<u8>,) =
        sqlx::query_as("SELECT user_handle FROM webauthn_user_handles WHERE user_id = $1")
            .bind(user)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let mut other = app.browser();
    other.csrf(&app).await;
    let r = other
        .send(&app, other.post("/v1/login/passkey/options", &json!({})))
        .await;
    let options: Value = r.json();
    let mut rcr: RequestChallengeResponse =
        serde_json::from_value(options["options"].clone()).unwrap();
    rcr.public_key.allow_credentials = vec![AllowCredentials {
        type_: "public-key".to_owned(),
        id: raw_id,
        transports: None,
    }];
    let mut assertion = key
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .unwrap();
    assertion.response.user_handle = Some(handle);
    let r = other
        .send(
            &app,
            other.post(
                "/v1/login/passkey",
                &json!({"ceremony_id": options["ceremony_id"], "credential": assertion}),
            ),
        )
        .await;
    let body: Value = r.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(body["user_id"], json!(user));
    assert_eq!(app.send(other.get("/v1/me")).await.status, StatusCode::OK);
}
