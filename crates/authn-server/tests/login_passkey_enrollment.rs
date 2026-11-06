#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-112: passkey enrollment inside the login challenge (SES-22, MFA-07,
//! MFA-08, PKY-01, ADM-05) through the real router, real sessions and real
//! PostgreSQL, with the software authenticator.
//!
//! Before K-112 an account whose only permitted factor is a passkey
//! (platform admins; an organization policy demanding `webauthn`) and that
//! had none could never finish a login: the challenge offered no passkey
//! enrollment. The password-created break-glass admin (K-110) was the
//! visible case.

mod common;

use std::sync::Arc;

use authn_core::id::UserId;
use authn_core::ports::{AuditSink, NotificationKind};
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::{App, Browser, Native, ORIGIN, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::{AllowCredentials, CreationChallengeResponse, RequestChallengeResponse};

const OPTIONS: &str = "/v1/login/challenge/passkey/register/options";
const VERIFY: &str = "/v1/login/challenge/passkey/register/verify";
const NEW_PASSWORD: &str = "harbour quartz meadow violin 82";

async fn make_admin(app: &App, user: UserId) {
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(user)
        .execute(&app.pool)
        .await
        .unwrap();
    // K-93: staff without a role row have no admin permission.
    sqlx::query(
        "INSERT INTO admin_staff_roles (user_id, role, granted_at, updated_at) \
         VALUES ($1, 'platform_admin', now(), now())",
    )
    .bind(user)
    .execute(&app.pool)
    .await
    .unwrap();
}

/// `navigator.credentials.create()` with the software authenticator.
fn create(key: &mut SoftPasskey, options: &Value) -> Value {
    let ccr: CreationChallengeResponse =
        serde_json::from_value(options["options"].clone()).unwrap();
    serde_json::to_value(
        key.do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .unwrap(),
    )
    .unwrap()
}

fn required_actions(body: &Value) -> Vec<String> {
    body["required_actions"]
        .as_array()
        .unwrap_or_else(|| panic!("no challenge: {body}"))
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect()
}

/// The e-mailed mailbox proof of a web challenge (PWD-12 / RSK-03).
async fn web_mailbox_proof(app: &App, browser: &mut Browser) -> Value {
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/login/challenge/send-code",
                &json!({"channel": "email_confirmation"}),
            ),
        )
        .await;
    r.assert_status(StatusCode::ACCEPTED);
    let NotificationKind::LoginCode { code, .. } = app.last_notification("login_code") else {
        panic!("login code")
    };
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "email_confirmation", "code": code.expose()}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()
}

/// A native login of a platform admin without any factor, up to the
/// `enroll_mfa` step (with the risk mailbox confirmation when the new
/// device demands one).
async fn native_admin_at_enrollment(app: &App, email: &str) -> Native {
    let mut native = app.native();
    let r = app
        .send(native.post(
            "/v1/login/password",
            &json!({"email": email, "password": PASSWORD}),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let mut body: Value = r.json();
    native.absorb(&body);
    if body["allowed_factors"] == json!(["email"]) {
        let r = app
            .send(native.post(
                "/v1/login/challenge/send-code",
                &json!({"channel": "email_confirmation"}),
            ))
            .await;
        r.assert_status(StatusCode::ACCEPTED);
        let NotificationKind::LoginCode { code, .. } = app.last_notification("login_code") else {
            panic!("login code")
        };
        let r = app
            .send(native.post(
                "/v1/login/challenge/verify",
                &json!({"method": "email_confirmation", "code": code.expose()}),
            ))
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        body = r.json();
    }
    assert_eq!(required_actions(&body), vec!["enroll_mfa"], "{body}");
    assert_eq!(body["allowed_factors"], json!(["webauthn"]), "{body}");
    native
}

/// A username-less passkey login in a fresh browser.
async fn passkey_login(app: &App, user: UserId, key: &mut SoftPasskey, raw_id: &[u8]) -> Value {
    let (handle,): (Vec<u8>,) =
        sqlx::query_as("SELECT user_handle FROM webauthn_user_handles WHERE user_id = $1")
            .bind(user)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let mut browser = app.browser();
    browser.csrf(app).await;
    let r = browser
        .send(app, browser.post("/v1/login/passkey/options", &json!({})))
        .await;
    let options: Value = r.json();
    let mut rcr: RequestChallengeResponse =
        serde_json::from_value(options["options"].clone()).unwrap();
    rcr.public_key.allow_credentials = vec![AllowCredentials {
        type_: "public-key".to_owned(),
        id: raw_id.to_vec(),
        transports: None,
    }];
    let mut assertion = key
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .unwrap();
    assertion.response.user_handle = Some(handle);
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/login/passkey",
                &json!({"ceremony_id": options["ceremony_id"], "credential": assertion}),
            ),
        )
        .await;
    r.json()
}

/// ADM-05 / SES-22 / K-112: the break-glass admin created with a password
/// (`create-admin` without `--passkey-link`) completes its first login end
/// to end: password → (must change) → e-mailed mailbox code → passkey
/// enrollment inside the challenge → new password → session that reaches
/// the admin API. The enrollment is not offered before the mailbox proof.
/// Before the fix the challenge had no passkey enrollment step and the
/// login could never complete.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_k112_password_break_glass_admin_completes_login_with_passkey_enrollment(
    pool: PgPool,
) {
    let app = App::new(pool).await;
    let audit: Arc<dyn AuditSink> = Arc::new(authn_audit::PgAuditSink::keyed(
        app.pool.clone(),
        app.ports.clock.clone(),
        app.services.audit.chain_keys().clone(),
    ));
    let created = authn_admin::create_break_glass_admin(
        &app.pool,
        &app.services.crypto.passwords,
        app.ports.clock.as_ref(),
        &audit,
        "root@example.com",
    )
    .await
    .unwrap();
    let password = created.password.expose().to_owned();

    // 1. Password: a challenge (mailbox proof, enrollment, new password).
    let mut browser = app.browser();
    let body = browser.login(&app, "root@example.com", &password).await;
    assert_eq!(body["status"], "challenge_required", "{body}");
    assert_eq!(
        required_actions(&body),
        vec!["verify_mfa", "enroll_mfa", "change_password"],
        "{body}"
    );
    assert_eq!(body["allowed_factors"], json!(["email"]), "{body}");

    // Not before the mailbox proof: whoever found the printed password
    // alone cannot enroll a passkey.
    let r = browser.send(&app, browser.post(OPTIONS, &json!({}))).await;
    r.assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");

    // 2. The e-mailed code.
    let body = web_mailbox_proof(&app, &mut browser).await;
    assert_eq!(
        required_actions(&body),
        vec!["enroll_mfa", "change_password"],
        "{body}"
    );
    assert_eq!(body["allowed_factors"], json!(["webauthn"]), "{body}");
    // No session yet.
    assert_eq!(
        app.send(browser.get("/v1/me")).await.status,
        StatusCode::UNAUTHORIZED
    );

    // 3. Passkey enrollment (web: binding token in a cookie, not the body).
    let r = browser.send(&app, browser.post(OPTIONS, &json!({}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(
        r.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-authn_passkey=") && c.contains("HttpOnly")),
        "binding cookie"
    );
    let options: Value = r.json();
    assert!(options.get("binding_token").is_none(), "{options}");
    let mut key = SoftPasskey::new(true);
    let credential = create(&mut key, &options);
    let raw_id: Vec<u8> = serde_json::from_value::<webauthn_rs_proto::RegisterPublicKeyCredential>(
        credential.clone(),
    )
    .unwrap()
    .raw_id;
    let r = browser
        .send(
            &app,
            browser.post(
                VERIFY,
                &json!({"ceremony_id": options["ceremony_id"], "credential": credential, "name": "Vault key"}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body: Value = r.json();
    assert_eq!(required_actions(&body), vec!["change_password"], "{body}");
    assert_eq!(body["data"]["passkey"]["name"], "Vault key", "{body}");
    assert_eq!(body["data"]["passkey"]["usage"], "both", "{body}");
    assert_eq!(
        app.send(browser.get("/v1/me")).await.status,
        StatusCode::UNAUTHORIZED,
        "still no session before the new password"
    );

    // 4. The new password: signed in.
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "change_password", "new_password": NEW_PASSWORD}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body: Value = r.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(app.send(browser.get("/v1/me")).await.status, StatusCode::OK);
    browser.csrf(&app).await;
    // The session counts the passkey as its (phishing-resistant) second
    // factor: the admin API opens.
    let r = app.send(browser.get("/v1/admin/users")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let (amr, factors): (Vec<String>, Vec<String>) = sqlx::query_as(
        "SELECT amr, mfa_factors FROM sessions WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(created.user_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(amr.contains(&"mfa".to_owned()), "{amr:?}");
    assert!(amr.iter().any(|a| a == "swk" || a == "hwk"), "{amr:?}");
    assert_eq!(factors, vec!["webauthn".to_owned()]);

    // Audited as a login-challenge enrollment by the account owner.
    let (count, actor): (i64, Option<String>) = sqlx::query_as(
        "SELECT count(*), min(actor_type) FROM audit_events WHERE kind = 'passkey.registered' \
         AND outcome = 'success' AND metadata->>'enrollment' = 'login_challenge'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(actor.as_deref(), Some("user"));

    // The enrolled passkey is a real login credential afterwards.
    let body = passkey_login(&app, created.user_id, &mut key, &raw_id).await;
    assert_eq!(body["status"], "authenticated", "{body}");
}

/// SES-22 / MFA-08 / K-112: a native client (binding token in the body)
/// enrolls the passkey a platform admin without any factor needs, and the
/// enrollment completes the login.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_k112_native_platform_admin_enrolls_a_passkey_during_login(pool: PgPool) {
    let app = App::new(pool).await;
    let id = app.user("admin@example.com").await;
    make_admin(&app, id).await;
    let mut native = native_admin_at_enrollment(&app, "admin@example.com").await;

    let r = app.send(native.post(OPTIONS, &json!({}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(r.set_cookies().is_empty(), "native clients get no cookie");
    let options: Value = r.json();
    let binding = options["binding_token"].as_str().unwrap().to_owned();
    let credential = create(&mut SoftPasskey::new(true), &options);
    let r = app
        .send(native.post(
            VERIFY,
            &json!({"ceremony_id": options["ceremony_id"], "binding_token": binding, "credential": credential}),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body: Value = r.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert!(body["access_token"].is_string(), "{body}");
    assert_eq!(body["data"]["passkey"]["usage"], "both", "{body}");
    native.absorb(&body);
    let r = app.send(native.get("/v1/me")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

/// PKY-01 / K-112: the enrollment ceremony is bound to its challenge and
/// single use. A ceremony of one challenge cannot be finished through
/// another challenge of the same user (and is not burnt by the attempt); a
/// ceremony whose first finish failed cannot be replayed with a valid
/// response; without a challenge nothing is offered; and the enrollment is
/// never offered to a challenge that does not demand one.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_k112_enrollment_ceremony_is_bound_to_its_challenge_and_single_use(pool: PgPool) {
    let app = App::new(pool).await;
    let id = app.user("admin@example.com").await;
    make_admin(&app, id).await;
    let first = native_admin_at_enrollment(&app, "admin@example.com").await;
    let second = native_admin_at_enrollment(&app, "admin@example.com").await;
    assert_ne!(first.challenge, second.challenge);

    // A ceremony of the first challenge, presented to the second.
    let r = app.send(first.post(OPTIONS, &json!({}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let options: Value = r.json();
    let credential = create(&mut SoftPasskey::new(true), &options);
    let finish = json!({
        "ceremony_id": options["ceremony_id"],
        "binding_token": options["binding_token"],
        "credential": credential,
    });
    let r = app.send(second.post(VERIFY, &finish)).await;
    r.assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");
    // Nor with a forged binding token through its own challenge.
    let mut forged = finish.clone();
    forged["binding_token"] = json!("not-the-binding-token");
    let r = app.send(first.post(VERIFY, &forged)).await;
    r.assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");
    let passkeys = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(id)
            .fetch_one(&app.pool)
            .await
            .unwrap()
    };
    assert_eq!(passkeys().await, 0);

    // Replay: the second challenge's own ceremony fails once (malformed
    // response: consumed before verification), then the valid response is
    // refused.
    let r = app.send(second.post(OPTIONS, &json!({}))).await;
    let options2: Value = r.json();
    let credential2 = create(&mut SoftPasskey::new(true), &options2);
    let mut broken = json!({
        "ceremony_id": options2["ceremony_id"],
        "binding_token": options2["binding_token"],
        "credential": {"id": "AAAA", "type": "public-key"},
    });
    let r = app.send(second.post(VERIFY, &broken)).await;
    r.assert_error(StatusCode::BAD_REQUEST, "passkey_registration_failed");
    broken["credential"] = credential2;
    let r = app.send(second.post(VERIFY, &broken)).await;
    r.assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");
    assert_eq!(passkeys().await, 0);

    // The first challenge's ceremony survived the foreign attempts.
    let r = app.send(first.post(VERIFY, &finish)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json::<Value>()["status"], "authenticated");
    assert_eq!(passkeys().await, 1);
    // Replaying the successful finish: the challenge is gone.
    let r = app.send(first.post(VERIFY, &finish)).await;
    r.assert_error(StatusCode::UNAUTHORIZED, "challenge_invalid");

    // Without a challenge (the primary factor was never verified) nothing
    // is offered.
    let r = app
        .send(
            TestRequest::post(OPTIONS)
                .json(&json!({}))
                .header("x-authn-client", "native"),
        )
        .await;
    r.assert_error(StatusCode::UNAUTHORIZED, "challenge_invalid");

    // A login that demands no enrollment never offers one.
    app.user("plain@example.com").await;
    let mut browser = app.browser();
    let body = browser.login(&app, "plain@example.com", PASSWORD).await;
    if body["status"] == "challenge_required" {
        let r = browser.send(&app, browser.post(OPTIONS, &json!({}))).await;
        r.assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    } else {
        // Signed in directly: the challenge cookie is gone.
        let r = browser.send(&app, browser.post(OPTIONS, &json!({}))).await;
        r.assert_error(StatusCode::UNAUTHORIZED, "challenge_invalid");
    }
}

/// SES-22 / ADM-01 / K-112 (audit): a platform admin without a passkey
/// (e.g. an existing account after `grant-admin`) never enrolls one with the
/// password alone, even when the login is not risky: the e-mailed mailbox
/// proof comes first. Before K-112 such a login was a dead end; the new
/// enrollment step must not turn a known password into an admin passkey.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_k112_platform_admin_enrollment_needs_a_mailbox_proof_first(pool: PgPool) {
    // No risk signal: only the policy decides.
    let app = App::with(pool, |c| c.protect.risk.enabled = false).await;
    let id = app.user("granted@example.com").await;
    make_admin(&app, id).await;

    let mut native = app.native();
    let r = app
        .send(native.post(
            "/v1/login/password",
            &json!({"email": "granted@example.com", "password": PASSWORD}),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body: Value = r.json();
    native.absorb(&body);
    assert_eq!(
        required_actions(&body),
        vec!["verify_mfa", "enroll_mfa"],
        "{body}"
    );
    assert_eq!(body["allowed_factors"], json!(["email"]), "{body}");
    let r = app.send(native.post(OPTIONS, &json!({}))).await;
    r.assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");

    // After the e-mailed code the passkey enrollment opens.
    let r = app
        .send(native.post(
            "/v1/login/challenge/send-code",
            &json!({"channel": "email_confirmation"}),
        ))
        .await;
    r.assert_status(StatusCode::ACCEPTED);
    let NotificationKind::LoginCode { code, .. } = app.last_notification("login_code") else {
        panic!("login code")
    };
    let r = app
        .send(native.post(
            "/v1/login/challenge/verify",
            &json!({"method": "email_confirmation", "code": code.expose()}),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body: Value = r.json();
    assert_eq!(required_actions(&body), vec!["enroll_mfa"], "{body}");
    assert_eq!(body["allowed_factors"], json!(["webauthn"]), "{body}");
    let r = app.send(native.post(OPTIONS, &json!({}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());

    // A regular account under an organization policy keeps the SES-22
    // enrollment after the primary factor (unchanged): only the platform
    // admin role demands the mailbox proof first.
}
