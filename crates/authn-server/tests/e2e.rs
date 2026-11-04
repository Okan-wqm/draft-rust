#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! End-to-end scenarios over the real router, every module wired together
//! (TST-06): registration → verification → login → MFA → logout → login
//! with TOTP and recovery code; password reset; native token rotation and
//! reuse detection; organizations, invitations, roles, policies and API
//! keys.

mod common;

use std::time::Duration;

use authn_core::ports::NotificationKind;
use axum::http::StatusCode;
use common::{App, Browser, PASSWORD, totp_code};
use serde_json::{Value, json};
use sqlx::PgPool;

/// Signs up `email` in `browser` and verifies the address with the
/// e-mailed link (same browser: the registration cookie proves it).
async fn register(app: &App, browser: &mut Browser, email: &str) -> Value {
    browser.csrf(app).await;
    let terms: Vec<Value> = app
        .send(browser.get("/v1/terms"))
        .await
        .json::<Value>()
        .get("current")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|t| json!({"document": t["document"], "version": t["version"]}))
        .collect();
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/signup",
                &json!({"email": email, "password": PASSWORD, "accepted_terms": terms}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "signup: {}", r.text());
    app.drain().await;
    let NotificationKind::EmailVerification { token, .. } =
        app.last_notification("email_verification")
    else {
        panic!("verification mail")
    };
    let r = browser
        .send(
            app,
            browser.post("/v1/email/verify", &json!({"token": token.expose()})),
        )
        .await;
    assert!(r.status.is_success(), "verify: {}", r.text());
    r.json()
}

/// RSK-03: a login from a new device of a user without MFA asks for an
/// e-mailed confirmation code; completes it.
async fn confirm_by_email(app: &App, browser: &mut Browser, body: &Value) {
    if body["status"] == "authenticated" {
        return;
    }
    assert_eq!(body["allowed_factors"], json!(["email"]), "{body}");
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
    assert_eq!(r.json::<Value>()["status"], "authenticated", "{}", r.text());
}

async fn me(app: &App, browser: &Browser) -> StatusCode {
    app.send(browser.get("/v1/me")).await.status
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_06_register_verify_login_totp_logout_and_recovery(pool: PgPool) {
    let app = App::new(pool).await;
    let mut browser = app.browser();
    register(&app, &mut browser, "alice@example.com").await;

    // Login with the password.
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(me(&app, &browser).await, StatusCode::OK);

    // Enroll TOTP (the login is fresh: no step-up needed).
    let r = browser
        .send(
            &app,
            browser.post("/v1/me/mfa/totp", &json!({"label": "Phone"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    let enrollment: Value = r.json();
    let secret = enrollment["secret"].as_str().unwrap().to_owned();
    let factor = enrollment["factor"]["id"].as_str().unwrap().to_owned();
    let r = browser
        .send(
            &app,
            browser.post(
                &format!("/v1/me/mfa/factors/{factor}/confirm"),
                &json!({"code": totp_code(&app, &secret)}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let confirmed: Value = r.json();
    let recovery: Vec<String> = confirmed["recovery_codes"]["codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(recovery.len(), 10);

    // Logout.
    let r = browser
        .send(&app, browser.post("/v1/logout", &json!({})))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    assert_eq!(me(&app, &browser).await, StatusCode::UNAUTHORIZED);

    // Login again: TOTP challenge.
    app.advance(Duration::from_secs(30));
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "challenge_required", "{body}");
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": totp_code(&app, &secret)}),
            ),
        )
        .await;
    assert_eq!(r.json::<Value>()["status"], "authenticated", "{}", r.text());
    assert_eq!(me(&app, &browser).await, StatusCode::OK);
    browser
        .send(&app, browser.post("/v1/logout", &json!({})))
        .await;

    // Login with a recovery code; the user is told (MFA-04).
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "challenge_required");
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "recovery_code", "code": recovery[0]}),
            ),
        )
        .await;
    assert_eq!(r.json::<Value>()["status"], "authenticated", "{}", r.text());
    assert!(
        !app.ports
            .notifier
            .with_template("recovery_code_used")
            .is_empty()
    );
    // The same recovery code never works twice.
    browser
        .send(&app, browser.post("/v1/logout", &json!({})))
        .await;
    browser.login(&app, "alice@example.com", PASSWORD).await;
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "recovery_code", "code": recovery[0]}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_06_password_reset_ends_every_session_and_trusted_device(pool: PgPool) {
    let app = App::new(pool).await;
    let mut laptop = app.browser();
    register(&app, &mut laptop, "alice@example.com").await;
    laptop.login(&app, "alice@example.com", PASSWORD).await;
    // A second device: new-device risk → e-mail confirmation (RSK-03).
    let mut phone = app.browser();
    let body = phone.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "challenge_required", "{body}");
    confirm_by_email(&app, &mut phone, &body).await;
    assert!(
        !app.ports
            .notifier
            .with_template("new_device_login")
            .is_empty()
    );
    assert_eq!(me(&app, &laptop).await, StatusCode::OK);
    assert_eq!(me(&app, &phone).await, StatusCode::OK);

    let mut stranger = app.browser();
    stranger.csrf(&app).await;
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
    let NotificationKind::PasswordReset { token, .. } = app.last_notification("password_reset")
    else {
        panic!("reset mail")
    };
    let new_password = "completely new passphrase 2026";
    let r = stranger
        .send(
            &app,
            stranger.post(
                "/v1/password/reset",
                &json!({"token": token.expose(), "new_password": new_password}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    assert_eq!(me(&app, &laptop).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me(&app, &phone).await, StatusCode::UNAUTHORIZED);
    let mut b = laptop.clone();
    let body = b.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["error"]["code"], "invalid_credentials");
    let body = b.login(&app, "alice@example.com", new_password).await;
    confirm_by_email(&app, &mut b, &body).await;
    assert_eq!(me(&app, &b).await, StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_06_native_refresh_rotation_and_reuse_detection(pool: PgPool) {
    let app = App::new(pool).await;
    let mut browser = app.browser();
    register(&app, &mut browser, "alice@example.com").await;
    let mut native = app.native();
    let r = app
        .send(native.post(
            "/v1/login/password",
            &json!({"email": "alice@example.com", "password": PASSWORD}),
        ))
        .await;
    native.absorb(&r.json());
    app.send(native.get("/v1/me"))
        .await
        .assert_status(StatusCode::OK);
    let first_refresh = native.refresh.clone().unwrap();

    let r = app
        .send(native.post(
            "/v1/token/refresh",
            &json!({"refresh_token": first_refresh}),
        ))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    native.absorb(&r.json());
    assert_ne!(native.refresh.as_deref(), Some(first_refresh.as_str()));
    app.send(native.get("/v1/me"))
        .await
        .assert_status(StatusCode::OK);

    // Replaying the used token revokes the whole family.
    let r = app
        .send(native.post(
            "/v1/token/refresh",
            &json!({"refresh_token": first_refresh}),
        ))
        .await;
    r.assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    let r = app
        .send(native.post(
            "/v1/token/refresh",
            &json!({"refresh_token": native.refresh.clone().unwrap()}),
        ))
        .await;
    r.assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    app.send(native.get("/v1/me"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_06_organization_invitation_role_policy_and_api_key(pool: PgPool) {
    let app = App::new(pool).await;
    let mut owner = app.browser();
    register(&app, &mut owner, "owner@example.com").await;
    owner.login(&app, "owner@example.com", PASSWORD).await;
    let r = owner
        .send(
            &app,
            owner.post("/v1/orgs", &json!({"name": "Acme", "slug": "acme"})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let org = r.json::<Value>()["id"].as_str().unwrap().to_owned();

    // Invite Bob as a member; Bob registers and accepts.
    let member_role = authn_org::BuiltinRole::Member.id();
    let r = owner
        .send(
            &app,
            owner.post(
                &format!("/v1/orgs/{org}/invitations"),
                &json!({"email": "bob@example.com", "role_id": member_role}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let NotificationKind::Invitation { token, .. } = app.last_notification("invitation") else {
        panic!("invitation mail")
    };
    let mut bob = app.browser();
    register(&app, &mut bob, "bob@example.com").await;
    bob.login(&app, "bob@example.com", PASSWORD).await;
    let r = bob
        .send(
            &app,
            bob.post("/v1/invitations/accept", &json!({"token": token.expose()})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let r = app.send(bob.get(&format!("/v1/orgs/{org}"))).await;
    r.assert_status(StatusCode::OK);

    // A member cannot manage invitations (RBAC).
    let r = bob
        .send(
            &app,
            bob.post(
                &format!("/v1/orgs/{org}/invitations"),
                &json!({"email": "eve@example.com", "role_id": member_role}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());

    // Another tenant's organization is invisible (IDOR → 404).
    let mut eve = app.browser();
    register(&app, &mut eve, "eve@example.com").await;
    eve.login(&app, "eve@example.com", PASSWORD).await;
    let r = app.send(eve.get(&format!("/v1/orgs/{org}"))).await;
    r.assert_status(StatusCode::NOT_FOUND);

    // Policy: MFA required → Bob's next login must enroll a factor.
    // The owner must satisfy the policy first (lock-out guard): enroll TOTP
    // and step up with it (SES-13 success path over HTTP).
    let r = owner
        .send(&app, owner.post("/v1/me/mfa/totp", &json!({})))
        .await;
    let enrollment: Value = r.json();
    let secret = enrollment["secret"].as_str().unwrap().to_owned();
    let factor = enrollment["factor"]["id"].as_str().unwrap().to_owned();
    owner
        .send(
            &app,
            owner.post(
                &format!("/v1/me/mfa/factors/{factor}/confirm"),
                &json!({"code": totp_code(&app, &secret)}),
            ),
        )
        .await
        .assert_status(StatusCode::OK);
    app.advance(Duration::from_secs(30));
    let r = owner
        .send(
            &app,
            owner.post(
                "/v1/reauth",
                &json!({"method": "totp", "code": totp_code(&app, &secret)}),
            ),
        )
        .await;
    let body: Value = r.json();
    assert!(
        body["amr"].as_array().unwrap().contains(&json!("mfa")),
        "{body}"
    );
    let mut policy: Value = app
        .send(owner.get(&format!("/v1/orgs/{org}/policy")))
        .await
        .json();
    policy["mfa_required"] = json!(true);
    let r = app
        .send({
            let mut request =
                authn_testkit::http::TestRequest::put(&format!("/v1/orgs/{org}/policy"))
                    .json(&policy)
                    .header("origin", common::ORIGIN)
                    .header("x-csrf-token", owner.csrf.as_deref().unwrap());
            for (name, value) in &owner.cookies {
                request = request.cookie(name, value);
            }
            request
        })
        .await;
    assert!(r.status.is_success(), "policy: {}", r.text());
    bob.send(&app, bob.post("/v1/logout", &json!({}))).await;
    let mut bob2 = app.browser();
    bob2.csrf(&app).await;
    let r = bob2
        .send(
            &app,
            bob2.post(
                "/v1/login/password",
                &json!({"email": "bob@example.com", "password": PASSWORD, "org_id": org}),
            ),
        )
        .await;
    let body: Value = r.json();
    // A new device without a factor: the mailbox is confirmed first
    // (RSK-03), then a factor must be enrolled (ORG-07 policy) — a stolen
    // password alone can never enroll the attacker's own factor.
    let actions = body["required_actions"].as_array().unwrap();
    assert!(actions.contains(&json!("enroll_mfa")), "{body}");
    assert!(
        body.get("access_token").is_none() && !bob2.cookies.contains_key("__Host-authn_session")
    );

    // API key for the organization (org:read) works on org routes only.
    let r = owner
        .send(
            &app,
            owner.post(
                &format!("/v1/orgs/{org}/api-keys"),
                &json!({"name": "backend", "scopes": ["org:read"]}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let key = r.json::<Value>()["key"].as_str().unwrap().to_owned();
    let r = app
        .send(authn_testkit::http::TestRequest::get(&format!("/v1/orgs/{org}")).bearer(&key))
        .await;
    r.assert_status(StatusCode::OK);
    let r = app
        .send(authn_testkit::http::TestRequest::get("/v1/me").bearer(&key))
        .await;
    r.assert_status(StatusCode::UNAUTHORIZED);
}
