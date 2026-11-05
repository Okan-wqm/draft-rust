#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-57 global security audit: regression tests for the cross-module
//! findings (`docs/security/k57-global-audit.md`). Each test failed before
//! its fix.

mod common;

use std::time::Duration;

use authn_core::ports::NotificationKind;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::{App, Browser, PASSWORD, totp_code};
use serde_json::{Value, json};
use sqlx::PgPool;

/// Signs up `email` in `browser` and verifies the address with the
/// e-mailed link (same browser: the registration cookie proves it).
async fn register(app: &App, browser: &mut Browser, email: &str) {
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
}

/// An organization owned by `owner@example.com` with `bob@example.com` as
/// a plain member; both browsers are signed in with their password and
/// have **no** active organization (personal context).
async fn org_with_member(app: &App) -> (Browser, Browser, String) {
    let mut owner = app.browser();
    register(app, &mut owner, "owner@example.com").await;
    let body = owner.login(app, "owner@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let r = owner
        .send(
            app,
            owner.post("/v1/orgs", &json!({"name": "Acme", "slug": "acme"})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let org = r.json::<Value>()["id"].as_str().unwrap().to_owned();
    let r = owner
        .send(
            app,
            owner.post(
                &format!("/v1/orgs/{org}/invitations"),
                &json!({"email": "bob@example.com", "role_id": authn_org::BuiltinRole::Member.id()}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let NotificationKind::Invitation { token, .. } = app.last_notification("invitation") else {
        panic!("invitation mail")
    };
    let mut bob = app.browser();
    register(app, &mut bob, "bob@example.com").await;
    let body = bob.login(app, "bob@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let r = bob
        .send(
            app,
            bob.post("/v1/invitations/accept", &json!({"token": token.expose()})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    (owner, bob, org)
}

/// `PUT` with the browser's cookies, `Origin` and CSRF token.
fn put(browser: &Browser, path: &str, body: &Value) -> TestRequest {
    let mut request = TestRequest::put(path)
        .json(body)
        .header("origin", common::ORIGIN)
        .header("x-csrf-token", browser.csrf.as_deref().unwrap());
    for (name, value) in &browser.cookies {
        request = request.cookie(name, value);
    }
    request
}

/// K-57 F2 (ORG-07, SES-17): an organization's allowed login methods
/// apply to every session acting on the organization, not only to
/// sessions that activated it. Before the fix the policy was checked at
/// a login that requested the organization and at the organization
/// switch only, while every organization endpoint (authn-org, authn-audit)
/// authorized any member session — a member signed in with a forbidden
/// method simply never switched and used `/v1/orgs/{org_id}/…` directly.
/// A tightening policy change revokes only the sessions whose active
/// organization is the organization, so personal-context sessions kept
/// working too.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_k57_login_method_policy_applies_to_personal_context_sessions(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let (_owner, bob, org) = org_with_member(&app).await;
    let members = format!("/v1/orgs/{org}/members");
    app.send(bob.get(&members))
        .await
        .assert_status(StatusCode::OK);

    // The organization now admits passkey logins only (written directly:
    // the API path revokes only sessions with this active organization,
    // which Bob's personal-context session is not).
    sqlx::query(
        "INSERT INTO org_policies (org_id, allowed_login_methods) VALUES ($1::uuid, $2) \
         ON CONFLICT (org_id) DO UPDATE SET allowed_login_methods = EXCLUDED.allowed_login_methods",
    )
    .bind(&org)
    .bind(vec!["passkey"])
    .execute(&pool)
    .await
    .unwrap();

    // Switching is refused (control: this path was already enforced) …
    let r = app
        .send(bob.post("/v1/session/org", &json!({"org_id": org})))
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
    // … and so is every organization endpoint of the password session.
    let r = app.send(bob.get(&members)).await;
    r.assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
    let r = app.send(bob.get(&format!("/v1/orgs/{org}"))).await;
    r.assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
    let r = app
        .send(bob.post(&format!("/v1/orgs/{org}/leave"), &json!({})))
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
}

/// K-57 F2: the owner cannot lock their own session out of the
/// organization by forbidding the login method it was made with
/// (`org_policy_lockout`, as for the IP allow-list and MFA).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_k57_policy_change_refuses_to_forbid_the_callers_login_method(pool: PgPool) {
    let app = App::new(pool).await;
    let (owner, _bob, org) = org_with_member(&app).await;
    let path = format!("/v1/orgs/{org}/policy");
    let mut policy: Value = app.send(owner.get(&path)).await.json();
    policy["allowed_login_methods"] = json!(["passkey"]);
    let r = app.send(put(&owner, &path, &policy)).await;
    let error = r.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "org_policy_lockout");
    assert_eq!(
        error.details.unwrap()["reason"],
        "login_method",
        "{}",
        r.text()
    );
    // Allowing the caller's method is fine.
    policy["allowed_login_methods"] = json!(["passkey", "password"]);
    let r = app.send(put(&owner, &path, &policy)).await;
    assert!(r.status.is_success(), "{}", r.text());
}

/// K-57 F2 (ORG-07, MFA-08): an organization's allowed MFA factors apply
/// to every session acting on it. Bob's personal-context session is
/// multi-factor through TOTP; the organization then admits passkeys only as
/// a second factor. Before the fix only the organization switch read the
/// session's recorded factors (K-78), every organization endpoint accepted
/// the TOTP-based `mfa`.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_k57_allowed_factor_policy_applies_to_personal_context_sessions(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let (_owner, mut bob, org) = org_with_member(&app).await;
    // Bob enrols TOTP and steps up with it: the session is `mfa` via TOTP.
    let r = bob
        .send(&app, bob.post("/v1/me/mfa/totp", &json!({})))
        .await;
    let enrollment: Value = r.json();
    let secret = enrollment["secret"].as_str().unwrap().to_owned();
    let factor = enrollment["factor"]["id"].as_str().unwrap().to_owned();
    bob.send(
        &app,
        bob.post(
            &format!("/v1/me/mfa/factors/{factor}/confirm"),
            &json!({"code": totp_code(&app, &secret)}),
        ),
    )
    .await
    .assert_status(StatusCode::OK);
    app.advance(Duration::from_secs(30));
    let r = bob
        .send(
            &app,
            bob.post(
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
    let members = format!("/v1/orgs/{org}/members");
    app.send(bob.get(&members))
        .await
        .assert_status(StatusCode::OK);

    sqlx::query(
        "INSERT INTO org_policies (org_id, mfa_required, allowed_mfa_factors) \
         VALUES ($1::uuid, true, $2) ON CONFLICT (org_id) DO UPDATE SET \
         mfa_required = true, allowed_mfa_factors = EXCLUDED.allowed_mfa_factors",
    )
    .bind(&org)
    .bind(vec!["webauthn"])
    .execute(&pool)
    .await
    .unwrap();

    let r = app
        .send(bob.post("/v1/session/org", &json!({"org_id": org})))
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");
    let r = app.send(bob.get(&members)).await;
    r.assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");
}

/// `POST` with a native client's bearer access token.
fn native_post(token: &str, path: &str, body: &Value) -> TestRequest {
    TestRequest::post(path)
        .json(body)
        .header("x-authn-client", "native")
        .bearer(token)
}

/// K-57 F2 re-audit (ORG-07, MFA-08, SES-08): a bearer access token keeps
/// its own `amr` and never benefits from a later step-up of its session.
/// The session's recorded second factors (K-78) are read from the live
/// session row, so before the fix an access token minted after a
/// recovery-code step-up passed an organization admitting TOTP only, as
/// soon as the same session later stepped up with TOTP — although its own
/// `amr` carries no TOTP proof.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_k57_bearer_token_does_not_inherit_factors_of_a_later_step_up(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let (_owner, mut bob, org) = org_with_member(&app).await;

    // Bob enrols TOTP in the browser and receives recovery codes.
    let r = bob
        .send(&app, bob.post("/v1/me/mfa/totp", &json!({})))
        .await;
    let enrollment: Value = r.json();
    let secret = enrollment["secret"].as_str().unwrap().to_owned();
    let factor = enrollment["factor"]["id"].as_str().unwrap().to_owned();
    let r = bob
        .send(
            &app,
            bob.post(
                &format!("/v1/me/mfa/factors/{factor}/confirm"),
                &json!({"code": totp_code(&app, &secret)}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let recovery = r.json::<Value>()["recovery_codes"]["codes"][0]
        .as_str()
        .unwrap()
        .to_owned();

    // Bob's native session (personal context): password + recovery code,
    // token A (`mfa` via `kba`).
    let mut native = app.native();
    let r = app
        .send(native.post(
            "/v1/login/password",
            &json!({"email": "bob@example.com", "password": PASSWORD}),
        ))
        .await;
    assert_eq!(
        r.json::<Value>()["status"],
        "challenge_required",
        "{}",
        r.text()
    );
    native.absorb(&r.json());
    let r = app
        .send(native.post(
            "/v1/login/challenge/verify",
            &json!({"method": "recovery_code", "code": recovery}),
        ))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    native.absorb(&r.json());
    let kba_token = native.access.clone().unwrap();

    // Later step-up with TOTP: token B (`mfa` via `otp`).
    app.advance(Duration::from_secs(30));
    let r = app
        .send(native_post(
            &kba_token,
            "/v1/reauth",
            &json!({"method": "totp", "code": totp_code(&app, &secret)}),
        ))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    native.absorb(&r.json());
    let totp_token = native.access.clone().unwrap();

    // The organization admits TOTP as the second factor only.
    sqlx::query(
        "INSERT INTO org_policies (org_id, mfa_required, allowed_mfa_factors) \
         VALUES ($1::uuid, true, $2) ON CONFLICT (org_id) DO UPDATE SET \
         mfa_required = true, allowed_mfa_factors = EXCLUDED.allowed_mfa_factors",
    )
    .bind(&org)
    .bind(vec!["totp"])
    .execute(&pool)
    .await
    .unwrap();

    let members = format!("/v1/orgs/{org}/members");
    app.send(TestRequest::get(&members).bearer(&totp_token))
        .await
        .assert_status(StatusCode::OK);
    let r = app
        .send(TestRequest::get(&members).bearer(&kba_token))
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");
}
