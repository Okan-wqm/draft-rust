#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Passkey login (SES-20, SES-21) and the passkey second factor (SES-02)
//! with real WebAuthn ceremonies of a software authenticator.

mod common;

use authn_core::domain::{AuthMethodRef, ClientKind, FactorKind, LoginMethod};
use authn_core::id::UserId;
use authn_core::ports::RequiredAction;
use authn_session::cookies::{PASSKEY_BINDING_COOKIE, SESSION_COOKIE};
use authn_testkit::http::TestRequest;
use authn_webauthn::service::RegistrationIntent;
use authn_webauthn::{RegistrationOptionsRequest, RegistrationVerifyRequest};
use axum::http::StatusCode;
use common::browser::{Browser, native, native_challenge, status_of};
use common::{Harness, ORIGIN, empty_policy};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::{
    AllowCredentials, CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
};

struct Registered {
    raw_id: Vec<u8>,
    handle: Vec<u8>,
}

async fn register(
    h: &Harness,
    authenticator: &mut SoftPasskey,
    user: UserId,
    intent: RegistrationIntent,
) -> Registered {
    // Registration ceremonies are bound to a live session.
    let login = h.web_login(user).await;
    let mut principal = h.fresh(user);
    principal.credential = authn_core::domain::PrincipalCredential::SessionCookie {
        session_id: login.session_id,
    };
    let start = h
        .webauthn
        .start_registration(
            &h.ctx(),
            &principal,
            RegistrationOptionsRequest {
                name: None,
                usage: Some(intent),
            },
        )
        .await
        .unwrap();
    let ccr: CreationChallengeResponse = serde_json::from_value(start.options.clone()).unwrap();
    let credential = authenticator
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .unwrap();
    h.webauthn
        .finish_registration(
            &h.ctx(),
            &principal,
            RegistrationVerifyRequest {
                ceremony_id: start.ceremony_id,
                credential: serde_json::to_value(&credential).unwrap(),
                name: None,
            },
        )
        .await
        .unwrap();
    let (handle,): (Vec<u8>,) =
        sqlx::query_as("SELECT user_handle FROM webauthn_user_handles WHERE user_id = $1")
            .bind(user)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    Registered {
        raw_id: credential.raw_id.clone(),
        handle,
    }
}

/// `navigator.credentials.get()` for a discoverable login (the platform's
/// choice of the resident credential is simulated, see authn-webauthn).
fn assert_discoverable(
    authenticator: &mut SoftPasskey,
    options: &Value,
    passkey: &Registered,
) -> PublicKeyCredential {
    let mut rcr: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
    rcr.public_key.allow_credentials = vec![AllowCredentials {
        type_: "public-key".to_owned(),
        id: passkey.raw_id.clone(),
        transports: None,
    }];
    let mut credential = authenticator
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .unwrap();
    credential.response.user_handle = Some(passkey.handle.clone());
    credential
}

fn assert_with_allow_list(authenticator: &mut SoftPasskey, options: &Value) -> PublicKeyCredential {
    let rcr: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
    authenticator
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_20_web_passkey_login_without_username(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mut key = SoftPasskey::new(true);
    let passkey = register(&h, &mut key, alice, RegistrationIntent::Passwordless).await;

    let mut browser = Browser::new(&h);
    let options = browser
        .send(
            &h,
            browser.post(
                "/v1/login/passkey/options",
                &json!({"conditional_ui": true}),
            ),
        )
        .await;
    options.assert_status(StatusCode::OK);
    let body: Value = options.json();
    assert!(
        body.get("binding_token").is_none(),
        "web: binding in a cookie"
    );
    assert!(browser.has(PASSKEY_BINDING_COOKIE));
    let binding_line = options
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(PASSKEY_BINDING_COOKIE))
        .unwrap();
    assert!(binding_line.contains("SameSite=Strict") && binding_line.contains("HttpOnly"));
    assert_eq!(body["options"]["mediation"], "conditional");

    let credential = assert_discoverable(&mut key, &body["options"], &passkey);
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/passkey",
                &json!({"ceremony_id": body["ceremony_id"], "credential": credential}),
            ),
        )
        .await;
    let session: Value = done.json();
    assert_eq!(session["status"], "authenticated", "{session}");
    assert_eq!(session["user_id"], json!(alice));
    // SES-21: a user-verified passkey alone is MFA.
    assert_eq!(session["amr"], json!(["hwk", "user", "mfa"]));
    assert!(browser.has(SESSION_COOKIE));
    assert!(!browser.has(PASSKEY_BINDING_COOKIE));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_21_passkey_satisfies_mfa_and_phishing_resistant_policy(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    h.enroll_totp(alice).await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = empty_policy();
    policy.phishing_resistant_mfa_required = true;
    h.set_policy(owner, org, policy).await;
    let mut key = SoftPasskey::new(true);
    let passkey = register(&h, &mut key, alice, RegistrationIntent::Passwordless).await;

    // Native app, organization requested: no challenge although TOTP is
    // enrolled and the organization demands phishing resistance.
    let options = h
        .send(native("/v1/login/passkey/options", &json!({})))
        .await;
    let body: Value = options.json();
    let binding = body["binding_token"].as_str().unwrap().to_owned();
    let credential = assert_discoverable(&mut key, &body["options"], &passkey);
    let done = h
        .send(native(
            "/v1/login/passkey",
            &json!({
                "ceremony_id": body["ceremony_id"],
                "binding_token": binding,
                "credential": credential,
                "org_id": org,
            }),
        ))
        .await;
    let session: Value = done.json();
    assert_eq!(session["status"], "authenticated", "{session}");
    assert_eq!(session["active_org_id"], json!(org));
    assert!(session["access_token"].as_str().is_some());

    // The same organization refuses a password + TOTP login.
    let mut browser = Browser::new(&h);
    let r = browser
        .send(
            &h,
            browser.post(
                "/v1/login/password",
                &json!({"email": "alice@example.com", "password": common::PASSWORD, "org_id": org}),
            ),
        )
        .await;
    let body: Value = r.json();
    // Either the method is refused outright or only a passkey may finish.
    if r.status == StatusCode::OK {
        assert_eq!(body["status"], "challenge_required");
        // Either a passkey factor is asked for, or — the TOTP is outside the
        // policy — the TOTP authorizes a passkey enrollment that must
        // follow (SES-22: a password alone never enrolls a factor).
        assert!(
            body["allowed_factors"] == json!(["webauthn"])
                || body["required_actions"] == json!(["verify_mfa", "enroll_mfa"]),
            "{body}"
        );
    } else {
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{body}");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_20_binding_token_is_required_and_bound(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mut key = SoftPasskey::new(true);
    let passkey = register(&h, &mut key, alice, RegistrationIntent::Passwordless).await;
    let options = h
        .send(native("/v1/login/passkey/options", &json!({})))
        .await;
    let body: Value = options.json();
    let credential = assert_discoverable(&mut key, &body["options"], &passkey);
    // Without the binding token.
    let r = h
        .send(native(
            "/v1/login/passkey",
            &json!({"ceremony_id": body["ceremony_id"], "credential": credential}),
        ))
        .await;
    r.assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");
    // With somebody else's binding token.
    let other: Value = h
        .send(native("/v1/login/passkey/options", &json!({})))
        .await
        .json();
    let r = h
        .send(native(
            "/v1/login/passkey",
            &json!({
                "ceremony_id": body["ceremony_id"],
                "binding_token": other["binding_token"],
                "credential": credential,
            }),
        ))
        .await;
    r.assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");
    assert_eq!(
        h.count(
            "SELECT count(*) FROM sessions WHERE user_id = $1 AND login_method = 'passkey'",
            alice.as_uuid()
        )
        .await,
        0
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_passkey_as_second_factor_after_a_password(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mut key = SoftPasskey::new(false);
    register(&h, &mut key, alice, RegistrationIntent::SecondFactor).await;
    // A pending password login whose policy allows a passkey second factor.
    let token = {
        let mut tx = h.service.begin().await.unwrap();
        let issued = h
            .service
            .create_challenge(
                &mut tx,
                &h.ctx(),
                authn_session::NewChallenge {
                    kind: authn_session::ChallengeKind::Login,
                    user_id: alice,
                    client_kind: ClientKind::Native,
                    primary_method: Some(LoginMethod::Password),
                    amr: vec![AuthMethodRef::Pwd],
                    first_factor_at: Some(h.now()),
                    allowed_factors: vec![FactorKind::Webauthn],
                    required_actions: vec![RequiredAction::VerifyMfa],
                    remember_me: false,
                    shared_device: false,
                    requested_org: None,
                    risk_level: None,
                    session_id: None,
                    metadata: serde_json::Map::new(),
                },
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        issued.token.expose().to_owned()
    };
    let options: Value = h
        .send(native_challenge(
            "/v1/login/challenge/passkey/options",
            &json!({}),
            &token,
        ))
        .await
        .json();
    let credential = assert_with_allow_list(&mut key, &options["options"]);
    let done = h
        .send(native_challenge(
            "/v1/login/challenge/verify",
            &json!({
                "method": "passkey",
                "ceremony_id": options["ceremony_id"],
                "binding_token": options["binding_token"],
                "credential": credential,
            }),
            &token,
        ))
        .await;
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert!(body["amr"].as_array().unwrap().contains(&json!("mfa")));
    assert!(body["amr"].as_array().unwrap().contains(&json!("pwd")));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_passkey_options_need_an_allowed_passkey_step(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let (_, token) = h
        .pending_challenge(alice, authn_session::ChallengeKind::Login, None)
        .await;
    // The helper's challenge allows TOTP only and is a web challenge.
    let mut browser = Browser::new(&h);
    browser
        .cookies
        .insert(authn_session::cookies::CHALLENGE_COOKIE.into(), token);
    let r = browser
        .send(
            &h,
            browser.post("/v1/login/challenge/passkey/options", &json!({})),
        )
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    let _ = status_of(&r);
    let _ = TestRequest::get("/");
}

async fn make_break_glass(h: &Harness, user: UserId) {
    sqlx::query("UPDATE users SET is_platform_admin = true, is_break_glass = true WHERE id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
}

fn break_glass_events(h: &Harness) -> Vec<authn_core::ports::SecurityEvent> {
    h.ports
        .audit
        .of_kind(authn_core::ports::SecurityEventKind::BreakGlassUsed)
}

/// ADM-05 / K-05: a session established for a break-glass account records a
/// high-priority `admin.break_glass_used` (`surface: login`) in the login
/// transaction — both straight from the pipeline (passkey login) and when a
/// challenge completes (password + passkey second factor). Regular
/// accounts produce no such event.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_break_glass_login_emits_high_priority_event(pool: PgPool) {
    let h = Harness::new(pool).await;
    // A regular user: no event.
    let alice = h.user("alice@example.com").await;
    let mut alice_key = SoftPasskey::new(true);
    let alice_passkey = register(&h, &mut alice_key, alice, RegistrationIntent::Passwordless).await;
    let options: Value = h
        .send(native("/v1/login/passkey/options", &json!({})))
        .await
        .json();
    let credential = assert_discoverable(&mut alice_key, &options["options"], &alice_passkey);
    let done: Value = h
        .send(native(
            "/v1/login/passkey",
            &json!({"ceremony_id": options["ceremony_id"],
                    "binding_token": options["binding_token"], "credential": credential}),
        ))
        .await
        .json();
    assert_eq!(done["status"], "authenticated", "{done}");
    assert!(break_glass_events(&h).is_empty());

    // The break-glass account, pipeline path.
    let bg = h.user("breakglass@example.com").await;
    let mut key = SoftPasskey::new(true);
    let passkey = register(&h, &mut key, bg, RegistrationIntent::Passwordless).await;
    make_break_glass(&h, bg).await;
    let options: Value = h
        .send(native("/v1/login/passkey/options", &json!({})))
        .await
        .json();
    let credential = assert_discoverable(&mut key, &options["options"], &passkey);
    let done: Value = h
        .send(native(
            "/v1/login/passkey",
            &json!({"ceremony_id": options["ceremony_id"],
                    "binding_token": options["binding_token"], "credential": credential}),
        ))
        .await
        .json();
    assert_eq!(done["status"], "authenticated", "{done}");
    let events = break_glass_events(&h);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.subject_user, Some(bg));
    assert_eq!(event.actor, authn_core::ports::Actor::User(bg));
    assert_eq!(event.metadata["priority"], "high");
    assert_eq!(event.metadata["surface"], "login");
    assert_eq!(event.metadata["method"], "passkey");
    assert_eq!(
        event.resource.as_ref().unwrap().id,
        done["session_id"].as_str().unwrap()
    );

    // Challenge path: a pending password login finished with the passkey.
    let token = {
        let mut tx = h.service.begin().await.unwrap();
        let issued = h
            .service
            .create_challenge(
                &mut tx,
                &h.ctx(),
                authn_session::NewChallenge {
                    kind: authn_session::ChallengeKind::Login,
                    user_id: bg,
                    client_kind: ClientKind::Native,
                    primary_method: Some(LoginMethod::Password),
                    amr: vec![AuthMethodRef::Pwd],
                    first_factor_at: Some(h.now()),
                    allowed_factors: vec![FactorKind::Webauthn],
                    required_actions: vec![RequiredAction::VerifyMfa],
                    remember_me: false,
                    shared_device: false,
                    requested_org: None,
                    risk_level: None,
                    session_id: None,
                    metadata: serde_json::Map::new(),
                },
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        issued.token.expose().to_owned()
    };
    let options: Value = h
        .send(native_challenge(
            "/v1/login/challenge/passkey/options",
            &json!({}),
            &token,
        ))
        .await
        .json();
    let credential = assert_with_allow_list(&mut key, &options["options"]);
    let done: Value = h
        .send(native_challenge(
            "/v1/login/challenge/verify",
            &json!({
                "method": "passkey",
                "ceremony_id": options["ceremony_id"],
                "binding_token": options["binding_token"],
                "credential": credential,
            }),
            &token,
        ))
        .await
        .json();
    assert_eq!(done["status"], "authenticated", "{done}");
    let events = break_glass_events(&h);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].metadata["method"], "password");
    assert_eq!(events[1].metadata["surface"], "login");
}
