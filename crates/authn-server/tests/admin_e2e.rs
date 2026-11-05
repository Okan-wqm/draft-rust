#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Platform admin end to end (TST-06, K-50, K-52): the real router, real
//! sessions (password and passkey logins with a software authenticator),
//! the real account-aware `PgSessionRevoker`, real PostgreSQL. Also the
//! break-glass enrollment link through the session-less routes (K-11) and
//! the ACC-07 revert removing every login method an attacker added (K-20).

mod common;

use std::sync::Arc;
use std::time::Duration;

use authn_core::id::UserId;
use authn_core::ports::{AuditSink, Clock, NotificationKind};
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::{App, Browser, ORIGIN, PASSWORD, totp_code};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::{AllowCredentials, CreationChallengeResponse, RequestChallengeResponse};

async fn make_admin(app: &App, user: UserId) {
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(user)
        .execute(&app.pool)
        .await
        .unwrap();
}

/// Registers a passkey for the signed-in `browser`; returns the key and its
/// credential id.
async fn register_passkey(app: &App, browser: &mut Browser) -> (SoftPasskey, Vec<u8>) {
    let r = browser
        .send(
            app,
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
            app,
            browser.post(
                "/v1/me/passkeys/registration/verify",
                &json!({"ceremony_id": start["ceremony_id"], "credential": credential}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    (key, raw_id)
}

/// A username-less passkey login in a fresh browser; returns the browser
/// (with its CSRF token) and the response body.
async fn passkey_login(
    app: &App,
    user: UserId,
    key: &mut SoftPasskey,
    raw_id: &[u8],
) -> (Browser, Value) {
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
    let body: Value = r.json();
    browser.csrf(app).await;
    (browser, body)
}

/// Passkey step-up of a signed-in browser (SES-13).
async fn passkey_step_up(app: &App, browser: &mut Browser, key: &mut SoftPasskey) {
    let r = browser
        .send(app, browser.post("/v1/reauth/passkey/options", &json!({})))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let options: Value = r.json();
    let rcr: RequestChallengeResponse = serde_json::from_value(options["options"].clone()).unwrap();
    let assertion = key
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .unwrap();
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/reauth",
                &json!({"method": "passkey", "ceremony_id": options["ceremony_id"], "credential": assertion}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

/// An admin signed in with a passkey (phishing-resistant MFA, ADM-01).
struct Admin {
    id: UserId,
    browser: Browser,
    key: SoftPasskey,
}

async fn passkey_admin(app: &App, email: &str) -> Admin {
    // Platform admins must have phishing-resistant MFA before they can sign
    // in at all: the passkey is enrolled while the account is a normal one.
    let id = app.user(email).await;
    let mut browser = app.browser();
    let body = browser.login(app, email, PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let (mut key, raw_id) = register_passkey(app, &mut browser).await;
    make_admin(app, id).await;
    let (browser, body) = passkey_login(app, id, &mut key, &raw_id).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    Admin { id, browser, key }
}

async fn signed_in(app: &App, email: &str) -> (UserId, Browser) {
    let id = app.user(email).await;
    let mut browser = app.browser();
    let body = browser.login(app, email, PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    browser.csrf(app).await;
    (id, browser)
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_authorization_matrix_with_real_sessions(pool: PgPool) {
    let app = App::new(pool).await;
    let users = "/v1/admin/users";

    // Anonymous.
    app.send(TestRequest::get(users))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");

    // A normal user (password session): forbidden, nothing learned.
    let (_, normal) = signed_in(&app, "user@example.com").await;
    app.send(normal.get(users))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");

    // A password-only session of an account that became a platform admin
    // afterwards (the flag is re-read per request): passkey MFA required.
    let (pw_admin_id, pw_admin) = signed_in(&app, "pwadmin@example.com").await;
    make_admin(&app, pw_admin_id).await;
    app.send(pw_admin.get(users)).await.assert_error(
        StatusCode::FORBIDDEN,
        "admin_phishing_resistant_mfa_required",
    );

    // A platform admin signed in with a passkey: allowed.
    let mut admin = passkey_admin(&app, "admin@example.com").await;
    let r = app.send(admin.browser.get(users)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.headers["cache-control"], "no-store");

    // State-changing admin routes stay behind the CSRF layer.
    let target = app.user("target@example.com").await;
    let mut no_csrf = admin.browser.clone();
    no_csrf.csrf = None;
    app.send(no_csrf.post(
        &format!("/v1/admin/users/{target}/suspend"),
        &json!({"reason": "abuse report 7"}),
    ))
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");

    // The step-up window (10 min) is enforced per request.
    app.advance(Duration::from_secs(11 * 60));
    app.send(admin.browser.get(users))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    passkey_step_up(&app, &mut admin.browser, &mut admin.key).await;
    let r = app.send(admin.browser.get(users)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());

    // A real action with its justification, and the target rules.
    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                &format!("/v1/admin/users/{target}/suspend"),
                &json!({"reason": "abuse report 7"}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                &format!("/v1/admin/users/{}/suspend", admin.id),
                &json!({"reason": "self"}),
            ),
        )
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
    // A missing justification is refused.
    let r = admin
        .browser
        .send(
            &app,
            admin
                .browser
                .post(&format!("/v1/admin/users/{target}/unsuspend"), &json!({})),
        )
        .await;
    r.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_impersonation_header_read_only_and_real_revocation(pool: PgPool) {
    let app = App::new(pool).await;
    let mut admin = passkey_admin(&app, "admin@example.com").await;
    let (target, _target_browser) = signed_in(&app, "target@example.com").await;

    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                &format!("/v1/admin/users/{target}/impersonate"),
                &json!({"reason": "ticket 1234", "read_only": true, "ttl_minutes": 15}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    // K-12: the admin's cookie is never replaced.
    assert!(r.set_cookies().is_empty(), "{:?}", r.set_cookies());
    let body: Value = r.json();
    let token = body["impersonation_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"))
        .to_owned();

    // The impersonation travels in its header; the session is the target's.
    let with_header =
        |request: TestRequest| request.header("x-impersonation-session", token.as_str());
    let me = app.send(with_header(TestRequest::get("/v1/me"))).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text());
    assert_eq!(me.json::<Value>()["user_id"], json!(target));

    // Read-only: every state-changing method is refused (also with a CSRF
    // token and the admin's cookie in the same request).
    let r = app
        .send(with_header(
            TestRequest::patch("/v1/me/profile").json(&json!({"display_name": "x"})),
        ))
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "forbidden");
    let r = app
        .send(with_header(
            admin
                .browser
                .post("/v1/me/sessions/revoke-others", &json!({})),
        ))
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "forbidden");
    // Never the admin API under impersonation.
    let r = app
        .send(with_header(TestRequest::get("/v1/admin/users")))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    // A forged header is 401, never a fall-back to the admin's cookie.
    let r = app
        .send(
            admin
                .browser
                .get("/v1/me")
                .header("x-impersonation-session", "forged"),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());

    // The admin's own session is untouched.
    let r = app.send(admin.browser.get("/v1/admin/users")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());

    // Suspending the admin (offline, K-07) ends the impersonation through
    // the real account-aware revoker.
    let outcome = app
        .services
        .admin
        .suspend_admin_offline(
            &authn_admin::OfflineOperator::parse("oncall").unwrap(),
            &authn_admin::OfflineTarget::Id(admin.id),
            &authn_admin::Justification::parse(Some("compromised laptop")).unwrap(),
        )
        .await
        .unwrap();
    assert!(outcome.changed);
    let me = app.send(with_header(TestRequest::get("/v1/me"))).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED, "{}", me.text());
    let r = app.send(admin.browser.get("/v1/admin/users")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());
    let _ = &mut admin.key;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_emergency_revoke_all_keeps_the_callers_session(pool: PgPool) {
    let app = App::new(pool).await;
    let mut admin = passkey_admin(&app, "admin@example.com").await;
    let (_, user) = signed_in(&app, "user@example.com").await;
    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                "/v1/admin/emergency/revoke-all-sessions",
                &json!({"reason": "suspected key leak", "confirm": "revoke_all_sessions"}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(
        app.send(user.get("/v1/me")).await.status,
        StatusCode::UNAUTHORIZED
    );
    // K-10: the caller keeps working.
    let r = app.send(admin.browser.get("/v1/admin/users")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let _ = &mut admin.key;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k11_break_glass_enrollment_link_end_to_end(pool: PgPool) {
    let app = App::new(pool).await;
    // What `create-admin --passkey-link` does.
    let audit: Arc<dyn AuditSink> = Arc::new(authn_audit::PgAuditSink::new(
        app.pool.clone(),
        app.ports.clock.clone(),
    ));
    let link = authn_admin::create_break_glass_admin_with_passkey_link(
        &app.pool,
        app.ports.clock.as_ref(),
        &audit,
        "root@example.com",
        Duration::from_secs(30 * 60),
    )
    .await
    .unwrap();
    let url = authn_server::cli::enrollment_url(
        &app.services.config.server.public_base_url,
        link.token.expose(),
    );
    let token = Url::parse(&url).unwrap().fragment().unwrap().to_owned();

    // The enrollment page runs in a browser that also holds an unrelated
    // session cookie and no CSRF token: the session-less routes must not be
    // blocked by the CSRF layer.
    let (_, mut other) = signed_in(&app, "someone@example.com").await;
    other.csrf = None;
    let r = app
        .send(
            other
                .post("/v1/admin/enrollment/options", &json!({"token": token}))
                .header("origin", ORIGIN),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let start: Value = r.json();
    let ccr: CreationChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    let mut key = SoftPasskey::new(true);
    let credential = key
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .unwrap();
    let raw_id = credential.raw_id.clone();
    let r = app
        .send(other.post(
            "/v1/admin/enrollment/verify",
            &json!({"token": token, "ceremony_id": start["ceremony_id"], "credential": credential}),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());

    // Single use: the same link is dead (uniform error).
    let r = app
        .send(TestRequest::post("/v1/admin/enrollment/options").json(&json!({"token": token})))
        .await;
    r.assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");

    // The break-glass admin signs in with the enrolled passkey and reaches
    // the admin API.
    let (browser, body) = passkey_login(&app, link.user_id, &mut key, &raw_id).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let r = app.send(browser.get("/v1/admin/users")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

/// ACC-07 / K-20: an attacker who took over the session changes the
/// address, then adds a passkey, TOTP and a recovery path. The owner's
/// revert link removes every one of them in the revert transaction.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_k20_revert_removes_every_login_method_the_attacker_added(pool: PgPool) {
    let app = App::new(pool).await;
    let (victim, mut attacker) = signed_in(&app, "victim@example.com").await;

    // E-mail change to the attacker's mailbox.
    let r = attacker
        .send(
            &app,
            attacker.post(
                "/v1/me/email",
                &json!({"new_email": "attacker@evil.example"}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;
    let NotificationKind::EmailChangeVerification { token, .. } =
        app.last_notification("email_change_verification")
    else {
        panic!()
    };
    let r = attacker
        .send(
            &app,
            attacker.post(
                "/v1/email/change/confirm",
                &json!({"token": token.expose()}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;
    let NotificationKind::EmailChanged { revert_token, .. } =
        app.last_notification("email_changed")
    else {
        panic!()
    };
    attacker.csrf(&app).await;

    // The attacker's own login methods: a passkey and TOTP (+ recovery codes).
    let (mut key, raw_id) = register_passkey(&app, &mut attacker).await;
    let r = attacker
        .send(
            &app,
            attacker.post("/v1/me/mfa/totp", &json!({"label": "evil"})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let enrol: Value = r.json();
    let factor = enrol["factor"]["id"].as_str().unwrap().to_owned();
    let secret = enrol["secret"].as_str().unwrap().to_owned();
    let r = attacker
        .send(
            &app,
            attacker.post(
                &format!("/v1/me/mfa/factors/{factor}/confirm"),
                &json!({"code": totp_code(&app, &secret)}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let count = |sql: &'static str| {
        let pool = app.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .bind(victim)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        count("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1").await,
        1
    );
    assert!(count("SELECT count(*) FROM mfa_factors WHERE user_id = $1").await >= 1);

    // The owner reverts from the old mailbox (no session needed).
    let r = app
        .send(
            TestRequest::post("/v1/email/change/revert")
                .json(&json!({"token": revert_token.expose()})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());

    // Every added method is gone (same transaction as the revert).
    assert_eq!(
        count("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1").await,
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM mfa_factors WHERE user_id = $1").await,
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM recovery_codes WHERE user_id = $1").await,
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM identities WHERE user_id = $1").await,
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM trusted_devices WHERE user_id = $1 AND revoked_at IS NULL")
            .await,
        0
    );
    // The attacker's session is dead and the passkey no longer signs in.
    assert_eq!(
        app.send(attacker.get("/v1/me")).await.status,
        StatusCode::UNAUTHORIZED
    );
    let (_, body) = passkey_login(&app, victim, &mut key, &raw_id).await;
    assert_ne!(body["status"], "authenticated", "{body}");
    // The address is the victim's again.
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(victim)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(email, "victim@example.com");
    let _ = app.ports.clock.now();
}

/// Wave 3A audit (TST-06 gap): **writable** web impersonation and
/// **native** (read-only) impersonation through the full stack.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_writable_and_native_impersonation_through_the_stack(pool: PgPool) {
    let app = App::new(pool).await;
    let mut admin = passkey_admin(&app, "admin@example.com").await;
    let (target, _target_browser) = signed_in(&app, "target@example.com").await;

    // Writable web impersonation: a state-changing request succeeds with
    // the header alone (no cookie, no CSRF token needed: browsers never
    // attach a custom header cross-site)…
    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                &format!("/v1/admin/users/{target}/impersonate"),
                &json!({"reason": "ticket 77", "read_only": false, "ttl_minutes": 5}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(r.set_cookies().is_empty());
    let token = r.json::<Value>()["impersonation_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let with_header = |request: TestRequest| request.header("x-impersonation-session", &token);
    let r = app
        .send(with_header(
            TestRequest::post("/v1/orgs")
                .json(&json!({"name": "Support Co", "slug": "support-co"})),
        ))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    // Account self-service stays off-limits even when writable.
    let r = app
        .send(with_header(
            TestRequest::patch("/v1/me/profile").json(&json!({"display_name": "x"})),
        ))
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "forbidden");
    let me = app.send(with_header(TestRequest::get("/v1/me"))).await;
    assert_eq!(me.json::<Value>()["user_id"], json!(target));
    // …but it is never an admin session, and it cannot step up as the user.
    let r = app
        .send(with_header(TestRequest::get("/v1/admin/users")))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    let r = app
        .send(with_header(
            TestRequest::post("/v1/reauth")
                .json(&json!({"method": "password", "password": PASSWORD})),
        ))
        .await;
    assert!(r.status.is_client_error(), "{}", r.text());
    // The impersonation ends with its lifetime.
    app.advance(Duration::from_secs(6 * 60));
    let r = app.send(with_header(TestRequest::get("/v1/me"))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());

    // Native impersonation: bearer tokens carrying the impersonator,
    // read-only by default.
    passkey_step_up(&app, &mut admin.browser, &mut admin.key).await;
    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                &format!("/v1/admin/users/{target}/impersonate"),
                &json!({"reason": "ticket 78", "client": "native"}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert!(r.set_cookies().is_empty());
    let body: Value = r.json();
    let access = body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"))
        .to_owned();
    let me = app.send(TestRequest::get("/v1/me").bearer(&access)).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text());
    assert_eq!(me.json::<Value>()["user_id"], json!(target));
    let r = app
        .send(
            TestRequest::patch("/v1/me/profile")
                .bearer(&access)
                .json(&json!({"display_name": "x"})),
        )
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "forbidden");
    let r = app
        .send(TestRequest::get("/v1/admin/users").bearer(&access))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
}

/// Wave 3A audit (TST-06 gap): emergency signing-key rotation and the
/// bulk forced password change through the full stack (ADM-06).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_emergency_key_rotation_and_forced_password_change_through_the_stack(pool: PgPool) {
    let app = App::new(pool).await;
    let mut admin = passkey_admin(&app, "admin@example.com").await;
    app.user("mobile@example.com").await;
    // A native session: its access token is signed with the current key.
    let r = app
        .send(
            TestRequest::post("/v1/login/password")
                .header("x-authn-client", "native")
                .json(&json!({"email": "mobile@example.com", "password": PASSWORD})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let old_access = r.json::<Value>()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        app.send(TestRequest::get("/v1/me").bearer(&old_access))
            .await
            .status,
        StatusCode::OK
    );
    let jwks_before: Value = app
        .send(TestRequest::get("/.well-known/jwks.json"))
        .await
        .json();

    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                "/v1/admin/emergency/rotate-signing-key",
                &json!({"reason": "key leak drill", "confirm": "rotate_signing_key"}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let new_kid = r.json::<Value>()["key_id"].as_str().unwrap().to_owned();
    // This instance dropped its key cache at once (SigningKeyCache wiring):
    // the old token is refused, the JWKS no longer offers the old key.
    let r = app
        .send(TestRequest::get("/v1/me").bearer(&old_access))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text());
    let jwks_after: Value = app
        .send(TestRequest::get("/.well-known/jwks.json"))
        .await
        .json();
    let kids = |doc: &Value| -> Vec<String> {
        doc["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_owned())
            .collect()
    };
    assert!(kids(&jwks_after).contains(&new_kid), "{jwks_after}");
    for old in kids(&jwks_before) {
        assert!(!kids(&jwks_after).contains(&old), "{old} still published");
    }
    // The admin's cookie session is unaffected; new tokens use the new key.
    assert_eq!(
        app.send(admin.browser.get("/v1/admin/users")).await.status,
        StatusCode::OK
    );

    // Forced password change for every password older than now.
    app.advance(Duration::from_secs(60));
    let before = app
        .ports
        .clock
        .now()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let r = admin
        .browser
        .send(
            &app,
            admin.browser.post(
                "/v1/admin/emergency/force-password-change",
                &json!({
                    "reason": "credential stuffing wave",
                    "confirm": "force_password_change",
                    "changed_before": before,
                }),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    // The user's next password login yields no full session.
    let mut browser = app.browser();
    let body = browser.login(&app, "mobile@example.com", PASSWORD).await;
    assert_ne!(body["status"], "authenticated", "{body}");
    assert!(body.to_string().contains("change_password"), "{body}");
    assert_eq!(
        app.send(browser.get("/v1/me")).await.status,
        StatusCode::UNAUTHORIZED
    );
    let _ = &mut admin.key;
}
