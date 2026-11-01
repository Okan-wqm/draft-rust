#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! `GET /v1/me` (SES-16), the `SessionIssuer` port (SES-15): federated
//! login pipeline and impersonation (ADM-04).

mod common;

use std::time::Duration;

use authn_core::domain::{AuthMethodRef, ClientKind, LoginMethod};
use authn_core::ports::{
    ImpersonationRequest, LoginOutcome, NotificationKind, PrimaryAuthentication, RequiredAction,
    SecurityEventKind, SessionIssuer,
};
use authn_session::cookies::SESSION_COOKIE;
use authn_testkit::http::TestRequest;
use common::{Harness, empty_policy};
use http::StatusCode;
use http_body_util::BodyExt;
use sqlx::PgPool;

fn social(user: authn_core::id::UserId, client: ClientKind) -> PrimaryAuthentication {
    PrimaryAuthentication {
        user_id: user,
        method: LoginMethod::Social,
        amr: vec![AuthMethodRef::Fed],
        client,
        remember_me: false,
        shared_device: false,
        requested_org: None,
        provider_asserted_mfa: false,
    }
}

fn impersonation(
    admin: authn_core::id::UserId,
    target: authn_core::id::UserId,
    read_only: bool,
) -> ImpersonationRequest {
    ImpersonationRequest {
        admin_user_id: admin,
        target_user_id: target,
        read_only,
        ttl: Duration::from_secs(15 * 60),
        reason: "Support ticket 4711".into(),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_16_me_returns_profile_methods_organization_and_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.enroll_totp(owner).await;
    let mut request = h.request(owner, h.web_channel());
    request.org = Some(h.verified_org(owner, org).await);
    let login = common::web_of(h.establish(request).await);
    let res = h.send(h.web_get("/v1/me", &login)).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let me: serde_json::Value = res.json();
    assert_eq!(me["user_id"], owner.to_string());
    assert_eq!(me["email"], "alice@example.com");
    assert_eq!(me["email_verified"], true);
    assert_eq!(me["status"], "active");
    assert_eq!(me["methods"]["password"], true);
    assert_eq!(me["methods"]["passkeys"], 0);
    assert_eq!(me["methods"]["mfa_enabled"], true);
    assert_eq!(me["methods"]["mfa_factors"], serde_json::json!(["totp"]));
    assert_eq!(me["active_organization"]["id"], org.to_string());
    assert_eq!(me["active_organization"]["name"], "Org acme");
    assert_eq!(me["session"]["id"], login.session_id.to_string());
    assert_eq!(me["session"]["client_kind"], "web");
    assert_eq!(me["session"]["amr"], serde_json::json!(["pwd"]));
    assert!(me["session"]["impersonation"].is_null());
    assert_eq!(me["is_platform_admin"], false);
    // Unauthenticated.
    h.send(TestRequest::get("/v1/me"))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_session_issuer_federated_login_issues_or_challenges(pool: PgPool) {
    let h = Harness::new(pool).await;
    let issuer: &dyn SessionIssuer = &h.service;
    let user = h.user("alice@example.com").await;
    // No MFA: a session, rendered as a cookie for web.
    let outcome = issuer
        .complete_primary_authentication(&h.ctx(), social(user, ClientKind::Web))
        .await
        .unwrap();
    let LoginOutcome::Authenticated(session) = outcome.clone() else {
        panic!("expected a session")
    };
    assert!(session.session_token.is_some() && session.access_token.is_none());
    let response = issuer.login_response(outcome, Some("/dashboard"));
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/dashboard");
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("__Host-authn_session=") && cookie.contains("HttpOnly"));
    let me: serde_json::Value = h
        .send(
            TestRequest::get("/v1/me")
                .cookie(SESSION_COOKIE, session.session_token.unwrap().expose()),
        )
        .await
        .json();
    assert_eq!(me["session"]["amr"], serde_json::json!(["fed"]));
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::LoginSucceeded)
            .len(),
        1
    );

    // Native: tokens in the body.
    let outcome = issuer
        .complete_primary_authentication(&h.ctx(), social(user, ClientKind::Native))
        .await
        .unwrap();
    let response = issuer.login_response(outcome, None);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["access_token"].is_string() && body["refresh_token"].is_string());

    // With an enrolled factor, the provider's word is not enough (SOC-09
    // default): a challenge with the allowed factors.
    h.enroll_totp(user).await;
    let mut auth = social(user, ClientKind::Native);
    auth.provider_asserted_mfa = true;
    let outcome = issuer
        .complete_primary_authentication(&h.ctx(), auth)
        .await
        .unwrap();
    let LoginOutcome::ChallengeRequired(challenge) = outcome else {
        panic!("expected a challenge")
    };
    assert_eq!(challenge.required_actions, vec![RequiredAction::VerifyMfa]);
    assert!(
        challenge
            .allowed_factors
            .contains(&authn_core::domain::FactorKind::Totp)
    );
    // A passkey with user verification satisfies MFA (SES-21).
    let mut passkey = social(user, ClientKind::Native);
    passkey.method = LoginMethod::Passkey;
    passkey.amr = vec![AuthMethodRef::Swk, AuthMethodRef::User, AuthMethodRef::Mfa];
    assert!(matches!(
        issuer
            .complete_primary_authentication(&h.ctx(), passkey)
            .await
            .unwrap(),
        LoginOutcome::Authenticated(_)
    ));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_federated_login_refuses_blocked_accounts_and_disallowed_orgs(pool: PgPool) {
    let h = Harness::new(pool).await;
    let issuer: &dyn SessionIssuer = &h.service;
    let user = h.user("alice@example.com").await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
    let err = issuer
        .complete_primary_authentication(&h.ctx(), social(user, ClientKind::Web))
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "account_suspended");

    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let mut policy = empty_policy();
    policy.allowed_login_methods = Some(vec![LoginMethod::Password]);
    h.set_policy(owner, org, policy).await;
    let mut auth = social(owner, ClientKind::Web);
    auth.requested_org = Some(org);
    let err = issuer
        .complete_primary_authentication(&h.ctx(), auth)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "login_method_not_allowed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_impersonation_is_read_only_audited_notified_and_time_boxed(pool: PgPool) {
    let h = Harness::new(pool).await;
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    let target = h.user("alice@example.com").await;
    // The admin needs a live session of their own.
    let issuer: &dyn SessionIssuer = &h.service;
    let err = issuer
        .start_impersonation(&h.ctx(), impersonation(admin, target, true))
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "forbidden");
    let mut admin_login = h.request(admin, h.web_channel());
    admin_login.amr = vec![AuthMethodRef::Hwk, AuthMethodRef::User, AuthMethodRef::Mfa];
    h.establish(admin_login).await;

    let issued = issuer
        .start_impersonation(&h.ctx(), impersonation(admin, target, true))
        .await
        .unwrap();
    assert_eq!(issued.user_id, target);
    assert!(issued.browser_session_only);
    assert_eq!(
        issued.absolute_expires_at - h.now(),
        time::Duration::minutes(15)
    );
    let cookie = issued.session_token.unwrap().expose().to_owned();
    let me: serde_json::Value = h
        .send(TestRequest::get("/v1/me").cookie(SESSION_COOKIE, &cookie))
        .await
        .json();
    assert_eq!(me["user_id"], target.to_string());
    assert_eq!(
        me["session"]["impersonation"]["admin_user_id"],
        admin.to_string()
    );
    assert_eq!(me["session"]["impersonation"]["read_only"], true);
    assert_eq!(
        me["session"]["amr"],
        serde_json::json!(["hwk", "user", "mfa"])
    );
    assert_eq!(me["is_platform_admin"], false);
    // Read-only: every state-changing request is refused, CSRF or not…
    let csrf: serde_json::Value = h
        .send(TestRequest::get("/v1/csrf").cookie(SESSION_COOKIE, &cookie))
        .await
        .json();
    let csrf = csrf["csrf_token"].as_str().unwrap();
    for path in [
        "/v1/probe",
        "/v1/session/org",
        "/v1/reauth",
        "/v1/logout/all",
    ] {
        h.send(
            TestRequest::post(path)
                .cookie(SESSION_COOKIE, &cookie)
                .header("origin", common::ORIGIN)
                .header("x-csrf-token", csrf)
                .json(&serde_json::json!({})),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    }
    // …except ending the impersonation.
    let audit = h
        .ports
        .audit
        .of_kind(SecurityEventKind::ImpersonationStarted);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].impersonator, Some(admin));
    assert_eq!(audit[0].subject_user, Some(target));
    let notified = h.ports.notifier.recorded();
    assert!(notified.iter().any(|n| matches!(
        n.kind,
        NotificationKind::ImpersonationStarted { .. }
    ) && n.recipient.user_id == Some(target)));
    h.send(
        TestRequest::post("/v1/logout")
            .cookie(SESSION_COOKIE, &cookie)
            .header("origin", common::ORIGIN)
            .header("x-csrf-token", csrf),
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::ImpersonationEnded)
            .len(),
        1
    );

    // Time-boxed: never longer than the configured maximum, never extended.
    let issued = issuer
        .start_impersonation(&h.ctx(), impersonation(admin, target, false))
        .await
        .unwrap();
    let cookie = issued.session_token.unwrap().expose().to_owned();
    h.advance(Duration::from_secs(15 * 60 + 1));
    h.send(TestRequest::get("/v1/me").cookie(SESSION_COOKIE, &cookie))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let mut too_long = impersonation(admin, target, true);
    too_long.ttl = Duration::from_secs(61 * 60);
    assert_eq!(
        issuer
            .start_impersonation(&h.ctx(), too_long)
            .await
            .unwrap_err()
            .code()
            .code(),
        "validation_failed"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_impersonation_refuses_admins_break_glass_and_non_admins(pool: PgPool) {
    let h = Harness::new(pool).await;
    let issuer: &dyn SessionIssuer = &h.service;
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    h.establish(h.request(admin, h.web_channel())).await;
    let other_admin = h.user("admin2@example.com").await;
    h.make_admin(other_admin).await;
    let glass = h.user("glass@example.com").await;
    sqlx::query("UPDATE users SET is_platform_admin = true, is_break_glass = true WHERE id = $1")
        .bind(glass)
        .execute(&h.pool)
        .await
        .unwrap();
    for target in [other_admin, glass, admin] {
        let err = issuer
            .start_impersonation(&h.ctx(), impersonation(admin, target, true))
            .await
            .unwrap_err();
        assert_eq!(err.code().code(), "impersonation_not_allowed");
    }
    let user = h.user("alice@example.com").await;
    let not_admin = h.user("mallory@example.com").await;
    h.establish(h.request(not_admin, h.web_channel())).await;
    let err = issuer
        .start_impersonation(&h.ctx(), impersonation(not_admin, user, true))
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "forbidden");
    let mut no_reason = impersonation(admin, user, true);
    no_reason.reason = "  ".into();
    assert_eq!(
        issuer
            .start_impersonation(&h.ctx(), no_reason)
            .await
            .unwrap_err()
            .code()
            .code(),
        "validation_failed"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_08_native_impersonation_tokens_carry_the_act_claim(pool: PgPool) {
    let h = Harness::new(pool).await;
    let issuer: &dyn SessionIssuer = &h.service;
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    let admin_session = h.establish(h.request(admin, h.web_channel())).await;
    let target = h.user("alice@example.com").await;
    let issued = issuer
        .start_impersonation_with(
            &h.ctx(),
            impersonation(admin, target, true),
            ClientKind::Native,
            Some(admin_session.session.id),
        )
        .await
        .unwrap();
    let access = issued.access_token.unwrap().expose().to_owned();
    let claims = common::jwt_payload(&access);
    assert_eq!(claims["sub"], target.to_string());
    assert_eq!(
        claims["act"],
        serde_json::json!({ "sub": admin.to_string() })
    );
    assert_eq!(claims["read_only"], true);
    // The refresh family ends with the impersonation.
    assert_eq!(issued.idle_expires_at, issued.absolute_expires_at);
    // Read-only through the bearer path too.
    h.send(TestRequest::post("/v1/probe").bearer(&access))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    let body: serde_json::Value = h
        .send(TestRequest::get("/v1/probe").bearer(&access))
        .await
        .json();
    assert_eq!(body["impersonated"], true);
    // Even a writable impersonation can never step up (ADM-04).
    let writable = issuer
        .start_impersonation_with(
            &h.ctx(),
            impersonation(admin, target, false),
            ClientKind::Native,
            None,
        )
        .await
        .unwrap();
    let access = writable.access_token.unwrap().expose().to_owned();
    assert!(common::jwt_payload(&access).get("read_only").is_some());
    h.send(
        TestRequest::post("/v1/reauth")
            .bearer(&access)
            .json(&serde_json::json!({ "method": "password", "password": common::PASSWORD })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "forbidden");
}

// --- security review regressions -------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_primary_authentication_cannot_claim_mfa_or_passkey_amr(pool: PgPool) {
    // SOC-09 / SES-21: only a passkey ceremony proves `mfa` / `hwk` / `swk`
    // at the primary step; any other caller-supplied claim is dropped.
    let h = Harness::new(pool).await;
    let issuer: &dyn SessionIssuer = &h.service;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    for (method, amr) in [
        (
            LoginMethod::Social,
            vec![AuthMethodRef::Fed, AuthMethodRef::Mfa],
        ),
        (
            LoginMethod::Social,
            vec![
                AuthMethodRef::Fed,
                AuthMethodRef::Hwk,
                AuthMethodRef::User,
                AuthMethodRef::Mfa,
            ],
        ),
        (
            LoginMethod::Password,
            vec![AuthMethodRef::Pwd, AuthMethodRef::Swk, AuthMethodRef::Mfa],
        ),
    ] {
        let mut auth = social(user, ClientKind::Native);
        auth.method = method;
        auth.amr = amr.clone();
        let outcome = issuer
            .complete_primary_authentication(&h.ctx(), auth)
            .await
            .unwrap();
        let LoginOutcome::ChallengeRequired(challenge) = outcome else {
            panic!("{method:?} with {amr:?} skipped the second factor")
        };
        assert_eq!(challenge.required_actions, vec![RequiredAction::VerifyMfa]);
    }
    // Without an MFA requirement the session keeps only what the method
    // proves, so no later organization check trusts a forged `hwk`/`mfa`.
    let other = h.user("bob@example.com").await;
    let mut auth = social(other, ClientKind::Web);
    auth.amr = vec![AuthMethodRef::Fed, AuthMethodRef::Hwk, AuthMethodRef::Mfa];
    let LoginOutcome::Authenticated(session) = issuer
        .complete_primary_authentication(&h.ctx(), auth)
        .await
        .unwrap()
    else {
        panic!("expected a session")
    };
    let me: serde_json::Value = h
        .send(
            TestRequest::get("/v1/me")
                .cookie(SESSION_COOKIE, session.session_token.unwrap().expose()),
        )
        .await
        .json();
    assert_eq!(me["session"]["amr"], serde_json::json!(["fed"]));
}

async fn impersonate_web(
    h: &Harness,
    admin: authn_core::id::UserId,
    target: authn_core::id::UserId,
    read_only: bool,
) -> String {
    let issuer: &dyn SessionIssuer = &h.service;
    issuer
        .start_impersonation(&h.ctx(), impersonation(admin, target, read_only))
        .await
        .unwrap()
        .session_token
        .unwrap()
        .expose()
        .to_owned()
}

async fn me_status(h: &Harness, cookie: &str) -> StatusCode {
    h.send(TestRequest::get("/v1/me").cookie(SESSION_COOKIE, cookie))
        .await
        .status
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_impersonation_ends_when_the_admin_is_revoked_demoted_or_suspended(pool: PgPool) {
    let h = Harness::new(pool).await;
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    h.establish(h.request(admin, h.web_channel())).await;
    let target = h.user("alice@example.com").await;
    let own = h.web_login(target).await;

    // 1. Revoking every session of the admin (suspension, reset, "sign out
    //    everywhere") ends the impersonations they started — not the
    //    target's own sessions.
    let cookie = impersonate_web(&h, admin, target, true).await;
    assert_eq!(me_status(&h, &cookie).await, StatusCode::OK);
    let mut tx = h.service.begin().await.unwrap();
    authn_core::ports::SessionRevoker::revoke_all_for_user(
        &h.revoker,
        &mut tx,
        admin,
        authn_core::ports::RevocationReason::AccountSuspended,
        authn_core::ports::RevokeOptions::default(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(me_status(&h, &cookie).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me_status(&h, &own.cookie).await, StatusCode::OK);

    // 2. A demoted admin's impersonation stops at once (web and native).
    h.establish(h.request(admin, h.web_channel())).await;
    let cookie = impersonate_web(&h, admin, target, true).await;
    let issuer: &dyn SessionIssuer = &h.service;
    let native = issuer
        .start_impersonation_with(
            &h.ctx(),
            impersonation(admin, target, true),
            ClientKind::Native,
            None,
        )
        .await
        .unwrap();
    let access = native.access_token.unwrap().expose().to_owned();
    let refresh = native.refresh_token.unwrap().expose().to_owned();
    sqlx::query("UPDATE users SET is_platform_admin = false WHERE id = $1")
        .bind(admin)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(me_status(&h, &cookie).await, StatusCode::UNAUTHORIZED);
    h.send(TestRequest::get("/v1/probe").bearer(&access))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    h.send(
        TestRequest::post("/v1/token/refresh")
            .json(&serde_json::json!({ "refresh_token": refresh })),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");

    // 3. So does a suspended admin's.
    h.make_admin(admin).await;
    let cookie = impersonate_web(&h, admin, target, true).await;
    assert_eq!(me_status(&h, &cookie).await, StatusCode::OK);
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(admin)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(me_status(&h, &cookie).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me_status(&h, &own.cookie).await, StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_11_impersonation_cannot_end_the_users_other_sessions(pool: PgPool) {
    let h = Harness::new(pool).await;
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    h.establish(h.request(admin, h.web_channel())).await;
    let target = h.user("alice@example.com").await;
    let own = h.web_login(target).await;
    // Even a writable impersonation may only end itself.
    let cookie = impersonate_web(&h, admin, target, false).await;
    let csrf: serde_json::Value = h
        .send(TestRequest::get("/v1/csrf").cookie(SESSION_COOKIE, &cookie))
        .await
        .json();
    let csrf = csrf["csrf_token"].as_str().unwrap().to_owned();
    let delete = |id: authn_core::id::SessionId| {
        TestRequest::delete(&format!("/v1/me/sessions/{id}"))
            .cookie(SESSION_COOKIE, &cookie)
            .header("origin", common::ORIGIN)
            .header("x-csrf-token", &csrf)
    };
    h.send(delete(own.session_id))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    assert_eq!(me_status(&h, &own.cookie).await, StatusCode::OK);
    let me: serde_json::Value = h
        .send(TestRequest::get("/v1/me").cookie(SESSION_COOKIE, &cookie))
        .await
        .json();
    let current: authn_core::id::SessionId = me["session"]["id"].as_str().unwrap().parse().unwrap();
    h.send(delete(current))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(me_status(&h, &cookie).await, StatusCode::UNAUTHORIZED);
}
