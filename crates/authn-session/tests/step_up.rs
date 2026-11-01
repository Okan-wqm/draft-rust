#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Step-up re-authentication (SES-13).

mod common;

use std::time::Duration;

use authn_core::ports::SecurityEventKind;
use authn_session::cookies::SESSION_COOKIE;
use authn_testkit::http::TestRequest;
use common::{Harness, PASSWORD, cookie_value, set_cookie};
use http::StatusCode;
use sqlx::PgPool;

fn reauth(h: &Harness, login: &common::WebLogin, body: serde_json::Value) -> TestRequest {
    h.web_post("/v1/reauth", login).json(&body)
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_password_step_up_refreshes_auth_time_and_rotates_the_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    h.advance(Duration::from_secs(3600));
    let me: serde_json::Value = h.send(h.web_get("/v1/me", &login)).await.json();
    let old_auth_time = me["session"]["auth_time"].as_str().unwrap().to_owned();
    let res = h
        .send(reauth(
            &h,
            &login,
            serde_json::json!({ "method": "password", "password": PASSWORD }),
        ))
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_ne!(body["auth_time"], old_auth_time.as_str());
    assert_eq!(
        body["amr"],
        serde_json::json!(["pwd"]),
        "same method adds no mfa"
    );
    let cookies = res.set_cookies();
    let new_cookie = cookie_value(set_cookie(&cookies, SESSION_COOKIE).unwrap());
    assert_ne!(new_cookie, login.cookie, "session id rotated (SES-03)");
    // The old cookie is dead; the new one carries the fresh auth_time.
    h.send(h.web_get("/v1/me", &login))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let me: serde_json::Value = h
        .send(TestRequest::get("/v1/me").cookie(SESSION_COOKIE, &new_cookie))
        .await
        .json();
    assert_eq!(me["session"]["auth_time"], body["auth_time"]);
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::StepUpSucceeded)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_wrong_password_fails_uniformly_and_is_audited(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    let res = h
        .send(reauth(
            &h,
            &login,
            serde_json::json!({ "method": "password", "password": "wrong password 123" }),
        ))
        .await;
    res.assert_error(StatusCode::UNAUTHORIZED, "reauthentication_failed");
    assert!(!res.text().contains("wrong password"), "never echoed");
    let failed = h.ports.audit.of_kind(SecurityEventKind::StepUpFailed);
    assert_eq!(failed.len(), 1);
    assert!(!format!("{failed:?}").contains("wrong password"));
    // The session is untouched.
    h.send(h.web_get("/v1/me", &login))
        .await
        .assert_status(StatusCode::OK);
    // Without CSRF the attempt never reaches verification.
    h.send(
        TestRequest::post("/v1/reauth")
            .cookie(SESSION_COOKIE, &login.cookie)
            .header("origin", common::ORIGIN)
            .json(&serde_json::json!({ "method": "password", "password": PASSWORD })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_totp_step_up_adds_mfa_and_refuses_replay(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let secret = h.enroll_totp(user).await;
    let login = h.web_login(user).await;
    // Wrong code: uniform failure.
    h.send(reauth(
        &h,
        &login,
        serde_json::json!({ "method": "totp", "code": "000000" }),
    ))
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "reauthentication_failed");
    let code = h.totp_code(&secret);
    let res = h
        .send(reauth(
            &h,
            &login,
            serde_json::json!({ "method": "totp", "code": code }),
        ))
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(
        res.json::<serde_json::Value>()["amr"],
        serde_json::json!(["pwd", "otp", "mfa"])
    );
    // Replaying the same TOTP code fails (MFA-02 through step-up).
    let cookies = res.set_cookies();
    let rotated = common::WebLogin {
        user,
        session_id: login.session_id,
        cookie: cookie_value(set_cookie(&cookies, SESSION_COOKIE).unwrap()),
        csrf: res.json::<serde_json::Value>()["csrf_token"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    h.send(reauth(
        &h,
        &rotated,
        serde_json::json!({ "method": "totp", "code": code }),
    ))
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "reauthentication_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_step_up_is_rate_limited_per_user(pool: PgPool) {
    let h = Harness::with(pool, |c| {
        c.session.step_up_per_user =
            authn_core::ports::RateLimitPolicy::new(3, Duration::from_secs(900));
    })
    .await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    for _ in 0..3 {
        h.send(reauth(
            &h,
            &login,
            serde_json::json!({ "method": "password", "password": "nope nope nope" }),
        ))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "reauthentication_failed");
    }
    let res = h
        .send(reauth(
            &h,
            &login,
            serde_json::json!({ "method": "password", "password": PASSWORD }),
        ))
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_platform_admins_and_strict_orgs_need_a_passkey(pool: PgPool) {
    let h = Harness::new(pool).await;
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    let login = h.web_login(admin).await;
    h.send(reauth(
        &h,
        &login,
        serde_json::json!({ "method": "password", "password": PASSWORD }),
    ))
    .await
    .assert_error(StatusCode::FORBIDDEN, "step_up_method_not_allowed");

    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, member).await;
    let mut request = h.request(member, h.web_channel());
    request.org = Some(h.verified_org(member, org).await);
    let in_org = common::web_of(h.establish(request).await);
    let mut policy = common::empty_policy();
    policy.mfa_required = true;
    policy.phishing_resistant_mfa_required = true;
    h.set_policy(owner, org, policy).await;
    // (The tightening revoked org sessions; establish a fresh one.)
    let _ = in_org;
    let mut request = h.request(member, h.web_channel());
    let verified = {
        let mut conn = h.pool.acquire().await.unwrap();
        h.service
            .verify_login_org(
                &mut conn,
                &h.ctx(),
                member,
                org,
                authn_core::domain::LoginMethod::Password,
            )
            .await
            .unwrap()
    };
    request.org = Some(verified);
    request.amr = vec![
        authn_core::domain::AuthMethodRef::Hwk,
        authn_core::domain::AuthMethodRef::User,
        authn_core::domain::AuthMethodRef::Mfa,
    ];
    let strict = common::web_of(h.establish(request).await);
    h.send(reauth(
        &h,
        &strict,
        serde_json::json!({ "method": "password", "password": PASSWORD }),
    ))
    .await
    .assert_error(StatusCode::FORBIDDEN, "step_up_method_not_allowed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_native_step_up_rotates_tokens(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    h.advance(Duration::from_secs(120));
    let res = h
        .send(
            TestRequest::post("/v1/reauth")
                .bearer(&login.access)
                .json(&serde_json::json!({ "method": "password", "password": PASSWORD })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let access = body["access_token"].as_str().unwrap();
    let claims = common::jwt_payload(access);
    let old = common::jwt_payload(&login.access);
    assert!(claims["auth_time"].as_i64() > old["auth_time"].as_i64());
    // The pre-step-up token keeps its old auth_time (never upgraded).
    let principal: serde_json::Value = h
        .send(TestRequest::get("/v1/me").bearer(&login.access))
        .await
        .json();
    assert_eq!(
        time::OffsetDateTime::parse(
            principal["session"]["auth_time"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339
        )
        .unwrap()
        .unix_timestamp(),
        old["auth_time"].as_i64().unwrap()
    );
    assert_ne!(body["refresh_token"], login.refresh.as_str());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_unknown_method_and_unauthenticated_are_refused(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    h.send(reauth(
        &h,
        &login,
        serde_json::json!({ "method": "sms", "code": "123456" }),
    ))
    .await
    .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    h.send(
        TestRequest::post("/v1/reauth")
            .json(&serde_json::json!({ "method": "password", "password": PASSWORD })),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_passkey_step_up_needs_a_passkey_and_a_bound_ceremony(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    // No passkey registered: nothing to start.
    let res = h
        .send(h.web_post("/v1/reauth/passkey/options", &login))
        .await;
    assert!(
        res.status == StatusCode::BAD_REQUEST,
        "unexpected status {}: {}",
        res.status,
        res.text()
    );
    assert_eq!(res.error().code, "passkey_not_available");
    // A forged / unknown ceremony never verifies.
    h.send(reauth(
        &h,
        &login,
        serde_json::json!({
            "method": "passkey",
            "ceremony_id": uuid::Uuid::now_v7(),
            "binding_token": "A".repeat(43),
            "credential": {}
        }),
    ))
    .await
    .assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");
    // Without a binding token at all.
    h.send(reauth(
        &h,
        &login,
        serde_json::json!({
            "method": "passkey",
            "ceremony_id": uuid::Uuid::now_v7(),
            "credential": {}
        }),
    ))
    .await
    .assert_error(StatusCode::BAD_REQUEST, "passkey_ceremony_invalid");
}

// --- security review regressions -------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_strictest_membership_policy_applies_outside_the_strict_org(pool: PgPool) {
    // Step-up unlocks account-wide operations: a member of an organization
    // that requires phishing-resistant MFA cannot step up with the password
    // in the personal context or in a lax organization's context.
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let strict = h.org(owner, "strict").await;
    let lax = h.org(owner, "lax").await;
    h.add_member(strict, member).await;
    h.add_member(lax, member).await;
    let mut policy = common::empty_policy();
    policy.mfa_required = true;
    policy.phishing_resistant_mfa_required = true;
    h.set_policy(owner, strict, policy).await;

    let personal = h.web_login(member).await;
    h.send(reauth(
        &h,
        &personal,
        serde_json::json!({ "method": "password", "password": PASSWORD }),
    ))
    .await
    .assert_error(StatusCode::FORBIDDEN, "step_up_method_not_allowed");

    let mut request = h.request(member, h.web_channel());
    request.org = Some(h.verified_org(member, lax).await);
    let in_lax = common::web_of(h.establish(request).await);
    h.send(reauth(
        &h,
        &in_lax,
        serde_json::json!({ "method": "password", "password": PASSWORD }),
    ))
    .await
    .assert_error(StatusCode::FORBIDDEN, "step_up_method_not_allowed");

    // A user without such a membership still steps up with the password.
    let free = h.user("free@example.com").await;
    let login = h.web_login(free).await;
    h.send(reauth(
        &h,
        &login,
        serde_json::json!({ "method": "password", "password": PASSWORD }),
    ))
    .await
    .assert_status(StatusCode::OK);
}
