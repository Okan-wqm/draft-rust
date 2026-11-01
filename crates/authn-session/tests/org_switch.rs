#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Active organization switch (SES-17) and session-id rotation (SES-03).

mod common;

use authn_core::domain::LoginMethod;
use authn_core::ports::SecurityEventKind;
use authn_session::cookies::SESSION_COOKIE;
use authn_testkit::http::TestRequest;
use common::{Harness, ORIGIN, WebLogin, cookie_value, empty_policy, set_cookie};
use http::StatusCode;
use sqlx::PgPool;

fn switch(h: &Harness, login: &WebLogin, org: serde_json::Value) -> TestRequest {
    h.web_post("/v1/session/org", login)
        .json(&serde_json::json!({ "org_id": org }))
}

/// The rotated web login from a credentials response.
fn rotated(login: &WebLogin, res: &authn_testkit::http::TestResponse) -> WebLogin {
    let cookies = res.set_cookies();
    let cookie = cookie_value(set_cookie(&cookies, SESSION_COOKIE).unwrap());
    let body: serde_json::Value = res.json();
    WebLogin {
        user: login.user,
        session_id: login.session_id,
        cookie,
        csrf: body["csrf_token"].as_str().unwrap().to_owned(),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_switching_to_a_member_org_rotates_the_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, member).await;
    let login = h.web_login(member).await;
    let res = h.send(switch(&h, &login, org.to_string().into())).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["active_org_id"], org.to_string());
    let new = rotated(&login, &res);
    // Fixation defence: new cookie, new CSRF token, old cookie dead.
    assert_ne!(new.cookie, login.cookie);
    assert_ne!(new.csrf, login.csrf);
    let old: serde_json::Value = h.send(h.web_get("/v1/probe", &login)).await.json();
    assert_eq!(old["authenticated"], false);
    let now: serde_json::Value = h.send(h.web_get("/v1/probe", &new)).await.json();
    assert_eq!(now["active_org"], org.to_string());
    assert_eq!(now["session_id"], login.session_id.to_string());
    // The old CSRF token does not work with the new cookie.
    h.send(
        TestRequest::post("/v1/probe")
            .cookie(SESSION_COOKIE, &new.cookie)
            .header("origin", ORIGIN)
            .header("x-csrf-token", &login.csrf),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    let events = h.ports.audit.of_kind(SecurityEventKind::SessionOrgSwitched);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].org_id, Some(org));
    // Leaving the organization context rotates again.
    let res = h.send(switch(&h, &new, serde_json::Value::Null)).await;
    res.assert_status(StatusCode::OK);
    assert!(res.json::<serde_json::Value>()["active_org_id"].is_null());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_foreign_or_unknown_organization_is_not_found(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let user = h.user("user@example.com").await;
    let foreign = h.org(owner, "globex").await;
    let login = h.web_login(user).await;
    for org in [foreign.to_string(), uuid::Uuid::now_v7().to_string()] {
        h.send(switch(&h, &login, org.into()))
            .await
            .assert_error(StatusCode::NOT_FOUND, "not_found");
    }
    // A suspended membership is just as invisible.
    let member_org = h.org(owner, "acme").await;
    h.add_member(member_org, user).await;
    sqlx::query("UPDATE memberships SET status = 'suspended' WHERE user_id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
    h.send(switch(&h, &login, member_org.to_string().into()))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    // Nothing was rotated.
    h.send(h.web_get("/v1/me", &login))
        .await
        .assert_status(StatusCode::OK);
    // Malformed ids.
    h.send(switch(&h, &login, "not-an-id".into()))
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_mfa_policy_requires_a_second_factor_step_up(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, member).await;
    let mut policy = empty_policy();
    policy.mfa_required = true;
    h.set_policy(owner, org, policy).await;
    let secret = h.enroll_totp(member).await;
    let login = h.web_login(member).await;
    h.send(switch(&h, &login, org.to_string().into()))
        .await
        .assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");
    // Step up with TOTP: amr gains otp + mfa, the session rotates.
    let code = h.totp_code(&secret);
    let res = h
        .send(
            h.web_post("/v1/reauth", &login)
                .json(&serde_json::json!({ "method": "totp", "code": code })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["amr"], serde_json::json!(["pwd", "otp", "mfa"]));
    let stepped = rotated(&login, &res);
    let res = h.send(switch(&h, &stepped, org.to_string().into())).await;
    res.assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_ip_allowlist_and_login_methods_are_enforced(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let ip_org = h.org(owner, "ip-limited").await;
    let passkey_org = h.org(owner, "passkey-only").await;
    h.add_member(ip_org, member).await;
    h.add_member(passkey_org, member).await;
    let mut policy = empty_policy();
    policy.ip_allowlist = Some(vec!["198.51.100.0/24".into()]);
    h.set_policy(owner, ip_org, policy).await;
    let mut policy = empty_policy();
    policy.allowed_login_methods = Some(vec![LoginMethod::Passkey]);
    h.set_policy(owner, passkey_org, policy).await;
    let login = h.web_login(member).await;
    // The test client is 203.0.113.10.
    h.send(switch(&h, &login, ip_org.to_string().into()))
        .await
        .assert_error(StatusCode::FORBIDDEN, "org_policy_ip_denied");
    let res = h
        .send(
            switch(&h, &login, ip_org.to_string().into()).peer_ip("198.51.100.20".parse().unwrap()),
        )
        .await;
    res.assert_status(StatusCode::OK);
    // A password session cannot enter a passkey-only organization.
    let login = h.web_login(member).await;
    h.send(switch(&h, &login, passkey_org.to_string().into()))
        .await
        .assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_session_lifetime_cap_shrinks_the_absolute_expiry(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, member).await;
    let mut policy = empty_policy();
    policy.max_session_lifetime_seconds = Some(3600);
    h.set_policy(owner, org, policy).await;
    let login = h.web_login(member).await;
    let (_, _, before) = common::session_row(&h.pool, login.session_id).await;
    h.advance(std::time::Duration::from_secs(600));
    let res = h.send(switch(&h, &login, org.to_string().into())).await;
    res.assert_status(StatusCode::OK);
    let (_, idle, after) = common::session_row(&h.pool, login.session_id).await;
    assert!(after < before);
    assert_eq!(
        after - (h.now() - time::Duration::seconds(600)),
        time::Duration::hours(1)
    );
    assert!(idle <= after);
    // Leaving the organization never extends it back.
    let new = rotated(&login, &res);
    h.send(switch(&h, &new, serde_json::Value::Null))
        .await
        .assert_status(StatusCode::OK);
    let (_, _, later) = common::session_row(&h.pool, login.session_id).await;
    assert_eq!(later, after);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_native_switch_rotates_tokens_and_stales_old_access_tokens(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, member).await;
    let login = h.native_login(member).await;
    let res = h
        .send(
            TestRequest::post("/v1/session/org")
                .bearer(&login.access)
                .json(&serde_json::json!({ "org_id": org })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let access = body["access_token"].as_str().unwrap();
    let refresh = body["refresh_token"].as_str().unwrap();
    assert_ne!(refresh, login.refresh);
    assert_eq!(common::jwt_payload(access)["org_id"], org.to_string());
    // The pre-switch access token carries the old context: refused.
    h.send(TestRequest::get("/v1/probe").bearer(&login.access))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let probe: serde_json::Value = h
        .send(TestRequest::get("/v1/probe").bearer(access))
        .await
        .json();
    assert_eq!(probe["active_org"], org.to_string());
    // The new refresh token works.
    h.send(
        TestRequest::post("/v1/token/refresh")
            .json(&serde_json::json!({ "refresh_token": refresh })),
    )
    .await
    .assert_status(StatusCode::OK);
}

// --- security review regressions -------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_verified_org_is_bound_to_the_user_it_was_verified_for(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let outsider = h.user("mallory@example.com").await;
    // The owner's membership proof never activates the organization for
    // another user (ORG-10).
    let mut request = h.request(outsider, h.web_channel());
    request.org = Some(h.verified_org(owner, org).await);
    let mut tx = h.service.begin().await.unwrap();
    let err = h
        .service
        .establish(&mut tx, &h.ctx(), request)
        .await
        .unwrap_err();
    assert!(err.status().is_server_error(), "{err:?}");
    drop(tx);
    assert_eq!(
        h.count(
            "SELECT count(*) FROM sessions WHERE user_id = $1",
            outsider.as_uuid(),
        )
        .await,
        0
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_login_method_policy_reads_the_stored_session_without_session_check(pool: PgPool) {
    // With `access_token_session_check = false` the bearer principal only
    // carries the token's claims; the allowed-login-method rule must still
    // see the session's real login method.
    let h = Harness::with(pool, |c| c.session.access_token_session_check = false).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, member).await;
    let mut policy = empty_policy();
    policy.allowed_login_methods = Some(vec![LoginMethod::Password]);
    h.set_policy(owner, org, policy).await;
    let login = h.native_login(member).await;
    let res = h
        .send(
            TestRequest::post("/v1/session/org")
                .bearer(&login.access)
                .json(&serde_json::json!({ "org_id": org })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["active_org_id"], org.to_string());
    // …and a disallowed method is still refused.
    let mut social = h.request(member, authn_session::ClientChannel::Native);
    social.method = LoginMethod::Social;
    social.amr = vec![authn_core::domain::AuthMethodRef::Fed];
    let social = common::native_of(h.establish(social).await);
    h.send(
        TestRequest::post("/v1/session/org")
            .bearer(&social.access)
            .json(&serde_json::json!({ "org_id": org })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
}
