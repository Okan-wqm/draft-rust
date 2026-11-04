#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ADM-01: the authorization matrix of every `/v1/admin/**` route.

mod common;

use std::time::Duration;

use authn_core::domain::{AccountStatus, AuthMethodRef, PrincipalCredential, Subject};
use authn_core::id::{ApiKeyId, OrgId, ServiceAccountId, UserId};
use authn_testkit::http::TestRequest;
use axum::http::{Method, StatusCode};
use common::{ADMIN_IP, Harness};
use serde_json::json;

/// Every route of the admin router with a body that would be valid.
fn every_route(target: UserId) -> Vec<(Method, String, serde_json::Value)> {
    let r = json!({ "reason": "matrix test" });
    let u = format!("/v1/admin/users/{target}");
    vec![
        (Method::GET, "/v1/admin/users".into(), json!(null)),
        (Method::GET, u.clone(), json!(null)),
        (Method::POST, format!("{u}/suspend"), r.clone()),
        (Method::POST, format!("{u}/unsuspend"), r.clone()),
        (Method::POST, format!("{u}/unlock"), r.clone()),
        (Method::POST, format!("{u}/revoke-sessions"), r.clone()),
        (Method::POST, format!("{u}/force-password-reset"), r.clone()),
        (
            Method::POST,
            format!("{u}/must-change-password"),
            json!({ "reason": "x", "must_change": true }),
        ),
        (Method::POST, format!("{u}/reset-mfa"), r.clone()),
        (Method::POST, format!("{u}/mark-email-verified"), r.clone()),
        (Method::POST, format!("{u}/impersonate"), r.clone()),
        (
            Method::POST,
            "/v1/admin/emergency/revoke-all-sessions".into(),
            json!({ "reason": "x", "confirm": "revoke_all_sessions" }),
        ),
        (
            Method::POST,
            "/v1/admin/emergency/rotate-signing-key".into(),
            json!({ "reason": "x", "confirm": "rotate_signing_key" }),
        ),
        (
            Method::POST,
            "/v1/admin/emergency/force-password-change".into(),
            json!({
                "reason": "x",
                "confirm": "force_password_change",
                "changed_before": "2020-01-01T00:00:00Z"
            }),
        ),
        (Method::GET, "/v1/admin/audit-events".into(), json!(null)),
        (
            Method::POST,
            "/v1/admin/audit-events/export".into(),
            json!({ "reason": "x" }),
        ),
        (
            Method::POST,
            "/v1/admin/audit-events/verify".into(),
            json!({}),
        ),
    ]
}

fn request(method: &Method, uri: &str, body: &serde_json::Value) -> TestRequest {
    let req = TestRequest::new(method.clone(), uri);
    if body.is_null() { req } else { req.json(body) }
}

/// Sends every route as `principal` and asserts the same refusal; returns
/// nothing changed (the target stays active).
async fn assert_all_refused(
    h: &Harness,
    principal: &authn_core::domain::Principal,
    target: UserId,
    status: StatusCode,
    code: &str,
) {
    for (method, uri, body) in every_route(target) {
        let res = h.send(principal, request(&method, &uri, &body)).await;
        assert_eq!(res.status, status, "{method} {uri}: {}", res.text());
        assert_eq!(res.error().code, code, "{method} {uri}");
    }
    assert_eq!(h.record(target).await.status, AccountStatus::Active);
    assert!(h.ports.session_revoker.calls().is_empty());
    assert!(h.issuer.requests.lock().unwrap().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_requests_without_principal(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let target = h.user("target@example.com").await;
    for (method, uri, body) in every_route(target) {
        let res = request(&method, &uri, &body)
            .peer_ip(ADMIN_IP.parse().unwrap())
            .send(&h.app(None))
            .await;
        res.assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_non_admin(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let target = h.user("target@example.com").await;
    let user = h.user("user@example.com").await;
    // A regular user with a perfect passkey session, flag false.
    let principal = h.principal(user, false);
    assert_all_refused(&h, &principal, target, StatusCode::FORBIDDEN, "forbidden").await;
    // A principal claiming admin whose database row says otherwise (stale
    // or forged claim) is refused too.
    let forged = h.principal(user, true);
    assert_all_refused(&h, &forged, target, StatusCode::FORBIDDEN, "forbidden").await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_demoted_or_suspended_admin_immediately(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let target = h.user("target@example.com").await;
    let (admin, principal) = h.admin("admin@example.com").await;
    let res = h
        .send(&principal, TestRequest::get("/v1/admin/users"))
        .await;
    res.assert_status(StatusCode::OK);
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(admin)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_all_refused(&h, &principal, target, StatusCode::FORBIDDEN, "forbidden").await;
    sqlx::query("UPDATE users SET status = 'active', is_platform_admin = false WHERE id = $1")
        .bind(admin)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_all_refused(&h, &principal, target, StatusCode::FORBIDDEN, "forbidden").await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_admin_without_passkey_amr(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let target = h.user("target@example.com").await;
    let (_, principal) = h.admin("admin@example.com").await;
    for amr in [
        vec![AuthMethodRef::Pwd],
        vec![AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa],
        vec![AuthMethodRef::Pwd, AuthMethodRef::Sms, AuthMethodRef::Mfa],
        vec![AuthMethodRef::Email, AuthMethodRef::Kba, AuthMethodRef::Mfa],
        // A passkey without user verification is a single factor.
        vec![AuthMethodRef::Hwk, AuthMethodRef::User],
    ] {
        let mut p = principal.clone();
        p.amr = amr;
        assert_all_refused(
            &h,
            &p,
            target,
            StatusCode::FORBIDDEN,
            "admin_phishing_resistant_mfa_required",
        )
        .await;
    }
    // The refusal of a real admin is audited.
    let denials = h.admin_events("admin_access").await;
    assert!(!denials.is_empty());
    assert!(
        denials.iter().all(|e| e.outcome == "failure"
            && e.reason.as_deref() == Some("phishing_resistant_mfa_missing"))
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_admin_without_recent_step_up(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let target = h.user("target@example.com").await;
    let (_, mut principal) = h.admin("admin@example.com").await;
    principal.auth_time = Some(h.now() - Duration::from_secs(10 * 60 + 1));
    assert_all_refused(
        &h,
        &principal,
        target,
        StatusCode::UNAUTHORIZED,
        "step_up_required",
    )
    .await;
    principal.auth_time = None;
    assert_all_refused(
        &h,
        &principal,
        target,
        StatusCode::UNAUTHORIZED,
        "step_up_required",
    )
    .await;
    // Exactly at the window edge it is still accepted.
    principal.auth_time = Some(h.now() - Duration::from_secs(10 * 60));
    let res = h
        .send(&principal, TestRequest::get("/v1/admin/users"))
        .await;
    res.assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_impersonated_principal_and_impersonator(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let target = h.user("target@example.com").await;
    let (_, admin) = h.admin("admin@example.com").await;
    // The impersonation session of an admin, read-only and writable alike.
    for read_only in [true, false] {
        let p = h.impersonated(admin.clone(), read_only);
        assert_all_refused(&h, &p, target, StatusCode::FORBIDDEN, "forbidden").await;
    }
    // A regular user's principal under impersonation (the impersonator
    // acting as that user) is refused even if the claim says admin.
    let victim = h.user("victim@example.com").await;
    let mut p = h.principal(victim, true);
    p = h.impersonated(p, false);
    assert_all_refused(&h, &p, target, StatusCode::FORBIDDEN, "forbidden").await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_api_keys_and_service_accounts(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let target = h.user("target@example.com").await;
    let (_, admin) = h.admin("admin@example.com").await;
    let mut key = admin.clone();
    key.credential = PrincipalCredential::ApiKey {
        api_key_id: ApiKeyId::generate(),
    };
    assert_all_refused(&h, &key, target, StatusCode::FORBIDDEN, "forbidden").await;
    let mut service = admin.clone();
    service.subject = Subject::ServiceAccount {
        service_account_id: ServiceAccountId::generate(),
        org_id: OrgId::generate(),
    };
    assert_all_refused(&h, &service, target, StatusCode::FORBIDDEN, "forbidden").await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_rejects_ip_outside_allow_list(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.ip_allow_list = vec!["10.0.0.0/8".parse().unwrap()];
    })
    .await;
    let target = h.user("target@example.com").await;
    let (_, admin) = h.admin("admin@example.com").await;
    // ADMIN_IP (203.0.113.10) is outside 10/8.
    assert_all_refused(&h, &admin, target, StatusCode::FORBIDDEN, "forbidden").await;
    let denials = h.admin_events("admin_access").await;
    assert!(
        denials
            .iter()
            .any(|e| e.reason.as_deref() == Some("ip_not_allowed"))
    );
    // From inside the allow-list the same principal is accepted.
    let res = TestRequest::get("/v1/admin/users")
        .peer_ip("10.20.30.40".parse().unwrap())
        .send(&h.app(Some(admin)))
        .await;
    res.assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_proper_admin_is_allowed_on_every_route(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    // Synced passkeys (swk) are phishing-resistant as well.
    let mut synced = admin.clone();
    synced.amr = vec![AuthMethodRef::Swk, AuthMethodRef::Mfa];
    for principal in [admin, synced] {
        let target = h
            .user(&format!("t{}@example.com", UserId::generate()))
            .await;
        for (method, uri, body) in every_route(target) {
            let res = h.send(&principal, request(&method, &uri, &body)).await;
            // Some actions are refused for business reasons (e.g. unsuspend
            // of an active account, 409) — never by the guard.
            assert!(
                !matches!(res.status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
                "{method} {uri}: {} {}",
                res.status,
                res.text()
            );
            if res.status.is_success() {
                assert_eq!(
                    res.header("cache-control"),
                    Some("no-store"),
                    "{method} {uri}"
                );
            }
        }
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_break_glass_use_emits_high_priority_event(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let id = h.user("glass@example.com").await;
    h.make_admin(id, true).await;
    let principal = h.principal(id, true);
    let res = h
        .send(&principal, TestRequest::get("/v1/admin/users"))
        .await;
    res.assert_status(StatusCode::OK);
    let used = h.events("admin.break_glass_used").await;
    assert_eq!(used.len(), 1);
    assert_eq!(used[0].metadata["priority"], "high");
    // Actions of a break-glass admin are flagged too.
    let target = h.user("target@example.com").await;
    let res = h
        .send(
            &principal,
            TestRequest::post(&format!("/v1/admin/users/{target}/revoke-sessions"))
                .json(&json!({ "reason": "incident 42" })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let action = h.admin_events("revoke_user_sessions").await;
    assert_eq!(action[0].metadata["break_glass"], true);
    assert_eq!(action[0].metadata["priority"], "high");
    assert_eq!(h.events("admin.break_glass_used").await.len(), 2);
}
