#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ADM-04: impersonation constraints and delegation to `SessionIssuer`.

mod common;

use std::time::Duration;

use authn_core::domain::{AccountStatus, ClientKind};
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_defaults_read_only_fifteen_minutes_with_admin_session(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (admin_id, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let res = h
        .send(
            &admin,
            TestRequest::post(&format!("/v1/admin/users/{user}/impersonate"))
                .json(&json!({ "reason": "Reproduce billing page bug (SUP-9)" })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: Value = res.json();
    assert_eq!(body["user_id"], user.to_string());
    assert_eq!(body["client"], "web");

    let requests = h.issuer.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    let (request, client, admin_session) = &requests[0];
    assert!(request.read_only, "read-only is the default");
    assert_eq!(request.ttl, Duration::from_secs(15 * 60));
    assert_eq!(request.admin_user_id, admin_id);
    assert_eq!(request.target_user_id, user);
    assert_eq!(request.reason, "Reproduce billing page bug (SUP-9)");
    assert_eq!(*client, ClientKind::Web);
    // The admin's own session is passed so its amr/acr are inherited.
    assert_eq!(*admin_session, admin.session_id());

    // No duplicate notification or audit event: exactly the issuer's one,
    // with the justification attached outside the chain.
    assert!(h.ports.notifier.recorded().is_empty());
    let started = h.events("admin.impersonation_started").await;
    assert_eq!(started.len(), 1);
    assert_eq!(
        h.justification(started[0].id).await.as_deref(),
        Some("Reproduce billing page bug (SUP-9)")
    );
    assert!(h.admin_events("impersonation_started").await.is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_duration_bounds_and_options(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let uri = format!("/v1/admin/users/{user}/impersonate");
    for ttl in [0, 61, 600, u32::MAX] {
        let res = h
            .send(
                &admin,
                TestRequest::post(&uri).json(&json!({ "reason": "x", "ttl_minutes": ttl })),
            )
            .await;
        res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
    assert!(h.issuer.requests.lock().unwrap().is_empty());
    let res = h
        .send(
            &admin,
            TestRequest::post(&uri).json(&json!({
                "reason": "Support session",
                "ttl_minutes": 60,
                "read_only": false,
                "client": "native",
            })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["client"], "native");
    assert_eq!(body["has_access_token"], true);
    let requests = h.issuer.requests.lock().unwrap().clone();
    assert_eq!(requests[0].0.ttl, Duration::from_secs(3600));
    assert!(!requests[0].0.read_only);
    assert_eq!(requests[0].1, ClientKind::Native);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_configured_maximum_is_enforced(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.impersonation_max_ttl = Duration::from_secs(30 * 60);
    })
    .await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let res = h
        .send(
            &admin,
            TestRequest::post(&format!("/v1/admin/users/{user}/impersonate"))
                .json(&json!({ "reason": "x", "ttl_minutes": 31 })),
        )
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_not_applicable_to_admins_break_glass_self_or_inactive(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (me, admin) = h.admin("admin@example.com").await;
    let (other, _) = h.admin("other@example.com").await;
    let glass = h.user("glass@example.com").await;
    h.make_admin(glass, true).await;
    for target in [me, other, glass] {
        let res = h
            .send(
                &admin,
                TestRequest::post(&format!("/v1/admin/users/{target}/impersonate"))
                    .json(&json!({ "reason": "x" })),
            )
            .await;
        res.assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
    }
    for status in [
        AccountStatus::Suspended,
        AccountStatus::PendingVerification,
        AccountStatus::Disabled,
    ] {
        let target = h
            .user_with_status(&format!("{}@example.com", status.as_str()), status)
            .await;
        let res = h
            .send(
                &admin,
                TestRequest::post(&format!("/v1/admin/users/{target}/impersonate"))
                    .json(&json!({ "reason": "x" })),
            )
            .await;
        res.assert_error(StatusCode::FORBIDDEN, "impersonation_not_allowed");
    }
    assert!(h.issuer.requests.lock().unwrap().is_empty());
    assert!(h.events("admin.impersonation_started").await.is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_impersonation_session_cannot_start_another(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    // The principal of a (writable) impersonation session of alice.
    let mut as_alice = h.principal(alice, false);
    as_alice = h.impersonated(as_alice, false);
    if let Some(imp) = as_alice.impersonation.as_mut() {
        imp.admin_user_id = admin.user_id().unwrap();
    }
    let res = h
        .send(
            &as_alice,
            TestRequest::post(&format!("/v1/admin/users/{bob}/impersonate"))
                .json(&json!({ "reason": "chain" })),
        )
        .await;
    res.assert_error(StatusCode::FORBIDDEN, "forbidden");
    assert!(h.issuer.requests.lock().unwrap().is_empty());
}
