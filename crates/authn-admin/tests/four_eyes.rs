#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-66: four-eyes approval of critical admin operations (emergency
//! operations, actions on another platform admin) — request, approval by a
//! different admin who passes the full ADM-01 guard, single-use execution
//! bound to the exact parameters, expiry, denial, the break-glass and
//! single-admin exceptions, and the audit trail of every step.

mod common;

use std::time::Duration;

use authn_core::domain::{AccountStatus, AuthMethodRef, Principal};
use authn_core::id::UserId;
use authn_core::ports::RateLimitPolicy;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};

/// Four-eyes on, emergency budgets out of the way (K-08 is tested
/// elsewhere): cool-down of one second.
async fn harness(pool: sqlx::PgPool) -> Harness {
    Harness::with(pool, |s| {
        s.four_eyes = true;
        s.emergency_per_admin = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.emergency_global = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.emergency_cooldown = Duration::from_secs(1);
        s.admin_target_per_admin = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.admin_target_global = RateLimitPolicy::new(1000, Duration::from_secs(3600));
    })
    .await
}

/// Two more seconds (past the cool-down) and fresh step-ups.
fn later(h: &Harness, admins: &mut [(&UserId, &mut Principal)]) {
    h.advance(Duration::from_secs(2));
    for (id, principal) in admins.iter_mut() {
        **principal = h.principal(**id, true);
    }
}

async fn request(h: &Harness, admin: &Principal, body: Value) -> Value {
    let res = h
        .send(admin, TestRequest::post("/v1/admin/approvals").json(&body))
        .await;
    res.assert_status(StatusCode::OK);
    res.json()
}

async fn decide(
    h: &Harness,
    admin: &Principal,
    id: &str,
    verb: &str,
) -> authn_testkit::http::TestResponse {
    h.send(
        admin,
        TestRequest::post(&format!("/v1/admin/approvals/{id}/{verb}"))
            .json(&json!({ "reason": "Checked with the requester by phone" })),
    )
    .await
}

async fn revoke_all(
    h: &Harness,
    admin: &Principal,
    extra: Value,
) -> authn_testkit::http::TestResponse {
    let mut body = json!({ "reason": "INC-42 token theft", "confirm": "revoke_all_sessions" });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    h.send(
        admin,
        TestRequest::post("/v1/admin/emergency/revoke-all-sessions").json(&body),
    )
    .await
}

fn refusals(events: &[common::StoredEvent], reason: &str) -> usize {
    events
        .iter()
        .filter(|e| e.outcome == "failure" && e.reason.as_deref() == Some(reason))
        .count()
}

/// K-66 (ADM-06): an emergency operation needs a second admin's approval;
/// with it the operation runs exactly once; every step is audited with
/// high priority.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_emergency_needs_an_approval_and_uses_it_once(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (a_id, mut a) = h.admin("requester@example.com").await;
    let (b_id, mut b) = h.admin("approver@example.com").await;

    revoke_all(&h, &a, json!({}))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    assert_eq!(
        refusals(
            &h.admin_events("revoke_all_sessions").await,
            "four_eyes_approval_required"
        ),
        1
    );
    assert!(
        h.events("admin.emergency_action").await.is_empty(),
        "nothing ran"
    );

    let pending = request(
        &h,
        &a,
        json!({ "action": "revoke_all_sessions", "reason": "INC-42 token theft" }),
    )
    .await;
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["requested_by"], a_id.to_string());
    assert_eq!(pending["params"], json!({ "include_own_session": false }));
    assert_eq!(pending["reason"], "INC-42 token theft");
    let id = pending["id"].as_str().unwrap().to_owned();
    // Pending is not approved.
    revoke_all(&h, &a, json!({ "approval_id": id }))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");

    let approved: Value = decide(&h, &b, &id, "approve").await.json();
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["decided_by"], b_id.to_string());
    later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
    revoke_all(&h, &a, json!({ "approval_id": id }))
        .await
        .assert_status(StatusCode::OK);
    let ran = h.events("admin.emergency_action").await;
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].metadata["four_eyes"], "approved");
    assert_eq!(ran[0].metadata["approval_id"], id);

    // Replay: single use.
    later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
    revoke_all(&h, &a, json!({ "approval_id": id }))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    assert_eq!(h.events("admin.emergency_action").await.len(), 1);
    let listed: Value = h
        .send(&a, TestRequest::get("/v1/admin/approvals"))
        .await
        .json();
    assert_eq!(listed[0]["status"], "used");

    // Audit trail: request, decision (with justifications), refusals.
    let requested = h.events("admin.approval_requested").await;
    assert_eq!(requested.len(), 1);
    assert_eq!(requested[0].metadata["priority"], "high");
    assert_eq!(
        h.justification(requested[0].id).await.as_deref(),
        Some("INC-42 token theft")
    );
    let decided = h.events("admin.approval_decided").await;
    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0].metadata["decision"], "approved");
    assert!(h.justification(decided[0].id).await.is_some());
    assert_eq!(
        refusals(
            &h.admin_events("revoke_all_sessions").await,
            "four_eyes_approval_invalid"
        ),
        2
    );
}

/// K-66: nobody approves their own request; the target of an operation
/// cannot decide on it; another admin cannot use someone else's approval.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_k66_self_approval_target_approval_and_foreign_use_are_refused(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (_, a) = h.admin("requester@example.com").await;
    let (_, b) = h.admin("approver@example.com").await;
    let (target_id, target) = h.admin("target-admin@example.com").await;
    let pending = request(
        &h,
        &a,
        json!({ "action": "suspend_user", "target_user_id": target_id, "reason": "Compromised admin" }),
    )
    .await;
    let id = pending["id"].as_str().unwrap();
    decide(&h, &a, id, "approve")
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_self_approval_not_allowed");
    decide(&h, &target, id, "deny")
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
    assert_eq!(
        refusals(
            &h.admin_events("approval_decided").await,
            "four_eyes_self_approval"
        ),
        1
    );
    decide(&h, &b, id, "approve")
        .await
        .assert_status(StatusCode::OK);
    // B approved; B cannot use it (it is A's request).
    h.send(
        &b,
        TestRequest::post(&format!("/v1/admin/users/{target_id}/suspend"))
            .json(&json!({ "reason": "Compromised admin", "approval_id": id })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    assert_eq!(h.record(target_id).await.status, AccountStatus::Active);
    // A can.
    let res = h
        .send(
            &a,
            TestRequest::post(&format!("/v1/admin/users/{target_id}/suspend"))
                .json(&json!({ "reason": "Compromised admin", "approval_id": id })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(h.record(target_id).await.status, AccountStatus::Suspended);
    let event = h
        .admin_events("suspend_user")
        .await
        .into_iter()
        .find(|e| e.outcome == "success")
        .unwrap();
    assert_eq!(event.metadata["four_eyes"], "approved");
    assert_eq!(event.metadata["target_is_admin"], true);
}

/// K-66: the approval is bound to the exact operation, target and
/// parameters (hash); any change is refused — an equivalent spelling of
/// the same instant is the same parameter.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_parameter_tampering_is_refused(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (a_id, mut a) = h.admin("requester@example.com").await;
    let (b_id, mut b) = h.admin("approver@example.com").await;
    let (c_id, _) = h.admin("admin-c@example.com").await;
    let (d_id, _) = h.admin("admin-d@example.com").await;

    // revoke-all approved without the own session; used with it.
    let id = request(
        &h,
        &a,
        json!({ "action": "revoke_all_sessions", "reason": "INC-1" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    revoke_all(
        &h,
        &a,
        json!({ "approval_id": id, "include_own_session": true }),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    // Not consumed by the refused attempt: the approved form still works.
    revoke_all(&h, &a, json!({ "approval_id": id }))
        .await
        .assert_status(StatusCode::OK);

    // suspend approved for C, used on D; used for another action on C.
    later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
    let id = request(
        &h,
        &a,
        json!({ "action": "suspend_user", "target_user_id": c_id, "reason": "Containment" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    h.send(
        &a,
        TestRequest::post(&format!("/v1/admin/users/{d_id}/suspend"))
            .json(&json!({ "reason": "Containment", "approval_id": id })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    h.send(
        &a,
        TestRequest::post(&format!("/v1/admin/users/{c_id}/revoke-sessions"))
            .json(&json!({ "reason": "Containment", "approval_id": id })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    assert_eq!(h.record(d_id).await.status, AccountStatus::Active);
    // An emergency endpoint does not accept it either.
    revoke_all(&h, &a, json!({ "approval_id": id }))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");

    // Bulk password change: the instant is part of the approval.
    later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
    let id = request(
        &h,
        &a,
        json!({ "action": "force_password_change_before", "changed_before": "2025-06-01T00:00:00Z",
                "reason": "Credential stuffing wave" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    let run = |before: &str, revoke: bool| {
        TestRequest::post("/v1/admin/emergency/force-password-change").json(&json!({
            "reason": "Credential stuffing wave", "confirm": "force_password_change",
            "changed_before": before, "revoke_sessions": revoke, "approval_id": id,
        }))
    };
    h.send(&a, run("2025-07-01T00:00:00Z", true))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    h.send(&a, run("2025-06-01T00:00:00Z", false))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    h.send(&a, run("2025-06-01T03:00:00+03:00", true))
        .await
        .assert_status(StatusCode::OK);

    // Strict request validation: parameters of another operation.
    for body in [
        json!({ "action": "rotate_signing_key", "include_own_session": true, "reason": "x" }),
        json!({ "action": "suspend_user", "reason": "x" }),
        json!({ "action": "revoke_all_sessions", "target_user_id": c_id, "reason": "x" }),
        json!({ "action": "impersonate", "reason": "x" }),
        json!({ "action": "force_password_change_before", "reason": "x" }),
    ] {
        h.send(&a, TestRequest::post("/v1/admin/approvals").json(&body))
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
    // Non-critical actions refuse an approval id.
    let user = h.user("someone@example.com").await;
    h.send(
        &a,
        TestRequest::post(&format!("/v1/admin/users/{user}/reset-mfa"))
            .json(&json!({ "reason": "x", "approval_id": id })),
    )
    .await
    .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

/// K-66: requests expire (default 30 minutes); a denial is final; an
/// approver who lost the admin role no longer counts.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_expiry_denial_and_demoted_approver(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (a_id, mut a) = h.admin("requester@example.com").await;
    let (b_id, mut b) = h.admin("approver@example.com").await;
    let (_, _c) = h.admin("third@example.com").await;
    let rotate = |id: &str| {
        TestRequest::post("/v1/admin/emergency/rotate-signing-key").json(&json!({
            "reason": "Key leak", "confirm": "rotate_signing_key", "approval_id": id,
        }))
    };
    let body = json!({ "action": "rotate_signing_key", "reason": "Key leak" });

    // Approved, then expired before use.
    let id = request(&h, &a, body.clone()).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    h.advance(Duration::from_secs(30 * 60 + 1));
    later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
    h.send(&a, rotate(&id))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    // Expired before a decision: cannot be decided any more.
    let id = request(&h, &a, body.clone()).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    h.advance(Duration::from_secs(30 * 60 + 1));
    later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
    decide(&h, &b, &id, "approve")
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");

    // Denied: final.
    let id = request(&h, &a, body.clone()).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let denied: Value = decide(&h, &b, &id, "deny").await.json();
    assert_eq!(denied["status"], "denied");
    decide(&h, &b, &id, "approve")
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    h.send(&a, rotate(&id))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    let denials: Vec<_> = h
        .events("admin.approval_decided")
        .await
        .into_iter()
        .filter(|e| e.metadata["decision"] == "denied")
        .collect();
    assert_eq!(denials.len(), 1);

    // Approver demoted before the use.
    let id = request(&h, &a, body).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    sqlx::query("UPDATE users SET is_platform_admin = false WHERE id = $1")
        .bind(b_id)
        .execute(&h.pool)
        .await
        .unwrap();
    h.send(&a, rotate(&id))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    assert_eq!(*h.keys.0.lock().unwrap(), 0, "the key was never rotated");
}

/// K-66: the approver passes the same ADM-01 guard as any admin request:
/// a passkey (phishing-resistant MFA) session and a fresh step-up.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_k66_approver_passes_the_full_admin_guard(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (_, a) = h.admin("requester@example.com").await;
    let (b_id, b) = h.admin("approver@example.com").await;
    let id = request(
        &h,
        &a,
        json!({ "action": "rotate_signing_key", "reason": "Key leak" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut password_session = b.clone();
    password_session.amr = vec![AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa];
    decide(&h, &password_session, &id, "approve")
        .await
        .assert_error(
            StatusCode::FORBIDDEN,
            "admin_phishing_resistant_mfa_required",
        );
    let mut stale = h.principal(b_id, true);
    stale.auth_time = Some(h.now() - Duration::from_secs(3600));
    decide(&h, &stale, &id, "approve")
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    let regular = h.user("not-admin@example.com").await;
    decide(&h, &h.principal(regular, false), &id, "approve")
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    let listed: Value = h
        .send(&a, TestRequest::get("/v1/admin/approvals"))
        .await
        .json();
    assert_eq!(listed[0]["status"], "pending", "nothing was decided");
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
}

/// K-66 exceptions: a break-glass account and a lone admin run critical
/// operations without approval — each recorded as a high-priority
/// `admin.four_eyes_bypassed` event. Actions on regular users never need
/// an approval.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k66_break_glass_and_single_admin_exceptions_are_audited(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    // A lone admin (no one could approve).
    let (_, lone) = h.admin("lone@example.com").await;
    revoke_all(&h, &lone, json!({}))
        .await
        .assert_status(StatusCode::OK);
    let bypassed = h.events("admin.four_eyes_bypassed").await;
    assert_eq!(bypassed.len(), 1);
    assert_eq!(bypassed[0].metadata["exception"], "no_second_admin");
    assert_eq!(bypassed[0].metadata["priority"], "high");
    let ran = h.events("admin.emergency_action").await;
    assert_eq!(ran[0].metadata["four_eyes"], "bypassed");
    assert_eq!(ran[0].metadata["four_eyes_exception"], "no_second_admin");

    // A second admin exists: the lone admin now needs an approval …
    let (second_id, _) = h.admin("second@example.com").await;
    h.advance(Duration::from_secs(2));
    let lone_id = authn_store::UserRepository::find_by_email(
        &h.pool,
        &authn_core::domain::EmailAddress::parse("lone@example.com").unwrap(),
    )
    .await
    .unwrap()
    .unwrap()
    .id;
    let lone = h.principal(lone_id, true);
    revoke_all(&h, &lone, json!({}))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    // … also for an action on that admin: the target cannot approve, but
    // it is an active admin, so this is no single-admin case (audit
    // finding: otherwise one admin of two removes the other alone).
    h.send(
        &lone,
        TestRequest::post(&format!("/v1/admin/users/{second_id}/revoke-sessions"))
            .json(&json!({ "reason": "Containment" })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    let exceptions: Vec<_> = h
        .events("admin.four_eyes_bypassed")
        .await
        .into_iter()
        .map(|e| e.metadata["exception"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(exceptions, vec!["no_second_admin"]);

    // Break-glass: never blocked, always recorded.
    let glass = h.user("glass@example.com").await;
    h.make_admin(glass, true).await;
    let glass_principal = h.principal(glass, true);
    revoke_all(&h, &glass_principal, json!({}))
        .await
        .assert_status(StatusCode::OK);
    let last = h.events("admin.four_eyes_bypassed").await.pop().unwrap();
    assert_eq!(last.metadata["exception"], "break_glass");

    // Regular users: no four-eyes at all.
    let user = h.user("customer@example.com").await;
    h.send(
        &lone,
        TestRequest::post(&format!("/v1/admin/users/{user}/suspend"))
            .json(&json!({ "reason": "Fraud" })),
    )
    .await
    .assert_status(StatusCode::OK);
    assert_eq!(h.events("admin.four_eyes_bypassed").await.len(), 2);
}

/// K-66: the approval table guards itself (defence in depth): the request
/// is immutable, a decision is final and an approval is consumed once,
/// whatever SQL runs.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_approval_rows_cannot_be_rewritten(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (_, a) = h.admin("requester@example.com").await;
    let (_, b) = h.admin("approver@example.com").await;
    let id = request(
        &h,
        &a,
        json!({ "action": "rotate_signing_key", "reason": "Key leak" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    let id: uuid::Uuid = id.parse().unwrap();
    for sql in [
        "UPDATE admin_approvals SET params_hash = sha256('x') WHERE id = $1",
        "UPDATE admin_approvals SET expires_at = expires_at + interval '1 day' WHERE id = $1",
        "UPDATE admin_approvals SET requested_by = decided_by WHERE id = $1",
        "UPDATE admin_approvals SET decision = 'denied' WHERE id = $1",
        "DELETE FROM admin_approvals WHERE id = $1",
    ] {
        let mut tx = h.pool.begin().await.unwrap();
        assert!(
            sqlx::query(sql).bind(id).execute(&mut *tx).await.is_err(),
            "{sql}"
        );
        tx.rollback().await.unwrap();
    }
    sqlx::query("UPDATE admin_approvals SET consumed_at = now() WHERE id = $1")
        .bind(id)
        .execute(&h.pool)
        .await
        .unwrap();
    let mut tx = h.pool.begin().await.unwrap();
    assert!(
        sqlx::query("UPDATE admin_approvals SET consumed_at = NULL WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .is_err(),
        "an approval is used once"
    );
    tx.rollback().await.unwrap();
}

/// K-66: with `admin.four_eyes` off (development / test default) nothing
/// changes.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_switched_off_needs_no_approval(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    assert!(!h.service.settings().four_eyes);
    let (_, a) = h.admin("requester@example.com").await;
    let (_, _b) = h.admin("approver@example.com").await;
    revoke_all(&h, &a, json!({}))
        .await
        .assert_status(StatusCode::OK);
    assert!(h.events("admin.four_eyes_bypassed").await.is_empty());
}

/// K-66 with K-08: unapproved or forged attempts are refused before any
/// rate-limit budget is spent — a compromised admin cannot burn the shared
/// emergency cool-down and block the approved incident response.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_unapproved_attempts_do_not_burn_the_emergency_cooldown(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| s.four_eyes = true).await; // default 5-minute cool-down
    let (_, attacker) = h.admin("compromised@example.com").await;
    let (_, responder) = h.admin("responder@example.com").await;
    let (_, approver) = h.admin("approver@example.com").await;
    for extra in [json!({}), json!({ "approval_id": uuid::Uuid::now_v7() })] {
        let res = revoke_all(&h, &attacker, extra).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    }
    let id = request(
        &h,
        &responder,
        json!({ "action": "revoke_all_sessions", "reason": "INC-7" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &approver, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    revoke_all(&h, &responder, json!({ "approval_id": id }))
        .await
        .assert_status(StatusCode::OK);
}

/// K-66: two concurrent uses of one approval — exactly one runs (the
/// consumption is one conditional UPDATE in the operation's transaction).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_k66_concurrent_uses_of_one_approval_run_once(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (_, a) = h.admin("requester@example.com").await;
    let (_, b) = h.admin("approver@example.com").await;
    let (target, _) = h.admin("locked-admin@example.com").await;
    let id = request(
        &h,
        &a,
        json!({ "action": "revoke_user_sessions", "target_user_id": target, "reason": "Containment" }),
    )
    .await["id"]
    .as_str()
    .unwrap()
    .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    let caller = h.caller(&a).await;
    let approval: uuid::Uuid = id.parse().unwrap();
    let reason = authn_admin::Justification::parse(Some("Containment")).unwrap();
    let ctx = h.ctx();
    let (one, two) = tokio::join!(
        h.service
            .revoke_user_sessions_approved(&caller, &ctx, target, &reason, Some(approval)),
        h.service
            .revoke_user_sessions_approved(&caller, &ctx, target, &reason, Some(approval)),
    );
    let ok = [&one, &two].iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, 1, "{one:?} {two:?}");
    let err = one.err().or(two.err()).unwrap();
    assert_eq!(err.code().code(), "admin_approval_invalid");
}

/// K-66 audit finding: with two platform admins, one compromised admin
/// must not remove the other through the "no other admin could approve"
/// exception (the target cannot approve, so it used to count as "no second
/// admin") and then run every emergency operation alone. The target is an
/// active admin: the action needs an approval nobody but a third admin can
/// give — the recovery path is the break-glass account (or the CLI).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_k66_two_admins_cannot_remove_each_other_alone(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (_, attacker) = h.admin("compromised@example.com").await;
    let (peer, _) = h.admin("peer@example.com").await;
    for verb in ["suspend", "revoke-sessions", "unlock"] {
        h.send(
            &attacker,
            TestRequest::post(&format!("/v1/admin/users/{peer}/{verb}"))
                .json(&json!({ "reason": "Containment" })),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    }
    assert_eq!(h.record(peer).await.status, AccountStatus::Active);
    revoke_all(&h, &attacker, json!({}))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    assert!(h.events("admin.four_eyes_bypassed").await.is_empty());

    // The break-glass account is the recovery path (never blocked).
    let glass = h.user("glass@example.com").await;
    h.make_admin(glass, true).await;
    h.send(
        &h.principal(glass, true),
        TestRequest::post(&format!("/v1/admin/users/{peer}/suspend"))
            .json(&json!({ "reason": "Containment" })),
    )
    .await
    .assert_status(StatusCode::OK);
    // Once the peer is no longer an active admin, the remaining admin is
    // alone: the single-admin exception applies (audited).
    revoke_all(&h, &attacker, json!({}))
        .await
        .assert_status(StatusCode::OK);
    let bypassed = h.events("admin.four_eyes_bypassed").await;
    assert_eq!(
        bypassed.last().unwrap().metadata["exception"],
        "no_second_admin"
    );
}

/// K-66 audit finding: the search for an admin who could approve must
/// look at every admin — not only the few newest (break-glass accounts,
/// the caller and the target could fill a short page and hide an eligible
/// approver, turning the operation into an unapproved bypass).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_an_older_approver_is_found_among_many_admins(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (_, _approver) = h.admin("approver@example.com").await;
    h.advance(Duration::from_secs(1));
    let (caller_id, _) = h.admin("caller@example.com").await;
    for i in 0..4 {
        h.advance(Duration::from_secs(1));
        let glass = h.user(&format!("glass{i}@example.com")).await;
        h.make_admin(glass, true).await;
    }
    let caller = h.principal(caller_id, true);
    revoke_all(&h, &caller, json!({}))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    assert!(h.events("admin.four_eyes_bypassed").await.is_empty());
    assert!(h.events("admin.emergency_action").await.is_empty());
}

/// K-66 audit finding (approval fatigue): one admin cannot flood the
/// other admins with approval prompts — at most 3 pending requests at a
/// time and 10 per hour per requester (denied requests count too), each
/// refusal `429 rate_limited` and audited with high priority.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k66_approval_requests_are_capped_per_requester(pool: sqlx::PgPool) {
    let h = harness(pool).await;
    let (a_id, mut a) = h.admin("requester@example.com").await;
    let (b_id, mut b) = h.admin("approver@example.com").await;
    let body = json!({ "action": "rotate_signing_key", "reason": "INC-9 key leak" });
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(
            request(&h, &a, body.clone()).await["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let res = h
        .send(&a, TestRequest::post("/v1/admin/approvals").json(&body))
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert_eq!(
        refusals(
            &h.admin_events("approval_requested").await,
            "approvals_pending_per_admin"
        ),
        1
    );
    // Another admin is not affected.
    request(&h, &b, body.clone()).await;
    // Denials free pending slots, but not the hourly budget: deny and
    // re-request until 10 requests were made in the hour.
    let mut made = 3;
    while made < 10 {
        later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
        let id = ids.pop().unwrap();
        decide(&h, &b, &id, "deny")
            .await
            .assert_status(StatusCode::OK);
        ids.push(
            request(&h, &a, body.clone()).await["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        made += 1;
        ids.rotate_left(1);
    }
    later(&h, &mut [(&a_id, &mut a), (&b_id, &mut b)]);
    let id = ids.pop().unwrap();
    decide(&h, &b, &id, "deny")
        .await
        .assert_status(StatusCode::OK);
    h.send(&a, TestRequest::post("/v1/admin/approvals").json(&body))
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert_eq!(
        refusals(
            &h.admin_events("approval_requested").await,
            "approvals_per_hour_per_admin"
        ),
        1
    );
    // An hour later the budget is back.
    h.advance(Duration::from_secs(3600));
    let a = h.principal(a_id, true);
    request(&h, &a, body).await;
}

/// K-66 audit finding (containment tip-off): the target admin of a pending
/// request must not learn of it from its own security-event list or its
/// data export (request / decision events and their justifications) —
/// a compromised admin would get up to the approval's lifetime of warning.
/// Once the approval has expired, both are visible like any other entry.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_k66_target_is_not_tipped_off_by_a_pending_request(pool: sqlx::PgPool) {
    use authn_core::ports::DataExporter;
    let h = harness(pool).await;
    let (_, a) = h.admin("requester@example.com").await;
    let (_, b) = h.admin("approver@example.com").await;
    let (target, _) = h.admin("suspect@example.com").await;
    let view = |h: &Harness| {
        let pool = h.pool.clone();
        let now = h.now();
        async move {
            authn_audit::query::list_user_security_events(
                &pool,
                target,
                now,
                Duration::from_secs(365 * 86_400),
                &authn_core::domain::PageRequest {
                    limit: Some(100),
                    cursor: None,
                },
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|e| e.kind)
            .collect::<Vec<_>>()
        }
    };
    let export = |h: &Harness| {
        let pool = h.pool.clone();
        let clock = h.ports.clock.clone();
        async move {
            let mut conn = pool.acquire().await.unwrap();
            authn_admin::AdminActionsDataExporter::new(clock)
                .export(&mut conn, target)
                .await
                .unwrap()
                .to_string()
        }
    };
    let id = request(
        &h,
        &a,
        json!({ "action": "suspend_user", "target_user_id": target, "reason": "Suspected insider INC-77" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&h, &b, &id, "approve")
        .await
        .assert_status(StatusCode::OK);
    let seen = view(&h).await;
    assert!(
        !seen.iter().any(|k| k.starts_with("admin.approval")),
        "{seen:?}"
    );
    let exported = export(&h).await;
    assert!(!exported.contains("INC-77"), "{exported}");
    assert!(
        !exported.contains("Checked with the requester"),
        "{exported}"
    );

    // After the approval's lifetime: visible again (transparency).
    h.advance(Duration::from_secs(31 * 60));
    let seen = view(&h).await;
    assert!(
        seen.iter().any(|k| k == "admin.approval_requested"),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|k| k == "admin.approval_decided"),
        "{seen:?}"
    );
    let exported = export(&h).await;
    assert!(exported.contains("INC-77"), "{exported}");
}
