#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-93 (ADM-09, ADM-10): staff roles. Every admin route declares a
//! permission (no default allow), the role × route matrix, permissions read
//! from the database on every request, four-eyes authority limited to
//! `security` and `platform_admin`, role changes (API and CLI) and the
//! privilege-escalation attempts a lower role could try.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use authn_admin::{OfflineOperator, OfflineTarget, ROUTE_PERMISSIONS, StaffRole};
use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::id::UserId;
use authn_core::ports::{RateLimitPolicy, RevocationReason, RevokeOptions};
use authn_store::{NewUser, UserRepository};
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::{TestRequest, TestResponse};
use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};
use utoipa::OpenApi;

/// Four-eyes switched as asked, blast-radius budgets out of the way.
async fn harness(pool: sqlx::PgPool, four_eyes: bool) -> Harness {
    Harness::with(pool, |s| {
        s.four_eyes = four_eyes;
        s.emergency_per_admin = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.emergency_global = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.emergency_cooldown = Duration::from_secs(1);
        s.admin_target_per_admin = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.admin_target_global = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.audit_verify_per_admin = RateLimitPolicy::new(1000, Duration::from_secs(3600));
    })
    .await
}

fn path_of(template: &str) -> String {
    let id = UserId::generate().to_string();
    template
        .replace("{user_id}", &id)
        .replace("{approval_id}", &uuid::Uuid::now_v7().to_string())
        .replace("{event_id}", &uuid::Uuid::now_v7().to_string())
}

fn request(method: &str, path: &str) -> TestRequest {
    match method {
        "GET" => TestRequest::get(path),
        "POST" => TestRequest::post(path).json(&json!({})),
        other => panic!("unexpected method {other}"),
    }
}

fn openapi_operations() -> BTreeSet<(String, String)> {
    let doc = serde_json::to_value(authn_admin::AdminApi::openapi()).unwrap();
    let mut out = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            if ["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
                out.insert((method.to_uppercase(), path.clone()));
            }
        }
    }
    out
}

/// ADM-09 (K-93): every operation of the admin API (the OpenAPI document
/// lists every handler of `router`) declares exactly one permission, and
/// the table has no stale entry. The route probe below shows that a route
/// served by the router but missing from the table is refused for
/// everyone — even a `platform_admin` — so a forgotten declaration fails
/// closed.
#[test]
fn adm_09_every_admin_route_declares_a_permission() {
    let declared: BTreeSet<(String, String)> = ROUTE_PERMISSIONS
        .iter()
        .map(|(m, p, _)| ((*m).to_owned(), (*p).to_owned()))
        .collect();
    assert_eq!(
        declared.len(),
        ROUTE_PERMISSIONS.len(),
        "a route is declared twice"
    );
    assert_eq!(openapi_operations(), declared);
}

/// ADM-09: a route without a declared permission is refused for every
/// role (the extractor has no default allow).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_an_undeclared_admin_route_is_refused_for_everyone(pool: sqlx::PgPool) {
    let h = harness(pool, false).await;
    let (_, admin) = h.admin("root@example.com").await;
    async fn undeclared(_caller: authn_admin::AdminCaller) -> &'static str {
        "reached"
    }
    let app = authn_testkit::http::with_request_context(
        authn_admin::router::<authn_admin::AdminService>()
            .route("/v1/admin/undeclared", axum::routing::get(undeclared))
            .with_state(h.service.clone())
            .layer(axum::Extension(admin.clone())),
    );
    TestRequest::get("/v1/admin/undeclared")
        .peer_ip(common::ADMIN_IP.parse().unwrap())
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    // The declared routes of the same router still work.
    TestRequest::get("/v1/admin/users")
        .peer_ip(common::ADMIN_IP.parse().unwrap())
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
}

fn is_permission_denial(res: &TestResponse) -> bool {
    res.status == StatusCode::FORBIDDEN
        && res.json::<Value>()["error"]["code"] == "admin_permission_denied"
}

/// ADM-09: the full role × route matrix over HTTP. A role without the
/// route's permission gets `403 admin_permission_denied` (naming the
/// permission) before the body is even read; a role with it never does
/// (it reaches validation, `404`, … with the probe's empty body).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_role_route_matrix(pool: sqlx::PgPool) {
    let h = harness(pool, false).await;
    for role in StaffRole::ALL {
        let (_, principal) = h
            .staff(&format!("{}@example.com", role.as_str()), role)
            .await;
        for (method, template, permission) in ROUTE_PERMISSIONS {
            let res = h
                .send(&principal, request(method, &path_of(template)))
                .await;
            let denied = is_permission_denial(&res);
            assert_eq!(
                denied,
                !role.grants(*permission),
                "{role} {method} {template} ({permission}) answered {}",
                res.status
            );
            if denied {
                assert_eq!(
                    res.json::<Value>()["error"]["details"]["permission"],
                    permission.as_str()
                );
            } else {
                assert_ne!(
                    res.status,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "{role} {method} {template}"
                );
            }
        }
    }
    // Refusals are audited with the role and the permission.
    let refusals = h.admin_events("admin_access").await;
    assert!(
        refusals
            .iter()
            .any(|e| e.reason.as_deref() == Some("permission_denied")
                && e.metadata["role"] == "support_readonly"
                && e.metadata["permission"] == "users:suspend")
    );
}

/// ADM-09: representative actions with real effects per role.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_representative_actions_per_role(pool: sqlx::PgPool) {
    let h = harness(pool, false).await;
    let (_, readonly) = h.staff("ro@example.com", StaffRole::SupportReadonly).await;
    let (_, support) = h.staff("support@example.com", StaffRole::Support).await;
    let (_, security) = h.staff("security@example.com", StaffRole::Security).await;
    let user = h.user("user@example.com").await;
    let reason = json!({ "reason": "Ticket SUP-1" });

    // Everyone reads.
    for p in [&readonly, &support, &security] {
        h.send(p, TestRequest::get(&format!("/v1/admin/users/{user}")))
            .await
            .assert_status(StatusCode::OK);
    }
    // Support recovers, security does not.
    let mfa = format!("/v1/admin/users/{user}/reset-mfa");
    h.send(&security, TestRequest::post(&mfa).json(&reason))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
    h.send(&support, TestRequest::post(&mfa).json(&reason))
        .await
        .assert_status(StatusCode::OK);
    // Security suspends, support does not; support_readonly changes nothing.
    let suspend = format!("/v1/admin/users/{user}/suspend");
    for p in [&readonly, &support] {
        h.send(p, TestRequest::post(&suspend).json(&reason))
            .await
            .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
    }
    assert_eq!(h.record(user).await.status, AccountStatus::Active);
    h.send(&security, TestRequest::post(&suspend).json(&reason))
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(h.record(user).await.status, AccountStatus::Suspended);
    // Audit: security yes, support no.
    h.send(&security, TestRequest::get("/v1/admin/audit-events"))
        .await
        .assert_status(StatusCode::OK);
    h.send(&support, TestRequest::get("/v1/admin/audit-events"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
}

/// ADM-04 / ADM-09: impersonation is for `support` and `platform_admin`
/// only — `security` investigates, it does not act as users.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_impersonation_is_limited_to_support_and_platform_admin(pool: sqlx::PgPool) {
    let h = harness(pool, false).await;
    let user = h.user("user@example.com").await;
    let uri = format!("/v1/admin/users/{user}/impersonate");
    let body = json!({ "reason": "Customer asked for help (SUP-7)" });
    for (role, allowed) in [
        (StaffRole::SupportReadonly, false),
        (StaffRole::Support, true),
        (StaffRole::Security, false),
        (StaffRole::PlatformAdmin, true),
    ] {
        let (_, p) = h
            .staff(&format!("imp-{}@example.com", role.as_str()), role)
            .await;
        let res = h.send(&p, TestRequest::post(&uri).json(&body)).await;
        if allowed {
            res.assert_status(StatusCode::OK);
        } else {
            res.assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
        }
    }
}

/// ADM-09 (K-93): permissions come from the database on every request,
/// never from the session: demoting a live session's staff member applies
/// to its very next request, and removing the role row (or the staff flag)
/// shuts the console at once.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_role_removal_mid_session_applies_to_the_next_request(pool: sqlx::PgPool) {
    let h = harness(pool, false).await;
    let (id, session) = h.staff("sec@example.com", StaffRole::Security).await;
    h.send(&session, TestRequest::get("/v1/admin/audit-events"))
        .await
        .assert_status(StatusCode::OK);

    h.set_role(id, StaffRole::SupportReadonly).await;
    h.send(&session, TestRequest::get("/v1/admin/audit-events"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
    h.send(&session, TestRequest::get("/v1/admin/users"))
        .await
        .assert_status(StatusCode::OK);

    // No role row: no permission at all (fail closed), generic answer.
    sqlx::query("DELETE FROM admin_staff_roles WHERE user_id = $1")
        .bind(id)
        .execute(&h.pool)
        .await
        .unwrap();
    h.send(&session, TestRequest::get("/v1/admin/users"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
}

/// ADM-09: a support member cannot raise itself: no role change (own or
/// anyone's), no approval request for one, no action on another staff
/// member (`staff:contain`), no four-eyes decision.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_support_cannot_escalate(pool: sqlx::PgPool) {
    let h = harness(pool, true).await;
    let (support_id, support) = h.staff("support@example.com", StaffRole::Support).await;
    let (admin_id, admin) = h.admin("root@example.com").await;
    let (_, _other_admin) = h.admin("root2@example.com").await;

    for role in ["platform_admin", "security"] {
        h.send(
            &support,
            TestRequest::post(&format!("/v1/admin/staff/{support_id}/role"))
                .json(&json!({ "role": role, "reason": "promote me" })),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
    }
    h.send(
        &support,
        TestRequest::post("/v1/admin/approvals").json(&json!({
            "action": "change_staff_role",
            "target_user_id": support_id,
            "role": "platform_admin",
            "reason": "promote me",
        })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
    // Unlock and revoke-sessions are support permissions on regular users,
    // but never on another staff member.
    for action in ["unlock", "revoke-sessions"] {
        h.send(
            &support,
            TestRequest::post(&format!("/v1/admin/users/{admin_id}/{action}"))
                .json(&json!({ "reason": "lock out the admin" })),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
    }
    assert!(
        !h.ports
            .session_revoker
            .calls()
            .iter()
            .any(|c| matches!(c, RevocationCall::AllForUser(u, ..) if *u == admin_id))
    );
    // A pending request of a platform admin cannot be decided by support.
    let pending: Value = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/approvals").json(&json!({
                "action": "rotate_signing_key",
                "reason": "INC-9 key leak",
            })),
        )
        .await
        .json();
    h.send(
        &support,
        TestRequest::post(&format!(
            "/v1/admin/approvals/{}/approve",
            pending["id"].as_str().unwrap()
        ))
        .json(&json!({ "reason": "sure" })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
    assert_eq!(
        h.staff_role(support_id).await,
        Some(StaffRole::Support),
        "nothing changed"
    );
}

/// ADM-10 (K-93): four-eyes authority belongs to `security` and
/// `platform_admin` only. A security member cannot approve its own request,
/// a second security member can; a security member cannot approve a staff
/// role change (it lacks `staff:manage`); an approver demoted after
/// approving no longer carries the approval.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_10_four_eyes_authority_and_self_approval(pool: sqlx::PgPool) {
    let h = harness(pool, true).await;
    let (_, sec1) = h.staff("sec1@example.com", StaffRole::Security).await;
    let (sec2_id, sec2) = h.staff("sec2@example.com", StaffRole::Security).await;
    let (_, admin) = h.admin("root@example.com").await;
    let (target_id, _) = h.staff("target@example.com", StaffRole::Support).await;

    let rotate = json!({ "reason": "INC-10 key leak", "confirm": "rotate_signing_key" });
    let pending: Value = h
        .send(
            &sec1,
            TestRequest::post("/v1/admin/approvals")
                .json(&json!({ "action": "rotate_signing_key", "reason": "INC-10 key leak" })),
        )
        .await
        .json();
    let id = pending["id"].as_str().unwrap().to_owned();
    h.send(
        &sec1,
        TestRequest::post(&format!("/v1/admin/approvals/{id}/approve"))
            .json(&json!({ "reason": "self" })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_self_approval_not_allowed");
    h.send(
        &sec2,
        TestRequest::post(&format!("/v1/admin/approvals/{id}/approve"))
            .json(&json!({ "reason": "Confirmed by phone" })),
    )
    .await
    .assert_status(StatusCode::OK);
    // The approver loses its four-eyes authority before the use.
    h.set_role(sec2_id, StaffRole::Support).await;
    let mut body = rotate.clone();
    body["approval_id"] = Value::from(id.clone());
    h.send(
        &sec1,
        TestRequest::post("/v1/admin/emergency/rotate-signing-key").json(&body),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    h.set_role(sec2_id, StaffRole::Security).await;

    // A lone platform admin cannot change a role alone while security
    // members exist (they count as a second admin but cannot approve a
    // role change): no `no_second_admin` bypass.
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/staff/{target_id}/role"))
            .json(&json!({ "role": "security", "reason": "Joins security (HR-12)" })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    assert!(h.events("admin.four_eyes_bypassed").await.is_empty());
    // A role change requested by a platform admin: security cannot approve.
    let change: Value = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/approvals").json(&json!({
                "action": "change_staff_role",
                "target_user_id": target_id,
                "role": "security",
                "reason": "Joins the security team (HR-12)",
            })),
        )
        .await
        .json();
    assert_eq!(change["params"], json!({ "role": "security" }));
    h.send(
        &sec2,
        TestRequest::post(&format!(
            "/v1/admin/approvals/{}/approve",
            change["id"].as_str().unwrap()
        ))
        .json(&json!({ "reason": "ok" })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");
}

/// ADM-10: the single-approver exception counts only staff who could
/// approve. With one platform admin and a support colleague, an emergency
/// operation runs under the audited `no_second_admin` exception; once a
/// security member exists, it needs that member's approval.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_10_only_approvers_count_as_a_second_admin(pool: sqlx::PgPool) {
    let h = harness(pool, true).await;
    let (_, admin) = h.admin("root@example.com").await;
    let (support_id, _) = h.staff("support@example.com", StaffRole::Support).await;
    let body = json!({ "reason": "INC-11 key leak", "confirm": "rotate_signing_key" });
    h.send(
        &admin,
        TestRequest::post("/v1/admin/emergency/rotate-signing-key").json(&body),
    )
    .await
    .assert_status(StatusCode::OK);
    let bypassed = h.events("admin.four_eyes_bypassed").await;
    assert_eq!(bypassed.len(), 1);
    assert_eq!(bypassed[0].metadata["exception"], "no_second_admin");

    h.set_role(support_id, StaffRole::Security).await;
    h.advance(Duration::from_secs(2));
    let admin = h.principal(h.record_by_email("root@example.com").await, true);
    h.send(
        &admin,
        TestRequest::post("/v1/admin/emergency/rotate-signing-key").json(&body),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
}

/// ADM-09 (K-93): the API role change — `platform_admin` only, another
/// non-break-glass staff member only, audited with both roles and the
/// justification, the target's sessions revoked; the same role is a
/// conflict; regular accounts are never made staff through the API.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_staff_role_change_through_the_api(pool: sqlx::PgPool) {
    let h = harness(pool, false).await;
    let (admin_id, admin) = h.admin("root@example.com").await;
    let (sec_id, sec) = h.staff("sec@example.com", StaffRole::Security).await;
    let bg = h.user("breakglass@example.com").await;
    h.make_admin(bg, true).await;
    let user = h.user("user@example.com").await;
    let change = |target: UserId, role: &str| {
        TestRequest::post(&format!("/v1/admin/staff/{target}/role"))
            .json(&json!({ "role": role, "reason": "Moves to support (HR-13)" }))
    };

    let res = h.send(&admin, change(sec_id, "support")).await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["previous_role"], "security");
    assert_eq!(body["role"], "support");
    assert_eq!(h.staff_role(sec_id).await, Some(StaffRole::Support));
    assert!(
        h.ports
            .session_revoker
            .calls()
            .contains(&RevocationCall::AllForUser(
                sec_id,
                RevocationReason::AdminAction,
                RevokeOptions {
                    also_trusted_devices: true
                }
            ))
    );
    let events = h.admin_events("staff_role_changed").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["previous_role"], "security");
    assert_eq!(events[0].metadata["role"], "support");
    assert_eq!(events[0].metadata["priority"], "high");
    assert_eq!(
        h.justification(events[0].id).await.as_deref(),
        Some("Moves to support (HR-13)")
    );
    // The demoted member's live session lost the permission at once.
    h.send(&sec, TestRequest::get("/v1/admin/audit-events"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");

    h.send(&admin, change(sec_id, "support"))
        .await
        .assert_error(StatusCode::CONFLICT, "conflict");
    for target in [admin_id, bg, user] {
        h.send(&admin, change(target, "support_readonly"))
            .await
            .assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
    }
    assert!(!h.record(user).await.is_platform_admin);
    h.send(&admin, change(UserId::generate(), "support"))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/staff/{sec_id}/role"))
            .json(&json!({ "role": "owner", "reason": "x" })),
    )
    .await
    .assert_status(StatusCode::UNPROCESSABLE_ENTITY);

    let staff: Value = h
        .send(&admin, TestRequest::get("/v1/admin/staff"))
        .await
        .json();
    let roles: BTreeSet<String> = staff
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        roles,
        ["platform_admin", "support"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
}

/// ADM-10 (K-93): with four-eyes on, a role change needs the approval of
/// another `platform_admin` for the exact target and role.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_10_staff_role_change_needs_a_second_platform_admin(pool: sqlx::PgPool) {
    let h = harness(pool, true).await;
    let (_, a) = h.admin("a@example.com").await;
    let (_, b) = h.admin("b@example.com").await;
    let (target, _) = h.staff("t@example.com", StaffRole::SupportReadonly).await;
    let uri = format!("/v1/admin/staff/{target}/role");
    let body = json!({ "role": "support", "reason": "Promotion (HR-14)" });
    h.send(&a, TestRequest::post(&uri).json(&body))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_required");
    let pending: Value = h
        .send(
            &a,
            TestRequest::post("/v1/admin/approvals").json(&json!({
                "action": "change_staff_role",
                "target_user_id": target,
                "role": "support",
                "reason": "Promotion (HR-14)",
            })),
        )
        .await
        .json();
    let id = pending["id"].as_str().unwrap();
    h.send(
        &b,
        TestRequest::post(&format!("/v1/admin/approvals/{id}/approve"))
            .json(&json!({ "reason": "Checked with HR" })),
    )
    .await
    .assert_status(StatusCode::OK);
    // Approved for `support`, not for `platform_admin`.
    let mut tampered = json!({ "role": "platform_admin", "reason": "Promotion (HR-14)" });
    tampered["approval_id"] = Value::from(id);
    h.send(&a, TestRequest::post(&uri).json(&tampered))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_approval_invalid");
    let mut good = body.clone();
    good["approval_id"] = Value::from(id);
    let res = h.send(&a, TestRequest::post(&uri).json(&good)).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(h.staff_role(target).await, Some(StaffRole::Support));
    let events = h.admin_events("staff_role_changed").await;
    assert_eq!(events[0].metadata["four_eyes"], "approved");
}

/// ADM-09 (K-93): the CLI grants staff rights with a role, changes the
/// role of staff, keeps break-glass accounts `platform_admin`, and never
/// demotes or revokes the last `platform_admin`.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_09_cli_grant_admin_takes_a_role(pool: sqlx::PgPool) {
    let h = harness(pool, false).await;
    let (root, _) = h.admin("root@example.com").await;
    let alice = h.user("alice@example.com").await;
    let bg = h.user("bg@example.com").await;
    h.make_admin(bg, true).await;
    let operator = OfflineOperator::parse("ops.oncall").unwrap();
    let why = authn_admin::Justification::parse(Some("Support hire (HR-15)")).unwrap();

    let out = h
        .service
        .grant_admin_offline(
            &operator,
            &OfflineTarget::Id(alice),
            StaffRole::SupportReadonly,
            &why,
        )
        .await
        .unwrap();
    assert_eq!(out.action, "offline_grant_admin");
    assert_eq!(h.staff_role(alice).await, Some(StaffRole::SupportReadonly));
    let alice_p = h.principal(alice, true);
    h.send(&alice_p, TestRequest::get("/v1/admin/users"))
        .await
        .assert_status(StatusCode::OK);
    h.send(&alice_p, TestRequest::get("/v1/admin/audit-events"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "admin_permission_denied");

    let out = h
        .service
        .grant_admin_offline(
            &operator,
            &OfflineTarget::Id(alice),
            StaffRole::Security,
            &why,
        )
        .await
        .unwrap();
    assert_eq!(out.action, "offline_change_staff_role");
    let events = h.admin_events("offline_change_staff_role").await;
    assert_eq!(events[0].metadata["previous_role"], "support_readonly");
    assert_eq!(events[0].metadata["role"], "security");
    assert_eq!(events[0].metadata["surface"], "cli");
    let err = h
        .service
        .grant_admin_offline(
            &operator,
            &OfflineTarget::Id(alice),
            StaffRole::Security,
            &why,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "conflict");
    let err = h
        .service
        .grant_admin_offline(&operator, &OfflineTarget::Id(bg), StaffRole::Support, &why)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "admin_target_not_allowed");

    // Revoke-admin removes the role too.
    h.service
        .revoke_admin_offline(&operator, &OfflineTarget::Id(alice), &why)
        .await
        .unwrap();
    assert_eq!(h.staff_role(alice).await, None);
    assert!(!h.record(alice).await.is_platform_admin);

    // The last platform_admin: root and bg; demote root is fine while bg
    // (break-glass, platform_admin) stays; then bg is the last one.
    h.service
        .grant_admin_offline(
            &operator,
            &OfflineTarget::Id(root),
            StaffRole::Security,
            &why,
        )
        .await
        .unwrap();
    let err = h
        .service
        .revoke_admin_offline(&operator, &OfflineTarget::Id(bg), &why)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "admin_target_not_allowed");
    // Break-glass accounts never hold another role, even in the database.
    let refused = sqlx::query("UPDATE admin_staff_roles SET role = 'support' WHERE user_id = $1")
        .bind(bg)
        .execute(&h.pool)
        .await;
    assert!(refused.is_err());
    // A role row needs the staff flag.
    let regular = h.user("regular@example.com").await;
    let refused = sqlx::query(
        "INSERT INTO admin_staff_roles (user_id, role, granted_at, updated_at) \
         VALUES ($1, 'support', now(), now())",
    )
    .bind(regular)
    .execute(&h.pool)
    .await;
    assert!(refused.is_err());
}

/// ADM-09 (K-93): migration `2203` keeps every existing platform admin
/// (break-glass included) as `platform_admin`.
#[sqlx::test(migrations = false)]
async fn adm_09_existing_platform_admins_become_platform_admin(pool: sqlx::PgPool) {
    authn_testkit::MIGRATOR.run_to(2202, &pool).await.unwrap();
    let now = time::OffsetDateTime::now_utc();
    let mut conn = pool.acquire().await.unwrap();
    let mut ids = Vec::new();
    for (email, admin, break_glass) in [
        ("admin@example.com", true, false),
        ("bg@example.com", true, true),
        ("user@example.com", false, false),
    ] {
        let id = UserId::generate();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status: AccountStatus::Active,
                created_at: now,
            },
        )
        .await
        .unwrap();
        UserRepository::set_admin_flags(&mut conn, id, admin, break_glass)
            .await
            .unwrap();
        ids.push(id);
    }
    drop(conn);
    authn_testkit::MIGRATOR.run(&pool).await.unwrap();
    let role = |id: UserId| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT role FROM admin_staff_roles WHERE user_id = $1")
                .bind(id)
                .fetch_optional(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(role(ids[0]).await.as_deref(), Some("platform_admin"));
    assert_eq!(role(ids[1]).await.as_deref(), Some("platform_admin"));
    assert_eq!(role(ids[2]).await, None);
}
