#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Wave 2B hardening of the admin crate: offline incident response (K-07),
//! blast-radius limits (K-08), chain verification limits (K-09), the
//! emergency revocation keeping the caller's session (K-10), break-glass
//! passkey enrollment links (K-11), impersonation without replacing the
//! admin's cookie (K-12), break-glass and the IP allow-list (K-13),
//! justifications in the data export (K-39) and the MFA reset notice.

mod common;

use std::time::Duration;

use authn_admin::{
    AdminActionsDataExporter, OfflineOperator, OfflineTarget,
    create_break_glass_admin_with_passkey_link,
};
use authn_core::domain::AccountStatus;
use authn_core::id::UserId;
use authn_core::ports::{DataExporter, RevocationReason, RevokeOptions};
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::{Harness, PASSWORD};
use serde_json::{Value, json};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator as _;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::CreationChallengeResponse;

const ORIGIN: &str = "https://auth.test.example";

fn reason(text: &str) -> authn_admin::Justification {
    authn_admin::Justification::parse(Some(text)).unwrap()
}

async fn emergency(
    h: &Harness,
    admin: &authn_core::domain::Principal,
    which: &str,
) -> common::StoredResponse {
    let (uri, body) = match which {
        "revoke" => (
            "/v1/admin/emergency/revoke-all-sessions",
            json!({ "reason": "INC-1", "confirm": "revoke_all_sessions" }),
        ),
        "rotate" => (
            "/v1/admin/emergency/rotate-signing-key",
            json!({ "reason": "INC-1", "confirm": "rotate_signing_key" }),
        ),
        _ => (
            "/v1/admin/emergency/force-password-change",
            json!({ "reason": "INC-1", "confirm": "force_password_change",
                    "changed_before": "2000-01-01T00:00:00Z" }),
        ),
    };
    let res = h.send(admin, TestRequest::post(uri).json(&body)).await;
    common::StoredResponse {
        status: res.status,
        retry_after: res.header("retry-after").map(str::to_owned),
        body: res.json(),
    }
}

async fn throttle_events(h: &Harness, limit: &str) -> Vec<common::StoredEvent> {
    h.events("admin.action")
        .await
        .into_iter()
        .filter(|e| e.outcome == "failure" && e.reason.as_deref() == Some(limit))
        .collect()
}

// --- K-08 ------------------------------------------------------------------

/// K-08 (ADM-06): a second run of the same emergency operation within the
/// cool-down is refused for every (non break-glass) admin, with
/// `Retry-After`, a high-priority failed event and no effect.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k08_emergency_cooldown_blocks_repeated_operations(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, first) = h.admin("first@example.com").await;
    let (_, second) = h.admin("second@example.com").await;
    assert_eq!(emergency(&h, &first, "revoke").await.status, StatusCode::OK);
    let refused = emergency(&h, &second, "revoke").await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        refused.body["error"]["code"], "rate_limited",
        "{}",
        refused.body
    );
    assert!(refused.retry_after.is_some());
    assert_eq!(
        h.revoker.kept.lock().unwrap().len(),
        1,
        "no second revocation"
    );
    let events = throttle_events(&h, "emergency_cooldown").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["priority"], "high");
    assert_eq!(events[0].metadata["action"], "revoke_all_sessions");
    // Another emergency operation is not affected by this cool-down …
    assert_eq!(
        emergency(&h, &second, "rotate").await.status,
        StatusCode::OK
    );
    // … and after the cool-down the same operation works again.
    h.advance(Duration::from_secs(5 * 60 + 1));
    assert_eq!(
        emergency(&h, &second, "revoke").await.status,
        StatusCode::OK
    );
}

/// K-08: per-admin budget of emergency operations (3 per hour) and the
/// break-glass exemption from the shared (global / cool-down) budgets.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_k08_emergency_budget_per_admin_and_break_glass_exemption(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    for which in ["revoke", "rotate", "force"] {
        assert_eq!(
            emergency(&h, &admin, which).await.status,
            StatusCode::OK,
            "{which}"
        );
    }
    h.advance(Duration::from_secs(6 * 60));
    let refused = emergency(&h, &admin, "revoke").await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(throttle_events(&h, "emergency_per_admin").await.len(), 1);

    // A compromised admin consumed the shared cool-down: the break-glass
    // account can still act at once.
    let (_, other) = h.admin("other@example.com").await;
    assert_eq!(emergency(&h, &other, "revoke").await.status, StatusCode::OK);
    let bg = h.user("breakglass@example.com").await;
    h.make_admin(bg, true).await;
    let bg = h.principal(bg, true);
    assert_eq!(emergency(&h, &bg, "revoke").await.status, StatusCode::OK);
}

/// K-08: actions on other platform admins have their own strict budget;
/// actions on regular users are not affected. Successful admin-targeting
/// actions are high priority.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_k08_admin_targeting_actions_are_rate_limited(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, attacker) = h.admin("attacker@example.com").await;
    let mut admins = Vec::new();
    for i in 0..4 {
        admins.push(h.admin(&format!("admin{i}@example.com")).await.0);
    }
    for (i, target) in admins.iter().enumerate() {
        let res = h
            .send(
                &attacker,
                TestRequest::post(&format!("/v1/admin/users/{target}/suspend"))
                    .json(&json!({ "reason": "Suspicious activity" })),
            )
            .await;
        if i < 3 {
            res.assert_status(StatusCode::OK);
        } else {
            res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            assert_eq!(h.record(*target).await.status, AccountStatus::Active);
        }
    }
    assert_eq!(throttle_events(&h, "admin_target_per_admin").await.len(), 1);
    let suspended: Vec<_> = h
        .admin_events("suspend_user")
        .await
        .into_iter()
        .filter(|e| e.outcome == "success")
        .collect();
    assert_eq!(suspended.len(), 3);
    assert!(
        suspended
            .iter()
            .all(|e| e.metadata["priority"] == "high" && e.metadata["target_is_admin"] == true)
    );
    // Regular users: no admin-targeting budget.
    for i in 0..5 {
        let user = h.user(&format!("user{i}@example.com")).await;
        h.send(
            &attacker,
            TestRequest::post(&format!("/v1/admin/users/{user}/revoke-sessions"))
                .json(&json!({ "reason": "Support" })),
        )
        .await
        .assert_status(StatusCode::OK);
    }
}

/// K-08: the global admin-targeting budget spans all (non break-glass)
/// admins.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_k08_admin_targeting_has_a_global_budget(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.admin_target_global =
            authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(3600));
    })
    .await;
    let (_, a) = h.admin("a@example.com").await;
    let (_, b) = h.admin("b@example.com").await;
    let targets = [
        h.admin("t1@example.com").await.0,
        h.admin("t2@example.com").await.0,
        h.admin("t3@example.com").await.0,
    ];
    for (caller, target, status) in [
        (&a, targets[0], StatusCode::OK),
        (&b, targets[1], StatusCode::OK),
        (&a, targets[2], StatusCode::TOO_MANY_REQUESTS),
    ] {
        h.send(
            caller,
            TestRequest::post(&format!("/v1/admin/users/{target}/revoke-sessions"))
                .json(&json!({ "reason": "Containment" })),
        )
        .await
        .assert_status(status);
    }
    assert_eq!(throttle_events(&h, "admin_target_global").await.len(), 1);
}

// --- K-09 ------------------------------------------------------------------

/// K-09 (ADM-07): chain verification has a per-admin budget and at most one
/// runs at a time (lease); a stale lease expires on its own.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_07_k09_chain_verification_is_rate_limited_and_single_flight(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.audit_verify_per_admin =
            authn_core::ports::RateLimitPolicy::new(3, Duration::from_secs(3600));
    })
    .await;
    let (admin_id, admin) = h.admin("admin@example.com").await;
    let verify = || TestRequest::post("/v1/admin/audit-events/verify").json(&json!({}));
    h.send(&admin, verify()).await.assert_status(StatusCode::OK);
    // The lease is released after a run.
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_operation_leases")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(leases, 0);
    // Another verification is running (lease held by another instance).
    sqlx::query(
        "INSERT INTO admin_operation_leases (name, holder, acquired_at, expires_at) \
         VALUES ('audit_chain_verification', $1, $2, $3)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(h.now())
    .bind(h.now() + Duration::from_secs(15 * 60))
    .execute(&h.pool)
    .await
    .unwrap();
    h.send(&admin, verify())
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert_eq!(throttle_events(&h, "audit_verify_running").await.len(), 1);
    // The holder died: the lease expires and verification works again.
    h.advance(Duration::from_secs(15 * 60 + 1));
    let admin = h.principal(admin_id, true); // fresh step-up
    h.send(&admin, verify()).await.assert_status(StatusCode::OK);
    // Per-admin budget (3 per hour here; the refused run above counted).
    h.send(&admin, verify())
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert_eq!(throttle_events(&h, "audit_verify_per_admin").await.len(), 1);
}

// --- K-10 ------------------------------------------------------------------

/// K-10 (ADM-06): "revoke all sessions" keeps the caller's own session by
/// default and revokes it only on request.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_revoke_all_keeps_caller_session_by_default(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let res = emergency(&h, &admin, "revoke").await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.body["sessions_revoked"], 7);
    assert_eq!(
        *h.revoker.kept.lock().unwrap(),
        vec![(admin.session_id().unwrap(), RevocationReason::Emergency)]
    );
    assert!(
        h.ports.session_revoker.calls().is_empty(),
        "no revoke_everything"
    );
    let events = h.admin_events("revoke_all_sessions").await;
    assert_eq!(events[0].metadata["own_session_kept"], true);
}

// --- K-12 ------------------------------------------------------------------

/// K-12 (ADM-04): the web impersonation response never sets a cookie (the
/// admin's session cookie survives); the token is in the body with the
/// header to send it in.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_04_web_impersonation_does_not_replace_the_admin_cookie(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let res = h
        .send(
            &admin,
            TestRequest::post(&format!("/v1/admin/users/{user}/impersonate"))
                .json(&json!({ "reason": "Reproduce bug SUP-12" })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert!(res.set_cookies().is_empty(), "{:?}", res.set_cookies());
    let body: Value = res.json();
    assert_eq!(body["status"], "impersonating");
    assert_eq!(body["token_header"], "x-impersonation-session");
    assert!(
        body["impersonation_token"]
            .as_str()
            .unwrap()
            .starts_with("fake-")
    );
    // The admin is still an admin on the next request.
    h.send(&admin, TestRequest::get("/v1/admin/users"))
        .await
        .assert_status(StatusCode::OK);
}

// --- K-13 ------------------------------------------------------------------

/// K-13 (ADM-01, ADM-05): decision — break-glass accounts do **not** bypass
/// the admin IP allow-list (a stolen break-glass credential must not work
/// from anywhere). The documented procedure changes `[admin]
/// ip_allow_list` (configuration) or uses the offline CLI commands.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_01_k13_break_glass_obeys_the_ip_allow_list(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.ip_allow_list = vec!["198.51.100.0/24".parse().unwrap()];
    })
    .await;
    let bg = h.user("breakglass@example.com").await;
    h.make_admin(bg, true).await;
    let principal = h.principal(bg, true);
    h.send(&principal, TestRequest::get("/v1/admin/users"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    let res = TestRequest::get("/v1/admin/users")
        .peer_ip("198.51.100.7".parse().unwrap())
        .send(&h.app(Some(principal)))
        .await;
    res.assert_status(StatusCode::OK);
    // Refusals of real admins are audited (and alertable).
    let refused = h.admin_events("admin_access").await;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].reason.as_deref(), Some("ip_not_allowed"));
}

// --- K-07 ------------------------------------------------------------------

/// K-07 (ADM-05): offline (CLI) incident response suspends a compromised
/// break-glass admin and revokes its sessions — impossible through the API —
/// with a mandatory justification, as a high-priority `Actor::System` staff
/// action with the operator label; regular users are refused.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k07_offline_suspend_and_revoke_of_admin_accounts(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let bg = h.user("breakglass@example.com").await;
    h.make_admin(bg, true).await;
    let user = h.user("alice@example.com").await;
    let operator = OfflineOperator::parse("ops.oncall").unwrap();
    let why = reason("Break-glass password found in a public paste (INC-42)");

    let err = h
        .service
        .suspend_admin_offline(&operator, &OfflineTarget::Id(user), &why)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "admin_target_not_allowed");

    let out = h
        .service
        .suspend_admin_offline(
            &operator,
            &OfflineTarget::parse("BreakGlass@example.com"),
            &why,
        )
        .await
        .unwrap();
    assert!(out.changed);
    assert_eq!(h.record(bg).await.status, AccountStatus::Suspended);
    assert!(
        h.ports
            .session_revoker
            .calls()
            .contains(&RevocationCall::AllForUser(
                bg,
                RevocationReason::AccountSuspended,
                RevokeOptions {
                    also_trusted_devices: true
                }
            ))
    );
    let events = h.admin_events("offline_suspend_admin").await;
    assert_eq!(events.len(), 1);
    let meta = &events[0].metadata;
    assert_eq!(meta["priority"], "high");
    assert_eq!(meta["surface"], "cli");
    assert_eq!(meta["operator"], "ops.oncall");
    assert_eq!(meta["target_is_break_glass"], true);
    let (actor_type, admin_id): (String, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT e.actor_type, r.admin_user_id FROM audit_events e \
         JOIN admin_action_reasons r ON r.event_id = e.id WHERE e.id = $1",
    )
    .bind(events[0].id)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(actor_type, "system");
    assert_eq!(admin_id, None);
    assert_eq!(
        h.justification(events[0].id).await.as_deref(),
        Some("Break-glass password found in a public paste (INC-42)")
    );
    // The suspended break-glass account no longer passes the guard.
    let principal = h.principal(bg, true);
    h.send(&principal, TestRequest::get("/v1/admin/users"))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");

    // Revoke sessions and lift the suspension offline.
    let out = h
        .service
        .revoke_admin_sessions_offline(&operator, &OfflineTarget::Id(bg), &why)
        .await
        .unwrap();
    assert_eq!(out.action, "offline_revoke_admin_sessions");
    let out = h
        .service
        .unsuspend_admin_offline(
            &operator,
            &OfflineTarget::Id(bg),
            &reason("Credentials rotated"),
        )
        .await
        .unwrap();
    assert!(out.changed);
    assert_eq!(h.record(bg).await.status, AccountStatus::Active);
    assert_eq!(h.admin_events("offline_unsuspend_admin").await.len(), 1);
    // Unknown target.
    let err = h
        .service
        .revoke_admin_sessions_offline(&operator, &OfflineTarget::parse("nobody@example.com"), &why)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "not_found");
}

// --- K-11 ------------------------------------------------------------------

async fn enroll_with_link(
    h: &Harness,
    token: &str,
    key: &mut SoftPasskey,
) -> Result<authn_webauthn::PasskeySummary, authn_core::error::AuthError> {
    let start = h
        .service
        .start_break_glass_enrollment(&h.ctx(), token)
        .await?;
    let ccr: CreationChallengeResponse = serde_json::from_value(start.options.clone()).unwrap();
    let credential = key
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .unwrap();
    h.service
        .finish_break_glass_enrollment(
            &h.ctx(),
            token,
            authn_webauthn::RegistrationVerifyRequest {
                ceremony_id: start.ceremony_id,
                credential: serde_json::to_value(&credential).unwrap(),
                name: None,
            },
        )
        .await
}

/// K-11 (ADM-05): `create-admin --passkey-link` creates a password-less
/// break-glass admin and a single-use, short-lived link; the link token is
/// stored hashed, enrolls exactly one passkey, and is then dead. Expired
/// and unknown tokens answer the same error.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k11_break_glass_passkey_enrollment_link(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let link = create_break_glass_admin_with_passkey_link(
        &h.pool,
        h.ports.clock.as_ref(),
        &h.audit,
        "root@example.com",
        Duration::from_secs(30 * 60),
    )
    .await
    .unwrap();
    let token = link.token.expose().to_owned();
    assert!(
        !format!("{link:?}").contains(&token),
        "token never in Debug"
    );
    let record = h.record(link.user_id).await;
    assert!(record.is_break_glass && record.is_platform_admin);
    assert_eq!(record.status, AccountStatus::Active);
    let has_password = authn_store::UserRepository::find_password(&h.pool, link.user_id)
        .await
        .unwrap()
        .is_some();
    assert!(!has_password, "no password with a passkey link");
    // Hashed at rest.
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM admin_passkey_enrollments WHERE user_id = $1")
            .bind(link.user_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(stored, authn_crypto::sha256(token.as_bytes()).to_vec());
    assert_ne!(stored, token.as_bytes());
    let created = h.admin_events("break_glass_admin_created").await;
    assert_eq!(created[0].metadata["enrollment"], "passkey_link");
    assert_eq!(created[0].metadata["priority"], "high");

    // Unknown / malformed tokens.
    for bad in ["", "x", &"A".repeat(43)] {
        let err = h
            .service
            .start_break_glass_enrollment(&h.ctx(), bad)
            .await
            .unwrap_err();
        assert_eq!(err.code().code(), "invalid_or_expired_token");
    }

    let mut key = SoftPasskey::new(true);
    let summary = enroll_with_link(&h, &token, &mut key).await.unwrap();
    assert!(summary.usage.allows_passwordless());
    let enrolled = h.admin_events("break_glass_passkey_enrolled").await;
    assert_eq!(enrolled.len(), 1);
    assert_eq!(enrolled[0].metadata["priority"], "high");
    // Single use.
    let mut again = SoftPasskey::new(true);
    let err = enroll_with_link(&h, &token, &mut again).await.unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    let passkeys: i64 =
        sqlx::query_scalar("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(link.user_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(passkeys, 1);

    // A re-issued link (CLI, existing break-glass account) replaces the
    // open ones; an expired link is refused like an unknown one.
    let operator = OfflineOperator::parse("ops").unwrap();
    let first = h
        .service
        .issue_break_glass_enrollment_link_offline(
            &operator,
            &OfflineTarget::Id(link.user_id),
            &reason("Passkey lost (INC-9)"),
            Duration::from_secs(600),
        )
        .await
        .unwrap();
    let second = h
        .service
        .issue_break_glass_enrollment_link_offline(
            &operator,
            &OfflineTarget::Id(link.user_id),
            &reason("Passkey lost (INC-9)"),
            Duration::from_secs(600),
        )
        .await
        .unwrap();
    let err = h
        .service
        .start_break_glass_enrollment(&h.ctx(), first.token.expose())
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token", "replaced");
    h.advance(Duration::from_secs(601));
    let err = h
        .service
        .start_break_glass_enrollment(&h.ctx(), second.token.expose())
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token", "expired");
    // Regular users never get links; the TTL is bounded.
    let user = h.user("alice@example.com").await;
    h.make_admin(user, false).await;
    let err = h
        .service
        .issue_break_glass_enrollment_link_offline(
            &operator,
            &OfflineTarget::Id(user),
            &reason("x"),
            Duration::from_secs(600),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "admin_target_not_allowed");
    let err = create_break_glass_admin_with_passkey_link(
        &h.pool,
        h.ports.clock.as_ref(),
        &h.audit,
        "late@example.com",
        Duration::from_secs(25 * 3600),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code().code(), "validation_failed");
}

/// K-11 / K-13: the public enrollment endpoints obey the admin IP
/// allow-list, are rate limited per IP, and work over HTTP.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k11_enrollment_endpoints_obey_allow_list_and_rate_limit(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.enrollment_per_ip = authn_core::ports::RateLimitPolicy::new(3, Duration::from_secs(900));
    })
    .await;
    let link = create_break_glass_admin_with_passkey_link(
        &h.pool,
        h.ports.clock.as_ref(),
        &h.audit,
        "root@example.com",
        Duration::from_secs(600),
    )
    .await
    .unwrap();
    let app =
        authn_admin::enrollment_router::<authn_admin::AdminService>().with_state(h.service.clone());
    let app = authn_testkit::http::with_request_context(app);
    let options = TestRequest::post("/v1/admin/enrollment/options")
        .peer_ip(common::ADMIN_IP.parse().unwrap())
        .json(&json!({ "token": link.token.expose() }))
        .send(&app)
        .await;
    options.assert_status(StatusCode::OK);
    let body: Value = options.json();
    assert!(body["ceremony_id"].is_string());
    for _ in 0..2 {
        TestRequest::post("/v1/admin/enrollment/options")
            .peer_ip(common::ADMIN_IP.parse().unwrap())
            .json(&json!({ "token": "nope" }))
            .send(&app)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
    }
    TestRequest::post("/v1/admin/enrollment/options")
        .peer_ip(common::ADMIN_IP.parse().unwrap())
        .json(&json!({ "token": link.token.expose() }))
        .send(&app)
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");

    let h2 = Harness::with(h.pool.clone(), |s| {
        s.ip_allow_list = vec!["198.51.100.0/24".parse().unwrap()];
    })
    .await;
    let err = h2
        .service
        .start_break_glass_enrollment(&h2.ctx(), link.token.expose())
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "forbidden");
}

/// K-07 / K-11 (audit): the documented recovery of a **compromised**
/// break-glass account (`suspend-admin` → new enrollment link →
/// `unsuspend-admin` → enroll) must take every credential away from the
/// attacker: issuing the replacement link removes the account's password,
/// passkeys and other factors and ends its sessions in the same
/// transaction. Before the fix the attacker's passkey and password worked
/// again as soon as the account was unsuspended.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k07_replacement_link_removes_the_compromised_credentials(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    // A break-glass account with a password, plus a passkey the attacker
    // enrolled.
    let created = authn_admin::create_break_glass_admin(
        &h.pool,
        &h.crypto.passwords,
        h.ports.clock.as_ref(),
        &h.audit,
        "root@example.com",
    )
    .await
    .unwrap();
    let bg = created.user_id;
    let operator = OfflineOperator::parse("ops").unwrap();
    let first = h
        .service
        .issue_break_glass_enrollment_link_offline(
            &operator,
            &OfflineTarget::Id(bg),
            &reason("Initial passkey"),
            Duration::from_secs(600),
        )
        .await
        .unwrap();
    let mut attacker = SoftPasskey::new(true);
    enroll_with_link(&h, first.token.expose(), &mut attacker)
        .await
        .unwrap();

    let why = reason("Break-glass credentials leaked (INC-77)");
    h.service
        .suspend_admin_offline(&operator, &OfflineTarget::Id(bg), &why)
        .await
        .unwrap();
    let link = h
        .service
        .issue_break_glass_enrollment_link_offline(
            &operator,
            &OfflineTarget::Id(bg),
            &why,
            Duration::from_secs(600),
        )
        .await
        .unwrap();
    let passkeys = |pool: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(bg)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert_eq!(
        passkeys(h.pool.clone()).await,
        0,
        "attacker passkey removed"
    );
    assert!(
        authn_store::UserRepository::find_password(&h.pool, bg)
            .await
            .unwrap()
            .is_none(),
        "leaked password removed"
    );
    assert!(
        h.ports
            .session_revoker
            .calls()
            .iter()
            .filter(|c| matches!(c, RevocationCall::AllForUser(u, ..) if *u == bg))
            .count()
            >= 2,
        "sessions and trusted devices end again with the replacement link"
    );
    let events = h.admin_events("offline_issue_enrollment_link").await;
    assert_eq!(events.len(), 2);
    // The first link already replaced the leaked password, the second
    // one the attacker's passkey.
    assert!(
        events
            .iter()
            .any(|e| e.metadata["password_removed"] == true)
    );
    assert!(events.iter().any(|e| e.metadata["passkeys_removed"] == 1));

    // Suspended: the link does not work yet.
    let mut owner = SoftPasskey::new(true);
    let err = enroll_with_link(&h, link.token.expose(), &mut owner)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    h.service
        .unsuspend_admin_offline(&operator, &OfflineTarget::Id(bg), &reason("Rotated"))
        .await
        .unwrap();
    enroll_with_link(&h, link.token.expose(), &mut owner)
        .await
        .unwrap();
    assert_eq!(
        passkeys(h.pool.clone()).await,
        1,
        "only the owner's passkey"
    );
}

// --- K-39 ------------------------------------------------------------------

async fn export(h: &Harness, user: UserId) -> Value {
    let mut conn = h.pool.acquire().await.unwrap();
    AdminActionsDataExporter
        .export(&mut conn, user)
        .await
        .unwrap()
}

/// K-39 (ACC-10, ADM-08): justifications about the user are part of their
/// data export — action, time, text — without staff identity or IP.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_admin_justifications_are_exported_without_staff_identity(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (admin_id, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let other = h.user("bob@example.com").await;
    for (target, why) in [(user, "Chargeback dispute CB-1"), (other, "Unrelated")] {
        h.send(
            &admin,
            TestRequest::post(&format!("/v1/admin/users/{target}/revoke-sessions"))
                .json(&json!({ "reason": why })),
        )
        .await
        .assert_status(StatusCode::OK);
    }
    assert_eq!(AdminActionsDataExporter.section(), "admin_actions");
    let section = export(&h, user).await;
    let entries = section["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{section}");
    assert_eq!(entries[0]["action"], "revoke_user_sessions");
    assert_eq!(entries[0]["justification"], "Chargeback dispute CB-1");
    assert_eq!(entries[0]["actor"], "platform_staff");
    assert!(entries[0]["at"].as_str().unwrap().contains('T'));
    assert_eq!(section["withheld_under_legal_restriction"], 0);
    let text = section.to_string();
    assert!(!text.contains(&admin_id.to_string()), "no staff id");
    assert!(!text.contains(common::ADMIN_IP), "no staff IP");
    assert!(!text.contains("admin@example.com"));
}

/// K-39: a restricted justification is withheld from the export, which only
/// states how many entries are withheld; the restriction note is withheld
/// as well and the restriction cannot be removed.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_restricted_justification_is_withheld_and_counted(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let (_, other_admin) = h.admin("legal@example.com").await;
    let user = h.user("alice@example.com").await;
    for why in ["Fraud ring investigation FR-7", "Routine support"] {
        h.send(
            &admin,
            TestRequest::post(&format!("/v1/admin/users/{user}/revoke-sessions"))
                .json(&json!({ "reason": why })),
        )
        .await
        .assert_status(StatusCode::OK);
    }
    let fraud = h.admin_events("revoke_user_sessions").await[0].id;
    let res = h
        .send(
            &other_admin,
            TestRequest::post(&format!("/v1/admin/audit-events/{fraud}/restrict"))
                .json(&json!({ "reason": "Ongoing police investigation, KVKK m.28" })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let section = export(&h, user).await;
    let text = section.to_string();
    assert!(!text.contains("Fraud ring"), "{section}");
    assert!(
        !text.contains("police"),
        "the restriction note is withheld too"
    );
    assert_eq!(section["entries"].as_array().unwrap().len(), 1);
    assert_eq!(section["entries"][0]["justification"], "Routine support");
    assert_eq!(section["withheld_under_legal_restriction"], 2);
    // Append-only: the restriction cannot be lifted or rewritten.
    for sql in [
        "DELETE FROM admin_reason_restrictions",
        "UPDATE admin_reason_restrictions SET created_at = now()",
        "TRUNCATE admin_reason_restrictions",
    ] {
        let mut tx = h.pool.begin().await.unwrap();
        assert!(sqlx::query(sql).execute(&mut *tx).await.is_err(), "{sql}");
        tx.rollback().await.unwrap();
    }
    // The admins still see the justification (staff view).
    let page: Value = h
        .send(
            &admin,
            TestRequest::get("/v1/admin/audit-events?kind=admin.action"),
        )
        .await
        .json();
    assert!(page.to_string().contains("Fraud ring investigation FR-7"));
    // Erasure of the subject still removes everything (cascade).
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_reason_restrictions")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// K-39: restricting needs a valid note, is an audited `admin.action`
/// (`restrict_justification`) with that note as its justification, and is
/// refused for unknown events and the caller's own entries.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_restricting_requires_reason_and_is_audited(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (admin_id, admin) = h.admin("admin@example.com").await;
    let (_, other) = h.admin("other@example.com").await;
    let user = h.user("alice@example.com").await;
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/users/{user}/revoke-sessions"))
            .json(&json!({ "reason": "Fraud FR-8" })),
    )
    .await
    .assert_status(StatusCode::OK);
    let event = h.admin_events("revoke_user_sessions").await[0].id;
    let uri = format!("/v1/admin/audit-events/{event}/restrict");
    for body in [
        json!({}),
        json!({ "reason": "" }),
        json!({ "reason": "a\u{202e}b" }),
    ] {
        h.send(&admin, TestRequest::post(&uri).json(&body))
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
    }
    h.send(
        &admin,
        TestRequest::post(&format!(
            "/v1/admin/audit-events/{}/restrict",
            uuid::Uuid::now_v7()
        ))
        .json(&json!({ "reason": "Legal hold LH-1" })),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "not_found");
    let res = h
        .send(
            &admin,
            TestRequest::post(&uri).json(&json!({ "reason": "Legal hold LH-1" })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let out: Value = res.json();
    assert_eq!(out["changed"], true);
    let audited = h.admin_events("restrict_justification").await;
    assert_eq!(audited.len(), 1);
    assert_eq!(
        audited[0].metadata["restricted_event_id"],
        event.to_string()
    );
    assert_eq!(
        h.justification(audited[0].id).await.as_deref(),
        Some("Legal hold LH-1")
    );
    // Restricting again changes nothing (still audited).
    let again: Value = h
        .send(
            &admin,
            TestRequest::post(&uri).json(&json!({ "reason": "Legal hold LH-1" })),
        )
        .await
        .json();
    assert_eq!(again["changed"], false);
    // An entry about the caller cannot be restricted by them.
    h.send(
        &other,
        TestRequest::post(&format!("/v1/admin/users/{admin_id}/revoke-sessions"))
            .json(&json!({ "reason": "Containment" })),
    )
    .await
    .assert_status(StatusCode::OK);
    let about_admin = h
        .admin_events("revoke_user_sessions")
        .await
        .into_iter()
        .last()
        .unwrap()
        .id;
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/audit-events/{about_admin}/restrict"))
            .json(&json!({ "reason": "Hide it" })),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
}

// --- MFA reset notice (auditor note) -----------------------------------------

/// ADM-03: an MFA reset of an account with several passkeys sends exactly
/// one `mfa_reset` and exactly one passkey-removed (`mfa_factor_removed`)
/// notice — not one per credential.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_mfa_reset_sends_one_notice_not_one_per_passkey(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    for n in 0..3u8 {
        let hash = [n + 1; 32];
        let start = h
            .webauthn
            .start_enrollment_registration(&h.ctx(), user, hash)
            .await
            .unwrap();
        let ccr: CreationChallengeResponse = serde_json::from_value(start.options.clone()).unwrap();
        let mut key = SoftPasskey::new(true);
        let credential = key
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .unwrap();
        let verified = h
            .webauthn
            .verify_enrollment_registration(
                &h.ctx(),
                user,
                hash,
                authn_webauthn::RegistrationVerifyRequest {
                    ceremony_id: start.ceremony_id,
                    credential: serde_json::to_value(&credential).unwrap(),
                    name: None,
                },
            )
            .await
            .unwrap();
        let mut tx = h.pool.begin().await.unwrap();
        h.webauthn
            .store_enrollment_in_tx(&mut tx, &h.ctx(), verified)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    h.ports.notifier.take();
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/users/{user}/reset-mfa"))
            .json(&json!({ "reason": "Lost all devices (SUP-3)" })),
    )
    .await
    .assert_status(StatusCode::OK);
    assert_eq!(h.events("passkey.removed").await.len(), 3);
    assert_eq!(h.ports.notifier.with_template("mfa_reset").len(), 1);
    assert_eq!(
        h.ports.notifier.with_template("mfa_factor_removed").len(),
        1
    );
    let _ = PASSWORD;
}
