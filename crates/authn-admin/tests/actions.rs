#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ADM-03 / ADM-08: per-user actions, each audited with its justification
//! in the same transaction; reason validation; target rules.

mod common;

use authn_core::domain::AccountStatus;
use authn_core::id::UserId;
use authn_core::ports::{RevocationReason, RevokeOptions};
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};

const ALL_DEVICES: RevokeOptions = RevokeOptions {
    also_trusted_devices: true,
};

async fn post(
    h: &Harness,
    principal: &authn_core::domain::Principal,
    uri: &str,
    body: Value,
) -> authn_testkit::http::TestResponse {
    h.send(principal, TestRequest::post(uri).json(&body)).await
}

/// The `admin.action` event of `action` carries the actor, subject, the
/// action code and — outside the chain — the justification.
async fn assert_audited(h: &Harness, action: &str, subject: UserId, reason: &str) -> Value {
    let events = h.admin_events(action).await;
    assert_eq!(events.len(), 1, "{action}: {events:?}");
    let event = &events[0];
    assert_eq!(event.kind, "admin.action");
    assert_eq!(event.outcome, "success");
    assert_eq!(event.metadata["reason_recorded"], true);
    assert!(
        !event.metadata.to_string().contains("[REDACTED]"),
        "metadata redacted by the sink: {}",
        event.metadata
    );
    // The free text never enters the hash chain (AUD-03).
    assert!(!event.metadata.to_string().contains(reason));
    assert_eq!(h.justification(event.id).await.as_deref(), Some(reason));
    let subject_row: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT subject_user_id FROM admin_action_reasons WHERE event_id = $1")
            .bind(event.id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(subject_row, Some(subject.as_uuid()));
    event.metadata.clone()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_suspend_and_unsuspend_are_audited_with_reason(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;

    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/suspend"),
        json!({ "reason": "Fraud report FR-1001, card testing" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["action"], "suspend_user");
    assert_eq!(h.record(user).await.status, AccountStatus::Suspended);
    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::AllForUser(
            user,
            RevocationReason::AccountSuspended,
            ALL_DEVICES
        )]
    );
    let meta = assert_audited(
        &h,
        "suspend_user",
        user,
        "Fraud report FR-1001, card testing",
    )
    .await;
    assert_eq!(meta["from"], "active");
    assert_eq!(meta["to"], "suspended");
    // The account module's own event is attributed to the system, not to
    // the staff member (whose identity stays in admin.* only).
    let status_events = h.events("account.status_changed").await;
    assert_eq!(status_events.len(), 1);
    let actor: String = sqlx::query_scalar("SELECT actor_type FROM audit_events WHERE id = $1")
        .bind(status_events[0].id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(actor, "system");

    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/unsuspend"),
        json!({ "reason": "Chargeback resolved" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(h.record(user).await.status, AccountStatus::Active);
    assert_audited(&h, "unsuspend_user", user, "Chargeback resolved").await;

    // Unsuspending an active account is refused and nothing is audited.
    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/unsuspend"),
        json!({ "reason": "again" }),
    )
    .await;
    res.assert_error(
        StatusCode::CONFLICT,
        "account_status_transition_not_allowed",
    );
    assert_eq!(h.admin_events("unsuspend_user").await.len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_unsuspend_of_unverified_account_returns_to_verification(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h
        .user_with_status("pending@example.com", AccountStatus::PendingVerification)
        .await;
    post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/suspend"),
        json!({ "reason": "spam" }),
    )
    .await
    .assert_status(StatusCode::OK);
    post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/unsuspend"),
        json!({ "reason": "not spam" }),
    )
    .await
    .assert_status(StatusCode::OK);
    assert_eq!(
        h.record(user).await.status,
        AccountStatus::PendingVerification
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_unlock_clears_account_lock_and_soft_lock(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let until = h.now() + std::time::Duration::from_secs(3600);
    sqlx::query("UPDATE users SET status = 'locked', locked_until = $2 WHERE id = $1")
        .bind(user)
        .bind(until)
        .execute(&h.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO login_soft_locks (user_id, locked_until, failure_count, created_at) \
         VALUES ($1, $2, 7, $3)",
    )
    .bind(user)
    .bind(until)
    .bind(h.now())
    .execute(&h.pool)
    .await
    .unwrap();
    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/unlock"),
        json!({ "reason": "Verified identity by phone" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["changed"], true);
    assert_eq!(h.record(user).await.status, AccountStatus::Active);
    let locks: i64 = sqlx::query_scalar("SELECT count(*) FROM login_soft_locks WHERE user_id = $1")
        .bind(user)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(locks, 0);
    let meta = assert_audited(&h, "unlock_user", user, "Verified identity by phone").await;
    assert_eq!(meta["account_unlocked"], true);
    assert_eq!(meta["soft_lock_cleared"], true);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_revoke_sessions_is_audited(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    h.ports.session_revoker.set_revoked_count(3);
    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/revoke-sessions"),
        json!({ "reason": "Lost laptop" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["sessions_revoked"], 3);
    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::AllForUser(
            user,
            RevocationReason::AdminAction,
            ALL_DEVICES
        )]
    );
    let meta = assert_audited(&h, "revoke_user_sessions", user, "Lost laptop").await;
    assert_eq!(meta["sessions_revoked"], 3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_force_password_reset_invalidates_password_and_sends_link(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let before: String =
        sqlx::query_scalar("SELECT password_hash FROM password_credentials WHERE user_id = $1")
            .bind(user)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/force-password-reset"),
        json!({ "reason": "Password seen in a paste site" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["action"], "force_password_reset");
    assert_eq!(body["reset_email_queued"], true);
    let (after, must_change): (String, bool) = sqlx::query_as(
        "SELECT password_hash, must_change FROM password_credentials WHERE user_id = $1",
    )
    .bind(user)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_ne!(before, after, "the old password must stop working");
    assert!(must_change);
    // The old password no longer verifies.
    let stored = authn_store::UserRepository::find_password(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(stored.password_hash.expose(), before);
    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::AllForUser(
            user,
            RevocationReason::AdminAction,
            ALL_DEVICES
        )]
    );
    assert_audited(
        &h,
        "force_password_reset",
        user,
        "Password seen in a paste site",
    )
    .await;
    // The reset link goes out through the normal reset flow (background).
    h.service_passwords_drain().await;
    assert_eq!(h.ports.notifier.with_template("password_reset").len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_must_change_password_is_set_and_cleared(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let uri = format!("/v1/admin/users/{user}/must-change-password");
    let res = post(
        &h,
        &admin,
        &uri,
        json!({ "reason": "policy", "must_change": true }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["changed"], true);
    let flag: bool =
        sqlx::query_scalar("SELECT must_change FROM password_credentials WHERE user_id = $1")
            .bind(user)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(flag);
    let res = post(
        &h,
        &admin,
        &uri,
        json!({ "reason": "undo", "must_change": false }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    let events = h.admin_events("set_must_change_password").await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].metadata["must_change"], true);
    assert_eq!(events[1].metadata["must_change"], false);
    assert_eq!(h.justification(events[1].id).await.as_deref(), Some("undo"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_mfa_reset_requires_reason_notifies_user_and_revokes(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    sqlx::query(
        "INSERT INTO mfa_factors (id, user_id, kind, status, created_at, confirmed_at) \
         VALUES ($1, $2, 'email', 'active', $3, $3)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(user)
    .bind(h.now())
    .execute(&h.pool)
    .await
    .unwrap();
    let uri = format!("/v1/admin/users/{user}/reset-mfa");
    for body in [
        json!({}),
        json!({ "reason": "" }),
        json!({ "reason": "  " }),
    ] {
        let res = post(&h, &admin, &uri, body).await;
        res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
    }
    assert!(h.ports.notifier.recorded().is_empty());
    let factors: i64 = sqlx::query_scalar("SELECT count(*) FROM mfa_factors WHERE user_id = $1")
        .bind(user)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(factors, 1, "nothing happens without a reason");

    let res = post(
        &h,
        &admin,
        &uri,
        json!({ "reason": "Phone lost, ID checked (SUP-77)" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    let factors: i64 = sqlx::query_scalar("SELECT count(*) FROM mfa_factors WHERE user_id = $1")
        .bind(user)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(factors, 0);
    assert_eq!(h.ports.notifier.with_template("mfa_reset").len(), 1);
    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::AllForUser(
            user,
            RevocationReason::MfaChanged,
            ALL_DEVICES
        )]
    );
    let meta = assert_audited(&h, "reset_mfa", user, "Phone lost, ID checked (SUP-77)").await;
    assert_eq!(meta["factors_removed"], 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_mark_email_verified_requires_reason_and_uses_administrator_proof(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    let (admin_id, admin) = h.admin("admin@example.com").await;
    let user = h
        .user_with_status("pending@example.com", AccountStatus::PendingVerification)
        .await;
    let uri = format!("/v1/admin/users/{user}/mark-email-verified");
    post(&h, &admin, &uri, json!({}))
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
    assert!(h.record(user).await.email_verified_at.is_none());

    let res = post(
        &h,
        &admin,
        &uri,
        json!({ "reason": "Customer verified on a call" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["changed"], true);
    let record = h.record(user).await;
    assert!(record.email_verified_at.is_some());
    assert_eq!(record.status, AccountStatus::Active);
    // ADR 0002: the never-proven password is removed and sessions revoked.
    assert!(
        authn_store::UserRepository::find_password(&h.pool, user)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        h.ports
            .session_revoker
            .calls()
            .iter()
            .any(|c| matches!(c, RevocationCall::AllForUser(u, _, _) if *u == user))
    );
    let verified = h.events("account.email_verified").await;
    assert_eq!(verified[0].metadata["method"], "administrator");
    let _ = admin_id;
    assert_audited(
        &h,
        "mark_email_verified",
        user,
        "Customer verified on a call",
    )
    .await;

    // Already verified: no change, still audited.
    let res = post(&h, &admin, &uri, json!({ "reason": "double check" })).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["changed"], false);
    assert_eq!(h.admin_events("mark_email_verified").await.len(), 2);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_every_action_requires_a_valid_reason(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    let long = "x".repeat(1001);
    for action in [
        "suspend",
        "unsuspend",
        "unlock",
        "revoke-sessions",
        "force-password-reset",
        "reset-mfa",
        "mark-email-verified",
        "impersonate",
    ] {
        let uri = format!("/v1/admin/users/{user}/{action}");
        for reason in [
            Value::Null,
            json!(""),
            json!("\t"),
            json!(long),
            json!("hidden\u{202E}text"),
            json!("multi\nline"),
        ] {
            let res = post(&h, &admin, &uri, json!({ "reason": reason })).await;
            res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
        }
    }
    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/must-change-password"),
        json!({ "must_change": true }),
    )
    .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
    for (uri, confirm) in [
        (
            "/v1/admin/emergency/revoke-all-sessions",
            "revoke_all_sessions",
        ),
        (
            "/v1/admin/emergency/rotate-signing-key",
            "rotate_signing_key",
        ),
    ] {
        let res = post(&h, &admin, uri, json!({ "confirm": confirm })).await;
        res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
    }
    let res = post(&h, &admin, "/v1/admin/audit-events/export", json!({})).await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "admin_reason_required");
    // Nothing was done or audited.
    assert!(h.ports.session_revoker.calls().is_empty());
    assert_eq!(h.record(user).await.status, AccountStatus::Active);
    let actions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE kind IN ('admin.action', 'admin.emergency_action')",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(actions, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_target_rules_protect_self_admins_and_break_glass(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (me, admin) = h.admin("admin@example.com").await;
    let (other_admin, _) = h.admin("other-admin@example.com").await;
    let glass = h.user("glass@example.com").await;
    h.make_admin(glass, true).await;
    let r = json!({ "reason": "test" });

    // Nothing on one's own account.
    for action in [
        "suspend",
        "unlock",
        "revoke-sessions",
        "reset-mfa",
        "force-password-reset",
    ] {
        let res = post(
            &h,
            &admin,
            &format!("/v1/admin/users/{me}/{action}"),
            r.clone(),
        )
        .await;
        res.assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
    }
    // Takeover-enabling actions never apply to admins / break-glass.
    for target in [other_admin, glass] {
        for action in [
            "unsuspend",
            "force-password-reset",
            "reset-mfa",
            "mark-email-verified",
            "impersonate",
        ] {
            let res = post(
                &h,
                &admin,
                &format!("/v1/admin/users/{target}/{action}"),
                r.clone(),
            )
            .await;
            res.assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
        }
        let res = post(
            &h,
            &admin,
            &format!("/v1/admin/users/{target}/must-change-password"),
            json!({ "reason": "x", "must_change": true }),
        )
        .await;
        res.assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
    }
    assert!(h.issuer.requests.lock().unwrap().is_empty());
    // Defensive actions on another admin are allowed (compromised admin).
    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{other_admin}/suspend"),
        json!({ "reason": "Compromised admin account" }),
    )
    .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(h.record(other_admin).await.status, AccountStatus::Suspended);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_unknown_target_is_not_found_and_not_audited(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let ghost = UserId::generate();
    for action in [
        "suspend",
        "unlock",
        "revoke-sessions",
        "reset-mfa",
        "impersonate",
    ] {
        let res = post(
            &h,
            &admin,
            &format!("/v1/admin/users/{ghost}/{action}"),
            json!({ "reason": "x" }),
        )
        .await;
        res.assert_error(StatusCode::NOT_FOUND, "not_found");
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_action_reasons")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_failed_action_rolls_back_change_audit_and_reason(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    // Make the justification insert fail after the status change and the
    // audit append in the same transaction.
    sqlx::query(
        "ALTER TABLE admin_action_reasons ADD CONSTRAINT test_reject CHECK (reason <> 'boom')",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let res = post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/suspend"),
        json!({ "reason": "boom" }),
    )
    .await;
    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.record(user).await.status, AccountStatus::Active);
    assert!(h.admin_events("suspend_user").await.is_empty());
    assert!(h.events("account.status_changed").await.is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_justification_follows_subject_erasure(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    post(
        &h,
        &admin,
        &format!("/v1/admin/users/{user}/revoke-sessions"),
        json!({ "reason": "Alice Smith called from +90 555 111 2233" }),
    )
    .await
    .assert_status(StatusCode::OK);
    let event = h.admin_events("revoke_user_sessions").await[0].id;
    assert!(h.justification(event).await.is_some());
    // Account deletion (ACC-09) hard-deletes the user row.
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
    assert!(h.justification(event).await.is_none());
    // The chained event itself stays.
    assert_eq!(h.admin_events("revoke_user_sessions").await.len(), 1);
}
