#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ADM-06: emergency operations.

mod common;

use std::time::Duration;

use authn_core::ports::{RevocationReason, RevokeOptions};
use authn_store::SigningKeyRepository;
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_revoke_all_sessions_requires_confirmation_and_is_audited(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let uri = "/v1/admin/emergency/revoke-all-sessions";
    for confirm in [Value::Null, json!("yes"), json!("REVOKE_ALL_SESSIONS")] {
        let res = h
            .send(
                &admin,
                TestRequest::post(uri).json(&json!({ "reason": "x", "confirm": confirm })),
            )
            .await;
        res.assert_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "admin_confirmation_required",
        );
    }
    assert!(h.ports.session_revoker.calls().is_empty());
    h.ports.session_revoker.set_revoked_count(1234);
    let res = h
        .send(
            &admin,
            TestRequest::post(uri).json(&json!({
                "reason": "Session store leaked (INC-7)",
                "confirm": "revoke_all_sessions",
            })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["sessions_revoked"], 1234);
    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::Everything(RevocationReason::Emergency)]
    );
    let events = h.admin_events("revoke_all_sessions").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "admin.emergency_action");
    assert_eq!(events[0].metadata["priority"], "high");
    assert_eq!(
        h.justification(events[0].id).await.as_deref(),
        Some("Session store leaked (INC-7)")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_emergency_key_rotation_replaces_active_key(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let before = SigningKeyRepository::active(&h.pool)
        .await
        .unwrap()
        .unwrap();
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/emergency/rotate-signing-key").json(&json!({
                "reason": "Key material exposed in a backup",
                "confirm": "rotate_signing_key",
            })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    let after = SigningKeyRepository::active(&h.pool)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(before.id, after.id);
    assert_eq!(body["key_id"], after.id.to_string());
    let old = SigningKeyRepository::find(&h.pool, before.id)
        .await
        .unwrap()
        .unwrap();
    assert!(old.revoked_at.is_some(), "old key revoked at once");
    assert!(!old.is_publishable(h.now()));
    assert_eq!(*h.keys.0.lock().unwrap(), 1, "in-process cache dropped");
    let events = h.admin_events("rotate_signing_key").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["signing_key_id"], after.id.to_string());
    // Confirmation is mandatory.
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/emergency/rotate-signing-key")
                .json(&json!({ "reason": "x" })),
        )
        .await;
    res.assert_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "admin_confirmation_required",
    );
    assert_eq!(*h.keys.0.lock().unwrap(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_force_password_change_before_date_in_batches(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| s.bulk_batch_size = 2).await;
    let (_, mut admin) = h.admin("admin@example.com").await;
    let mut old = Vec::new();
    for i in 0..5 {
        old.push(h.user(&format!("old{i}@example.com")).await);
    }
    h.advance(Duration::from_secs(3600));
    let cutoff = h.now();
    h.advance(Duration::from_secs(60));
    let fresh = h.user("fresh@example.com").await;
    // The admin stepped up just now.
    admin.auth_time = Some(h.now());
    // Already flagged accounts are left alone (no double counting).
    sqlx::query("UPDATE password_credentials SET must_change = true WHERE user_id = $1")
        .bind(old[0])
        .execute(&h.pool)
        .await
        .unwrap();

    let body = |changed_before: String| {
        json!({
            "reason": "Hash database leaked (INC-9)",
            "confirm": "force_password_change",
            "changed_before": changed_before,
        })
    };
    let future = (h.now() + Duration::from_secs(3600))
        .format(&Rfc3339)
        .unwrap();
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/emergency/force-password-change").json(&body(future)),
        )
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/emergency/force-password-change")
                .json(&body("not a date".into())),
        )
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");

    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/emergency/force-password-change")
                .json(&body(cutoff.format(&Rfc3339).unwrap())),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let out: Value = res.json();
    // old[1..5] + the admin (created before the cutoff, same as old users).
    assert_eq!(out["accounts_updated"], 5);
    for user in &old {
        let flag: bool =
            sqlx::query_scalar("SELECT must_change FROM password_credentials WHERE user_id = $1")
                .bind(user)
                .fetch_one(&h.pool)
                .await
                .unwrap();
        assert!(flag);
    }
    let fresh_flag: bool =
        sqlx::query_scalar("SELECT must_change FROM password_credentials WHERE user_id = $1")
            .bind(fresh)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(!fresh_flag, "recently changed passwords are untouched");
    let revoked: Vec<_> = h
        .ports
        .session_revoker
        .calls()
        .into_iter()
        .filter(|c| {
            matches!(
                c,
                RevocationCall::AllForUser(
                    _,
                    RevocationReason::Emergency,
                    RevokeOptions {
                        also_trusted_devices: true
                    }
                )
            )
        })
        .collect();
    assert_eq!(revoked.len(), 5);
    assert!(!revoked.contains(&RevocationCall::AllForUser(
        old[0],
        RevocationReason::Emergency,
        RevokeOptions {
            also_trusted_devices: true
        }
    )));
    let events = h.admin_events("force_password_change_before").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["accounts_updated"], 5);
    assert_eq!(
        h.justification(events[0].id).await.as_deref(),
        Some("Hash database leaked (INC-9)")
    );

    // Re-running finds nothing left to do.
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/emergency/force-password-change").json(&json!({
                "reason": "again",
                "confirm": "force_password_change",
                "changed_before": cutoff.format(&Rfc3339).unwrap(),
                "revoke_sessions": false,
            })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["accounts_updated"], 0);
}
