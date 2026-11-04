#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Regression tests of the independent security review of authn-admin.
//! Each test failed before its fix (see the crate README, "Güvenlik
//! notları").

mod common;

use std::time::Duration;

use authn_admin::Justification;
use authn_core::domain::AccountStatus;
use authn_core::error::codes;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::Harness;
use serde_json::json;
use time::format_description::well_known::Rfc3339;

/// Finding 1: a single compromised admin could suspend the break-glass
/// account (and keep revoking its sessions). Unsuspending an admin is not
/// possible through the API, so the break-glass account — the recovery
/// path of last resort — was lost. Break-glass accounts are now out of
/// reach of every admin API action except `unlock`.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_break_glass_account_cannot_be_suspended_or_revoked_by_another_admin(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    let (attacker, compromised) = h.admin("compromised@example.com").await;
    let glass = h.user("glass@example.com").await;
    h.make_admin(glass, true).await;

    for action in ["suspend", "revoke-sessions"] {
        let res = h
            .send(
                &compromised,
                TestRequest::post(&format!("/v1/admin/users/{glass}/{action}"))
                    .json(&json!({ "reason": "taking over" })),
            )
            .await;
        res.assert_error(StatusCode::FORBIDDEN, "admin_target_not_allowed");
    }
    assert_eq!(h.record(glass).await.status, AccountStatus::Active);
    assert!(h.ports.session_revoker.calls().is_empty());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_action_reasons")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "refused actions leave no justification");

    // Unlocking stays possible (it only restores access).
    let res = h
        .send(
            &compromised,
            TestRequest::post(&format!("/v1/admin/users/{glass}/unlock"))
                .json(&json!({ "reason": "locked by a brute-force attempt" })),
        )
        .await;
    res.assert_status(StatusCode::OK);

    // The break-glass account can still neutralize the compromised admin.
    let glass_principal = h.principal(glass, true);
    let res = h
        .send(
            &glass_principal,
            TestRequest::post(&format!("/v1/admin/users/{attacker}/suspend"))
                .json(&json!({ "reason": "INC-77: admin account compromised" })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(h.record(attacker).await.status, AccountStatus::Suspended);
}

/// Finding 2: the justification filter missed invisible / line-breaking
/// characters that are not `char::is_control` (line and paragraph
/// separators, the Arabic letter mark bidi control, Unicode tag characters
/// used for "ASCII smuggling", Hangul fillers, the Mongolian vowel
/// separator, interlinear annotation controls, the combining grapheme
/// joiner, deprecated format characters). They let an admin hide or
/// disguise text an auditor reads.
#[test]
fn adm_08_justification_rejects_hidden_and_line_breaking_characters() {
    for bad in [
        "ticket\u{2028}approved by CISO",
        "ticket\u{2029}x",
        "bidi \u{061C}mark",
        "smuggled \u{E0041}\u{E0042}",
        "language tag \u{E0001}",
        "filler \u{3164}",
        "filler \u{115F}",
        "filler \u{1160}",
        "half-width filler \u{FFA0}",
        "mongolian \u{180E}separator",
        "annotation \u{FFF9}x\u{FFFB}",
        "joiner \u{034F}",
        "deprecated \u{206A}format",
        "deprecated \u{206F}format",
    ] {
        let err = Justification::parse(Some(bad)).unwrap_err();
        assert_eq!(err.code(), codes::admin::REASON_REQUIRED, "{bad:?}");
    }
    // Ordinary multilingual text and emoji stay allowed.
    for good in [
        "Kullanıcı telefonunu kaybetti (SUP-1234) — doğrulandı",
        "Клиент позвонил",
        "顧客からの依頼",
        "user confirmed by phone 👍",
        "👍\u{FE0F} ok",
    ] {
        assert!(Justification::parse(Some(good)).is_ok(), "{good:?}");
    }
}

/// Finding 3: justifications live outside the hash chain and could be
/// rewritten or deleted silently by anyone holding the application's
/// database role. The table is now append-only like `audit_events`: rows
/// can only disappear through the foreign-key cascades (subject erasure,
/// audit retention) and the admin link only be cleared by the
/// `ON DELETE SET NULL` of an erased admin.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_justifications_are_append_only(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (admin_id, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/users/{user}/revoke-sessions"))
            .json(&json!({ "reason": "Original justification" })),
    )
    .await
    .assert_status(StatusCode::OK);
    let event = h.admin_events("revoke_user_sessions").await[0].id;

    for statement in [
        "UPDATE admin_action_reasons SET reason = 'rewritten'",
        "UPDATE admin_action_reasons SET admin_user_id = NULL",
        "DELETE FROM admin_action_reasons",
        "TRUNCATE admin_action_reasons",
    ] {
        let mut tx = h.pool.begin().await.unwrap();
        let result = sqlx::query(statement).execute(&mut *tx).await;
        assert!(result.is_err(), "{statement} must be refused");
        tx.rollback().await.unwrap();
    }
    assert_eq!(
        h.justification(event).await.as_deref(),
        Some("Original justification")
    );

    // Erasing the acting admin unlinks them (ON DELETE SET NULL) …
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(admin_id)
        .execute(&h.pool)
        .await
        .unwrap();
    let admin_link: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT admin_user_id FROM admin_action_reasons WHERE event_id = $1")
            .bind(event)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(admin_link, None);
    // … and erasing the subject removes the text (ON DELETE CASCADE).
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
    assert!(h.justification(event).await.is_none());
}

/// Finding 4: when a batch of the bulk "force password change" failed, the
/// already committed batches were audited by a failure event **without**
/// the justification (ADM-08: every admin action carries its reason).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_partially_failed_bulk_operation_keeps_its_justification(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| s.bulk_batch_size = 1).await;
    for i in 0..3 {
        h.user(&format!("old{i}@example.com")).await;
    }
    h.advance(Duration::from_secs(3600));
    let cutoff = h.now();
    h.advance(Duration::from_secs(60));
    let (_, mut admin) = h.admin("admin@example.com").await;
    admin.auth_time = Some(h.now());
    // The last account in id order cannot be updated: the earlier batches
    // commit, then the operation fails.
    let last: uuid::Uuid = sqlx::query_scalar(
        "SELECT max(user_id::text)::uuid FROM password_credentials WHERE changed_at < $1",
    )
    .bind(cutoff)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE password_credentials ADD CONSTRAINT test_reject \
         CHECK (NOT must_change OR user_id <> '{last}')"
    )))
    .execute(&h.pool)
    .await
    .unwrap();

    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/emergency/force-password-change").json(&json!({
                "reason": "Hash database leaked (INC-10)",
                "confirm": "force_password_change",
                "changed_before": cutoff.format(&Rfc3339).unwrap(),
                "revoke_sessions": false,
            })),
        )
        .await;
    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    let events = h.admin_events("force_password_change_before").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].kind, "admin.emergency_action");
    assert_eq!(events[0].outcome, "failure");
    assert_eq!(events[0].metadata["accounts_updated"], 2);
    assert_eq!(events[0].metadata["reason_recorded"], true);
    assert_eq!(
        h.justification(events[0].id).await.as_deref(),
        Some("Hash database leaked (INC-10)")
    );
}

/// The append-only barrier of finding 3 must not block the audit retention
/// purge (AUD-05): purging an event still removes its justification.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_retention_purge_still_removes_justifications(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/users/{user}/revoke-sessions"))
            .json(&json!({ "reason": "Old justification" })),
    )
    .await
    .assert_status(StatusCode::OK);
    let event = h.admin_events("revoke_user_sessions").await[0].id;
    h.advance(Duration::from_secs(3600));
    let mut admin = admin;
    admin.auth_time = Some(h.now());
    // A younger event, so the purged prefix ends before the chain head.
    h.send(&admin, TestRequest::get(&format!("/v1/admin/users/{user}")))
        .await
        .assert_status(StatusCode::OK);
    let report =
        authn_audit::purge_before(&h.pool, h.now() - Duration::from_secs(60), 100, h.now())
            .await
            .unwrap();
    assert!(report.events_deleted >= 1, "{report:?}");
    assert!(h.admin_events("revoke_user_sessions").await.is_empty());
    assert!(h.justification(event).await.is_none());
}
