#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ADM-07: audit query, export and chain verification; ADM-05 break-glass
//! creation.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use authn_admin::create_break_glass_admin;
use authn_core::domain::AccountStatus;
use authn_core::ports::AuditSink;
use authn_store::UserRepository;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_07_query_filters_and_shows_justification(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (admin_id, admin) = h.admin("admin@example.com").await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    for (user, reason) in [(alice, "Alice lost phone"), (bob, "Bob asked")] {
        h.send(
            &admin,
            TestRequest::post(&format!("/v1/admin/users/{user}/revoke-sessions"))
                .json(&json!({ "reason": reason })),
        )
        .await
        .assert_status(StatusCode::OK);
    }
    let res = h
        .send(
            &admin,
            TestRequest::get(&format!(
                "/v1/admin/audit-events?kind=admin.action&subject_user_id={alice}"
            )),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["kind"], "admin.action");
    assert_eq!(items[0]["metadata"]["action"], "revoke_user_sessions");
    assert_eq!(items[0]["subject_user_id"], alice.to_string());
    assert_eq!(items[0]["actor_user_id"], admin_id.to_string());
    assert_eq!(items[0]["justification"], "Alice lost phone");

    // Keyset paging over every event: no duplicates.
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    loop {
        let uri = match &cursor {
            Some(c) => format!("/v1/admin/audit-events?limit=1&cursor={c}"),
            None => "/v1/admin/audit-events?limit=1".to_owned(),
        };
        let body: Value = h.send(&admin, TestRequest::get(&uri)).await.json();
        for item in body["items"].as_array().unwrap() {
            assert!(seen.insert(item["id"].as_str().unwrap().to_owned()));
        }
        match body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(i64::try_from(seen.len()).unwrap(), total);

    for bad in ["kind=nope", "outcome=maybe", "since=yesterday", "bogus=1"] {
        let res = h
            .send(
                &admin,
                TestRequest::get(&format!("/v1/admin/audit-events?{bad}")),
            )
            .await;
        assert!(res.status.is_client_error(), "{bad}");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_07_export_is_bounded_resumable_and_audited(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| s.audit_export_max_events = 3).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let alice = h.user("alice@example.com").await;
    for i in 0..5 {
        h.send(
            &admin,
            TestRequest::post(&format!("/v1/admin/users/{alice}/revoke-sessions"))
                .json(&json!({ "reason": format!("round {i}") })),
        )
        .await
        .assert_status(StatusCode::OK);
    }
    let filter = json!({ "subject_user_id": alice, "kind": "admin.action" });
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/audit-events/export")
                .json(&json!({ "reason": "Legal hold LH-3", "filter": filter })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert!(
        res.header("content-disposition")
            .unwrap()
            .contains("attachment")
    );
    let first: Value = res.json();
    assert_eq!(first["events"].as_array().unwrap().len(), 3);
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    let mut filter2 = filter.clone();
    filter2["cursor"] = json!(cursor);
    let second: Value = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/audit-events/export")
                .json(&json!({ "reason": "Legal hold LH-3", "filter": filter2 })),
        )
        .await
        .json();
    let ids: HashSet<String> = first["events"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["events"].as_array().unwrap())
        .map(|e| e["id"].as_str().unwrap().to_owned())
        .collect();
    // The 5 revocations, each exactly once across both parts (the first
    // export's own event is newer than the cursor and not repeated).
    assert_eq!(ids.len(), 5);
    assert!(second["next_cursor"].is_null());
    let exports = h.admin_events("audit_exported").await;
    assert_eq!(exports.len(), 2);
    assert_eq!(
        h.justification(exports[0].id).await.as_deref(),
        Some("Legal hold LH-3")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_07_chain_verification_detects_tampering(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, admin) = h.admin("admin@example.com").await;
    let alice = h.user("alice@example.com").await;
    h.send(
        &admin,
        TestRequest::post(&format!("/v1/admin/users/{alice}/suspend"))
            .json(&json!({ "reason": "x" })),
    )
    .await
    .assert_status(StatusCode::OK);
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/audit-events/verify").json(&json!({})),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let report: Value = res.json();
    assert_eq!(report["intact"], true);
    assert!(report["events_verified"].as_u64().unwrap() >= 2);
    let head = report["head"].clone();

    // From an externally kept anchor.
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/audit-events/verify").json(&json!({ "anchor": head })),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["intact"], true);
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/audit-events/verify")
                .json(&json!({ "anchor": { "seq": 1, "hash": "zz" } })),
        )
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");

    // Tamper with a stored event (as the table owner, bypassing the
    // append-only trigger).
    let mut tx = h.pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE audit_events SET metadata = '{\"action\":\"forged\"}' \
         WHERE seq = (SELECT min(seq) FROM audit_events WHERE kind = 'admin.action')",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("ALTER TABLE audit_events ENABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let res = h
        .send(
            &admin,
            TestRequest::post("/v1/admin/audit-events/verify").json(&json!({})),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let report: Value = res.json();
    assert_eq!(report["intact"], false);
    assert_eq!(report["problem"], "hash_mismatch");
    // Every verification is audited.
    assert_eq!(h.admin_events("audit_chain_verified").await.len(), 3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_break_glass_admin_creation(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let audit: Arc<dyn AuditSink> = Arc::new(authn_audit::PgAuditSink::new(
        h.pool.clone(),
        h.ports.clock.clone(),
    ));
    let created = create_break_glass_admin(
        &h.pool,
        &h.crypto.passwords,
        h.ports.clock.as_ref(),
        &audit,
        "glass@example.com",
    )
    .await
    .unwrap();
    let debug = format!("{created:?}");
    assert!(!debug.contains(created.password.expose()), "{debug}");
    // 256-bit base64url password.
    assert_eq!(created.password.expose().len(), 43);
    let record = h.record(created.user_id).await;
    assert!(record.is_platform_admin && record.is_break_glass);
    assert_eq!(record.status, AccountStatus::Active);
    assert!(record.email_verified_at.is_some());
    let stored = UserRepository::find_password(&h.pool, created.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(stored.password_hash.expose(), created.password.expose());
    assert!(
        h.crypto
            .passwords
            .verify(
                &authn_core::secret::SecretString::from(created.password.expose().to_owned()),
                Some(&authn_crypto::password::StoredPasswordHash {
                    hash: stored.password_hash.clone(),
                    algorithm: stored.algorithm.clone(),
                    pepper_version: stored.pepper_version,
                }),
            )
            .await
            .unwrap()
            .is_valid()
    );
    let events = h.admin_events("break_glass_admin_created").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["priority"], "high");
    // Two calls never share a password and an existing address is never
    // promoted.
    let second = create_break_glass_admin(
        &h.pool,
        &h.crypto.passwords,
        h.ports.clock.as_ref(),
        &audit,
        "glass2@example.com",
    )
    .await
    .unwrap();
    assert_ne!(second.password.expose(), created.password.expose());
    let user = h.user("existing@example.com").await;
    let err = create_break_glass_admin(
        &h.pool,
        &h.crypto.passwords,
        h.ports.clock.as_ref(),
        &audit,
        "existing@example.com",
    )
    .await
    .unwrap_err();
    assert_eq!(err.code().code(), "conflict");
    assert!(!h.record(user).await.is_platform_admin);
    let err = create_break_glass_admin(
        &h.pool,
        &h.crypto.passwords,
        h.ports.clock.as_ref(),
        &audit,
        "not an address",
    )
    .await
    .unwrap_err();
    assert_eq!(err.code().code(), "validation_failed");
}
