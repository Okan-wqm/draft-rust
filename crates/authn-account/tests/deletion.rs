#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Account deletion: ACC-09.

mod common;

use authn_core::ports::Clock as _;

use std::time::Duration;

use authn_core::domain::AccountStatus;
use authn_core::id::{OrgId, UserId};
use authn_core::ports::{DomainEventKind, NotificationKind, SecurityEventKind};
use authn_testkit::http::TestRequest;
use common::{Harness, secret};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

fn cancel_token(h: &Harness, email: &str) -> String {
    match h
        .mails("account_deletion_scheduled", email)
        .pop()
        .unwrap()
        .kind
    {
        NotificationKind::AccountDeletionScheduled { cancel_token, .. } => {
            cancel_token.expose().to_owned()
        }
        other => panic!("{other:?}"),
    }
}

/// Personal rows of other modules referencing the user (to prove the
/// cascade).
async fn seed_module_data(h: &Harness, user: UserId) {
    let now = h.ports.clock.now();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, client_kind, token_hash, amr, auth_time, user_agent, \
         created_ip, created_at, last_seen_at, idle_expires_at, absolute_expires_at) \
         VALUES ($1, $2, 'web', $3, ARRAY['pwd'], $4, 'UA', '203.0.113.5', $4, $4, $5, $5)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(user)
    .bind(vec![7_u8; 32])
    .bind(now)
    .bind(now + time::Duration::hours(1))
    .execute(&h.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO terms_versions (id, document, version, published_at) VALUES ($1, 'terms_of_service', 'v1', $2)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(now - time::Duration::days(1))
    .execute(&h.pool)
    .await
    .unwrap();
    let mut principal = h.fresh(user);
    principal.auth_time = Some(now);
    h.service
        .record_consent(
            &principal,
            &h.ctx(),
            &[authn_account::TermsAcceptance {
                document: authn_core::config::account::TermsDocument::TermsOfService,
                version: "v1".to_owned(),
            }],
        )
        .await
        .unwrap();
}

async fn personal_rows(h: &Harness, user: UserId) -> i64 {
    let mut total = 0;
    for sql in [
        "SELECT count(*) FROM users WHERE id = $1",
        "SELECT count(*) FROM user_profiles WHERE user_id = $1",
        "SELECT count(*) FROM password_credentials WHERE user_id = $1",
        "SELECT count(*) FROM one_time_tokens WHERE user_id = $1",
        "SELECT count(*) FROM consents WHERE user_id = $1",
        "SELECT count(*) FROM sessions WHERE user_id = $1",
        "SELECT count(*) FROM email_reservations WHERE user_id = $1",
    ] {
        total += h.count(sql, user).await;
    }
    total
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_deletion_requires_step_up_and_a_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("del@example.com").await;
    TestRequest::delete("/v1/me")
        .send(&h.app_as(&h.stale(user)))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    let mut api_key = h.fresh(user);
    api_key.credential = authn_core::domain::PrincipalCredential::ApiKey {
        api_key_id: authn_core::id::ApiKeyId::generate(),
    };
    TestRequest::delete("/v1/me")
        .send(&h.app_as(&api_key))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_deletion_is_scheduled_with_grace_period_and_cancel_link(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("del@example.com").await;
    let app = h.app_as(&h.fresh(user));
    let res = TestRequest::delete("/v1/me").send(&app).await;
    res.assert_status(StatusCode::ACCEPTED);
    let view: serde_json::Value = res.json();
    assert_eq!(view["status"], "scheduled");
    let expected = h.ports.clock.now() + time::Duration::days(30);
    let scheduled = time::OffsetDateTime::parse(
        view["scheduled_for"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(scheduled, expected);
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::PendingDeletion
    );
    // Idempotent: the second request returns the same schedule, no new mail.
    let again: serde_json::Value = TestRequest::delete("/v1/me").send(&app).await.json();
    assert_eq!(again["scheduled_for"], view["scheduled_for"]);
    assert_eq!(
        h.mails("account_deletion_scheduled", "del@example.com")
            .len(),
        1
    );
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountDeletionScheduled)
            .len(),
        1
    );
    let status: serde_json::Value = TestRequest::get("/v1/me/deletion").send(&app).await.json();
    assert_eq!(status["scheduled_for"], view["scheduled_for"]);

    // Cancel with the e-mailed link.
    let token = cancel_token(&h, "del@example.com");
    TestRequest::post("/v1/account/deletion/cancel")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
    assert_eq!(
        h.mails("account_deletion_cancelled", "del@example.com")
            .len(),
        1
    );
    TestRequest::post("/v1/account/deletion/cancel")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
    TestRequest::get("/v1/me/deletion")
        .send(&app)
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_signed_in_cancel_restores_previous_status(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("back@example.com").await;
    let app = h.app_as(&h.fresh(user));
    TestRequest::post("/v1/me/deletion/cancel")
        .send(&app)
        .await
        .assert_error(StatusCode::CONFLICT, "account_deletion_not_scheduled");
    TestRequest::delete("/v1/me")
        .send(&app)
        .await
        .assert_status(StatusCode::ACCEPTED);
    TestRequest::post("/v1/me/deletion/cancel")
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
    // The old cancel link is revoked.
    let token = cancel_token(&h, "back@example.com");
    assert!(
        h.service
            .cancel_deletion_with_link(&h.ctx(), &secret(&token))
            .await
            .is_err()
    );
    let changes = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountStatusChanged);
    let to: Vec<_> = changes.iter().map(|e| e.metadata["to"].clone()).collect();
    assert_eq!(
        to,
        vec![json!("active"), json!("pending_deletion"), json!("active")]
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_last_owner_cannot_delete(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("owner@example.com").await;
    let org = OrgId::generate();
    h.ownership.0.lock().unwrap().insert(user, vec![org]);
    let err = TestRequest::delete("/v1/me")
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_error(StatusCode::CONFLICT, "account_deletion_blocked_last_owner");
    assert_eq!(err.details.unwrap()["organization_ids"][0], org.to_string());
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_purge_after_grace_period_erases_everything(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("gone@example.com").await;
    let survivor = h.active_user("stay@example.com").await;
    seed_module_data(&h, user).await;
    h.service
        .request_deletion(&h.fresh(user), &h.ctx())
        .await
        .unwrap();
    assert!(personal_rows(&h, user).await > 4);

    // Not before the grace period ends.
    h.ports.clock.advance(Duration::from_secs(29 * 86_400));
    assert_eq!(h.service.purge_due_deletions(10).await.unwrap().purged, 0);
    assert!(h.user_by_id(user).await.is_some());

    h.ports.clock.advance(Duration::from_secs(86_400 + 1));
    let report = h.service.purge_due_deletions(10).await.unwrap();
    assert_eq!(report.purged, 1);
    assert_eq!(
        personal_rows(&h, user).await,
        0,
        "cascade removed every row"
    );
    assert!(h.user_by_id(survivor).await.is_some());
    // The request record remains as proof of erasure, without personal data.
    let (status,): (String,) =
        sqlx::query_as("SELECT status FROM account_deletions WHERE user_id = $1")
            .bind(user)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(status, "completed");
    // Audit trail pseudonymised, deletion recorded, webhook event published.
    assert_eq!(h.audit.pseudonymized.lock().unwrap().as_slice(), &[user]);
    let deleted = h.audit.events.of_kind(SecurityEventKind::AccountDeleted);
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].metadata.get("email").is_none());
    assert!(
        h.ports
            .events
            .recorded()
            .iter()
            .any(|e| e.kind == DomainEventKind::UserDeleted && e.user_id == Some(user))
    );
    // The address can be registered again by someone else.
    h.signup("gone@example.com").await;
    assert!(h.user("gone@example.com").await.is_some());
    // Idempotent job.
    assert_eq!(h.service.purge_due_deletions(10).await.unwrap().purged, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_purge_postpones_users_who_became_last_owner(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("late-owner@example.com").await;
    let other = h.active_user("normal@example.com").await;
    for u in [user, other] {
        h.service
            .request_deletion(&h.fresh(u), &h.ctx())
            .await
            .unwrap();
    }
    // Another owner left the organization during the grace period.
    h.ownership
        .0
        .lock()
        .unwrap()
        .insert(user, vec![OrgId::generate()]);
    h.ports.clock.advance(Duration::from_secs(31 * 86_400));
    let report = h.service.purge_due_deletions(10).await.unwrap();
    assert_eq!(report.purged, 1);
    assert_eq!(report.blocked, 1);
    assert!(h.user_by_id(user).await.is_some());
    assert!(h.user_by_id(other).await.is_none());
    assert!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountDeleted)
            .iter()
            .any(|e| e.reason.as_deref() == Some("last_owner"))
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_concurrent_purge_jobs_delete_each_account_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let mut users = Vec::new();
    for i in 0..4 {
        let u = h.active_user(&format!("p{i}@example.com")).await;
        h.service
            .request_deletion(&h.fresh(u), &h.ctx())
            .await
            .unwrap();
        users.push(u);
    }
    h.ports.clock.advance(Duration::from_secs(31 * 86_400));
    let mut handles = Vec::new();
    for _ in 0..3 {
        let service = h.service.clone();
        handles.push(tokio::spawn(async move {
            service.purge_due_deletions(10).await
        }));
    }
    let mut purged = 0;
    for handle in handles {
        purged += handle.await.unwrap().unwrap().purged;
    }
    assert_eq!(purged, 4);
    assert_eq!(h.audit.pseudonymized.lock().unwrap().len(), 4);
    for u in users {
        assert!(h.user_by_id(u).await.is_none());
    }
}
