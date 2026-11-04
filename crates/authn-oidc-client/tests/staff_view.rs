#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-14 (ADM-03, ADM-08) end to end with the real audit sink and the
//! user's own security-event view (`GET /v1/me/security-events`): when a
//! platform administrator marks an address verified, the user sees a
//! `system` action — neither the administrator's identity nor the network
//! of the administrator's IP.

mod common;

use std::sync::Arc;
use std::time::Duration;

use authn_account::{AccountService, AccountServiceDeps, AccountServiceSettings, MailboxProof};
use authn_audit::PgAuditSink;
use authn_audit::query::list_user_security_events;
use authn_core::domain::{AccountStatus, PageRequest};
use authn_core::ports::Clock as _;
use common::Harness;
use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_03_admin_verification_shows_no_staff_identity_in_the_users_view(pool: PgPool) {
    let h = Harness::new(pool).await;
    let sink = Arc::new(PgAuditSink::new(h.pool.clone(), h.ports.clock.clone()));
    let accounts = AccountService::new(
        AccountServiceDeps {
            pool: h.pool.clone(),
            clock: h.ports.clock.clone(),
            hasher: h.crypto.passwords.clone(),
            otp: h.crypto.otp.clone(),
            rate_limiter: h.ports.rate_limiter.clone(),
            captcha: h.ports.captcha.clone(),
            password_validator: h.ports.password_validator.clone(),
            notifier: h.ports.notifier.clone(),
            audit: sink,
            events: h.ports.events.clone(),
            sessions: h.ports.session_revoker.clone(),
            exporters: Vec::new(),
            ownership: Arc::new(authn_account::NoOrganizations),
        },
        AccountServiceSettings::from_app_config(&h.config).unwrap(),
    )
    .unwrap();
    let user = h
        .user(
            "member@example.com",
            AccountStatus::PendingVerification,
            false,
        )
        .await;
    let admin = h
        .user("admin@example.com", AccountStatus::Active, true)
        .await;
    let ctx = h.ctx(); // the administrator's request (203.0.113.10)

    let mut tx = h.pool.begin().await.unwrap();
    accounts
        .confirm_mailbox_control_in_tx(
            &mut tx,
            Some(&ctx),
            user,
            MailboxProof::Administrator { admin },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let page = list_user_security_events(
        &h.pool,
        user,
        h.ports.clock.now() + time::Duration::seconds(1),
        Duration::from_secs(3600),
        &PageRequest::default(),
    )
    .await
    .unwrap();
    let views: Vec<Value> = page
        .items
        .iter()
        .map(|v| serde_json::to_value(v).unwrap())
        .collect();
    let kinds: Vec<&str> = views.iter().map(|v| v["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"account.email_verified"), "{kinds:?}");
    assert!(kinds.contains(&"account.status_changed"), "{kinds:?}");
    let text = serde_json::to_string(&views).unwrap();
    assert!(!text.contains("203.0.113"), "staff IP visible: {text}");
    assert!(
        !text.contains(&admin.to_string()),
        "staff id visible: {text}"
    );
    for view in &views {
        assert_eq!(view["actor"], "system", "{view}");
        assert!(view["ip"].is_null(), "{view}");
        assert!(view["user_agent"].is_null(), "{view}");
    }

    // The administrator's own list does not show the user's events as theirs.
    let admin_page = list_user_security_events(
        &h.pool,
        admin,
        h.ports.clock.now() + time::Duration::seconds(1),
        Duration::from_secs(3600),
        &PageRequest::default(),
    )
    .await
    .unwrap();
    assert!(admin_page.items.is_empty());
}
