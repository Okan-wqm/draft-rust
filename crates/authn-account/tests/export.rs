#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Personal data export: ACC-10.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_account::{AccountService, AccountServiceDeps};
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{DataExporter, RateLimitPolicy, SecurityEventKind};
use authn_testkit::fakes::StaticDataExporter;
use authn_testkit::http::TestRequest;
use common::{Harness, Options};
use http::StatusCode;
use serde_json::json;
use sqlx::{PgConnection, PgPool};

/// An exporter that reads real data through the shared connection.
struct SessionsExporter;

#[async_trait]
impl DataExporter for SessionsExporter {
    fn section(&self) -> &'static str {
        "sessions"
    }

    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE user_id = $1")
            .bind(user)
            .fetch_one(conn)
            .await?;
        Ok(json!({ "count": n }))
    }
}

/// An exporter that tries to write (must be refused: read-only snapshot).
struct WritingExporter;

#[async_trait]
impl DataExporter for WritingExporter {
    fn section(&self) -> &'static str {
        "writer"
    }

    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
            .bind(user)
            .execute(conn)
            .await?;
        Ok(json!({}))
    }
}

fn exporters() -> Vec<Arc<dyn DataExporter>> {
    vec![
        Arc::new(StaticDataExporter {
            section: "mfa",
            value: json!({ "factors": [{ "kind": "totp" }] }),
        }),
        Arc::new(SessionsExporter),
    ]
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_export_contains_every_registered_section_and_no_secrets(pool: PgPool) {
    let h = Harness::build(
        pool,
        Options {
            exporters: exporters(),
            ..Options::default()
        },
        |_| {},
    )
    .await;
    let user = h.active_user("me@example.com").await;
    h.service
        .update_profile(
            &h.fresh(user),
            serde_json::from_value(json!({ "display_name": "Me Myself" })).unwrap(),
        )
        .await
        .unwrap();
    let res = TestRequest::post("/v1/me/export")
        .send(&h.app_as(&h.fresh(user)))
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    assert!(
        res.header("content-disposition")
            .unwrap()
            .starts_with("attachment")
    );
    let doc: serde_json::Value = res.json();
    assert_eq!(doc["format"], "rust-authentication/personal-data-export/v1");
    assert_eq!(doc["user_id"], user.to_string());
    let sections = doc["sections"].as_object().unwrap();
    let mut names: Vec<&str> = sections.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["account", "mfa", "sessions"]);
    let account = &doc["sections"]["account"];
    assert_eq!(account["user"]["email"], "me@example.com");
    assert_eq!(account["user"]["status"], "active");
    assert_eq!(account["profile"]["display_name"], "Me Myself");
    assert_eq!(account["password"]["set"], true);
    assert_eq!(doc["sections"]["mfa"]["factors"][0]["kind"], "totp");
    assert_eq!(doc["sections"]["sessions"]["count"], 0);
    // No secret material anywhere in the document.
    let text = res.text();
    for forbidden in ["$argon2", "password_hash", "token_hash", "\"hash\""] {
        assert!(!text.contains(forbidden), "{forbidden} leaked");
    }
    let audited = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountDataExported);
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].subject_user, Some(user));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_export_requires_step_up_and_is_rate_limited(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.export_per_user = RateLimitPolicy::new(2, Duration::from_secs(86_400));
    })
    .await;
    let user = h.active_user("rl@example.com").await;
    TestRequest::post("/v1/me/export")
        .send(&h.app_as(&h.stale(user)))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    let app = h.app_as(&h.fresh(user));
    for _ in 0..2 {
        TestRequest::post("/v1/me/export")
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
    }
    TestRequest::post("/v1/me/export")
        .send(&app)
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_failing_or_writing_exporter_fails_the_whole_export(pool: PgPool) {
    let h = Harness::build(
        pool,
        Options {
            exporters: vec![Arc::new(WritingExporter)],
            ..Options::default()
        },
        |_| {},
    )
    .await;
    let user = h.active_user("w@example.com").await;
    let before = h.user_by_id(user).await.unwrap().last_login_at;
    let res = TestRequest::post("/v1/me/export")
        .send(&h.app_as(&h.fresh(user)))
        .await;
    res.assert_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    assert_eq!(h.user_by_id(user).await.unwrap().last_login_at, before);
    assert!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountDataExported)
            .is_empty()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_duplicate_or_reserved_sections_are_refused_at_startup(pool: PgPool) {
    let h = Harness::new(pool).await;
    let make = |exporters: Vec<Arc<dyn DataExporter>>| {
        let deps = AccountServiceDeps {
            pool: h.pool.clone(),
            clock: h.ports.clock.clone(),
            hasher: h.crypto.passwords.clone(),
            otp: h.crypto.otp.clone(),
            rate_limiter: h.ports.rate_limiter.clone(),
            captcha: h.ports.captcha.clone(),
            password_validator: h.ports.password_validator.clone(),
            notifier: h.ports.notifier.clone(),
            audit: h.audit.clone(),
            events: h.ports.events.clone(),
            sessions: h.ports.session_revoker.clone(),
            exporters,
            ownership: h.ownership.clone(),
        };
        AccountService::new(deps, h.settings.clone())
    };
    let s = |section: &'static str| -> Arc<dyn DataExporter> {
        Arc::new(StaticDataExporter {
            section,
            value: json!(null),
        })
    };
    assert!(make(vec![s("mfa"), s("mfa")]).is_err());
    assert!(make(vec![s("account")]).is_err());
    assert!(make(vec![s("Bad-Name")]).is_err());
    assert!(make(vec![s("mfa"), s("sessions")]).is_ok());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_k58_export_is_a_post_never_a_get(pool: PgPool) {
    // K-58 audit: a GET is a "safe" method — no CSRF check, sent with the
    // session cookie on cross-site top-level navigations and link
    // prefetches — so a third-party page could spend the victim's daily
    // export quota (and produce exports nobody asked for).
    let h = Harness::new(pool).await;
    let user = h.active_user("get@example.com").await;
    let app = h.app_as(&h.fresh(user));
    TestRequest::get("/v1/me/export")
        .send(&app)
        .await
        .assert_status(StatusCode::METHOD_NOT_ALLOWED);
    TestRequest::post("/v1/me/export")
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
}
