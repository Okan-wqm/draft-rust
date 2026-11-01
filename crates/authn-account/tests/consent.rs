#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Consent records: ACC-11.

mod common;

use authn_core::ports::Clock as _;

use authn_account::LoginAssessment;
use authn_core::config::account::{TermsDocument, TermsVersionConfig};
use authn_core::ports::{RequiredAction, SecurityEventKind};
use authn_testkit::http::TestRequest;
use common::Harness;
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;

fn version(
    document: TermsDocument,
    version: &str,
    at: OffsetDateTime,
    reaccept: bool,
) -> TermsVersionConfig {
    TermsVersionConfig {
        document,
        version: version.to_owned(),
        url: Some(format!(
            "https://example.com/{}/{version}",
            document.as_str()
        )),
        published_at: at,
        requires_reacceptance: reaccept,
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_11_acceptance_is_recorded_with_ip_and_user_agent(pool: PgPool) {
    let start = OffsetDateTime::UNIX_EPOCH;
    let h = Harness::with(pool, |s| {
        s.account.terms = vec![
            version(TermsDocument::TermsOfService, "1", start, false),
            version(TermsDocument::PrivacyPolicy, "1", start, false),
        ];
    })
    .await;
    h.service.sync_terms_versions().await.unwrap();
    let terms: serde_json::Value = TestRequest::get("/v1/terms").send(&h.app()).await.json();
    assert_eq!(terms["documents"].as_array().unwrap().len(), 2);

    let user = h.active_user("c@example.com").await;
    let app = h.app_as(&h.fresh(user));
    TestRequest::post("/v1/me/consents")
        .json(&json!({ "accepted": [{ "document": "terms_of_service", "version": "1" }] }))
        .header("user-agent", "ConsentBrowser/2.0")
        .peer_ip("192.0.2.44".parse().unwrap())
        .send(&app)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let (ip, ua): (Option<std::net::IpAddr>, Option<String>) =
        sqlx::query_as("SELECT ip, user_agent FROM consents WHERE user_id = $1")
            .bind(user)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(ip, Some("192.0.2.44".parse().unwrap()));
    assert_eq!(ua.as_deref(), Some("ConsentBrowser/2.0"));
    let listed: serde_json::Value = TestRequest::get("/v1/me/consents").send(&app).await.json();
    assert_eq!(listed["consents"][0]["document"], "terms_of_service");
    // Idempotent; unknown versions are refused.
    TestRequest::post("/v1/me/consents")
        .json(&json!({ "accepted": [{ "document": "terms_of_service", "version": "1" }] }))
        .send(&app)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    TestRequest::post("/v1/me/consents")
        .json(&json!({ "accepted": [{ "document": "terms_of_service", "version": "0" }] }))
        .send(&app)
        .await
        .assert_error(StatusCode::CONFLICT, "terms_version_not_current");
    TestRequest::post("/v1/me/consents")
        .json(&json!({ "accepted": [] }))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::TermsAccepted)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_11_new_version_requiring_reacceptance_is_reported_at_login(pool: PgPool) {
    let start = OffsetDateTime::UNIX_EPOCH;
    let h0 = Harness::with(pool.clone(), |s| {
        s.account.terms = vec![version(TermsDocument::TermsOfService, "1", start, false)];
    })
    .await;
    h0.service.sync_terms_versions().await.unwrap();
    let user = h0.active_user("r@example.com").await;
    h0.service
        .record_consent(
            &h0.fresh(user),
            &h0.ctx(),
            &[authn_account::TermsAcceptance {
                document: TermsDocument::TermsOfService,
                version: "1".to_owned(),
            }],
        )
        .await
        .unwrap();
    assert!(
        h0.service
            .terms_requirements(user)
            .await
            .unwrap()
            .is_empty()
    );

    // Version 2 is published and requires re-acceptance.
    let later = h0.ports.clock.now() - time::Duration::hours(1);
    let h = Harness::with(pool.clone(), |s| {
        s.account.terms = vec![
            version(TermsDocument::TermsOfService, "1", start, false),
            version(TermsDocument::TermsOfService, "2", later, true),
        ];
    })
    .await;
    h.service.sync_terms_versions().await.unwrap();
    let pending = h.service.terms_requirements(user).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].version, "2");
    let record = h.user_by_id(user).await.unwrap();
    match h.service.assess_login(&record).await.unwrap() {
        LoginAssessment::Allowed {
            required_actions, ..
        } => assert_eq!(required_actions, vec![RequiredAction::AcceptTerms]),
        other @ LoginAssessment::Denied(_) => panic!("{other:?}"),
    }
    // The login flow completes the required action.
    h.service
        .accept_terms(
            &h.ctx(),
            user,
            &[authn_account::TermsAcceptance {
                document: TermsDocument::TermsOfService,
                version: "2".to_owned(),
            }],
        )
        .await
        .unwrap();
    assert!(h.service.terms_requirements(user).await.unwrap().is_empty());

    // With re-acceptance switched off nothing is required.
    let off = Harness::with(pool, |s| s.account.reaccept_terms_on_new_version = false).await;
    let other = off.active_user("o@example.com").await;
    assert!(
        off.service
            .terms_requirements(other)
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_11_users_without_any_acceptance_are_asked_when_required(pool: PgPool) {
    let start = OffsetDateTime::UNIX_EPOCH;
    let h = Harness::with(pool, |s| {
        s.account.require_terms_acceptance = true;
        s.account.terms = vec![version(TermsDocument::PrivacyPolicy, "2026", start, false)];
    })
    .await;
    h.service.sync_terms_versions().await.unwrap();
    // E.g. an account created through social login (no signup form).
    let user = authn_core::id::UserId::generate();
    let mut conn = h.pool.acquire().await.unwrap();
    authn_store::UserRepository::create(
        &mut conn,
        &authn_store::NewUser {
            id: user,
            email: authn_core::domain::EmailAddress::parse("social@example.com").unwrap(),
            status: authn_core::domain::AccountStatus::Active,
            created_at: h.ports.clock.now(),
        },
    )
    .await
    .unwrap();
    let pending = h.service.terms_requirements(user).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].document, TermsDocument::PrivacyPolicy);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_11_future_versions_are_not_current_yet(pool: PgPool) {
    let h0 = Harness::new(pool.clone()).await;
    let future = h0.ports.clock.now() + time::Duration::days(3);
    let h = Harness::with(pool, |s| {
        s.account.terms = vec![
            version(
                TermsDocument::TermsOfService,
                "now",
                OffsetDateTime::UNIX_EPOCH,
                false,
            ),
            version(TermsDocument::TermsOfService, "next", future, true),
        ];
    })
    .await;
    h.service.sync_terms_versions().await.unwrap();
    let current = h.service.current_terms().await.unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].version, "now");
}
