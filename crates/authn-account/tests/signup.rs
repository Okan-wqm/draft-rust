#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Registration: ACC-01, ACC-02, ACC-03, ACC-12, ACC-13.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use authn_account::{DisposableDomains, REGISTRATION_COOKIE};
use authn_core::config::common::CaptchaPolicy;
use authn_core::domain::AccountStatus;
use authn_core::ports::{CaptchaVerdict, DomainEventKind, RateLimitPolicy, SecurityEventKind};
use authn_testkit::http::TestRequest;
use authn_testkit::timing::TimingReport;
use common::{Harness, Options, PASSWORD, PASSWORD_2};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

fn body(email: &str, password: &str) -> serde_json::Value {
    json!({ "email": email, "password": password })
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_01_signup_creates_pending_account_with_hashed_password(pool: PgPool) {
    let h = Harness::new(pool).await;
    let res = TestRequest::post("/v1/signup")
        .json(&json!({
            "email": "  Alice@Example.COM ",
            "password": PASSWORD,
            "display_name": "Alice  Smith",
            "locale": "tr",
            "time_zone": "europe/istanbul"
        }))
        .send(&h.app())
        .await;
    res.assert_status(StatusCode::ACCEPTED);
    let answer = res.json::<serde_json::Value>();
    assert_eq!(answer["status"], "accepted");
    let handle = answer["registration"].as_str().unwrap().to_owned();
    assert_eq!(handle.len(), 43, "256-bit handle");
    // The same handle in a host-only, script-inaccessible, same-site cookie.
    let cookies = res.set_cookies();
    assert_eq!(cookies.len(), 1);
    let cookie = &cookies[0];
    assert!(cookie.starts_with(&format!("{REGISTRATION_COOKIE}={handle};")));
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Max-Age=604800",
    ] {
        assert!(cookie.contains(attribute), "{cookie}");
    }
    assert!(!cookie.contains("Domain"), "{cookie}");
    assert_eq!(res.header("cache-control"), Some("no-store"));
    h.drain().await;

    let user = h.user("alice@example.com").await.expect("user created");
    assert_eq!(user.status, AccountStatus::PendingVerification);
    assert_eq!(user.email.as_deref(), Some("Alice@example.com"));
    assert_eq!(user.email_normalized.as_deref(), Some("alice@example.com"));
    assert!(user.email_verified_at.is_none());
    // No credential and no profile before the address is proven (ADR 0002):
    // the registration holds them (Argon2id hash, never the password).
    assert!(
        authn_store::UserRepository::find_password(&h.pool, user.id)
            .await
            .unwrap()
            .is_none()
    );
    let before = h.service.profile_of(user.id).await.unwrap().unwrap();
    assert_eq!(before.display_name, None, "not applied before verification");
    let (hash, handle_hash): (String, Vec<u8>) = sqlx::query_as(
        "SELECT password_hash, handle_hash FROM pending_registrations WHERE user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(!hash.contains(PASSWORD));
    assert_eq!(
        handle_hash,
        authn_crypto::token::OpaqueToken::parse(&handle)
            .unwrap()
            .hash()
            .as_bytes()
            .to_vec()
    );

    let mails = h.mails("email_verification", "alice@example.com");
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].locale, authn_core::domain::Locale::Tr);
    let events = h.ports.events.recorded();
    assert!(
        events
            .iter()
            .any(|e| e.kind == DomainEventKind::UserCreated && e.user_id == Some(user.id))
    );
    let audited = h.audit.events.of_kind(SecurityEventKind::AccountRegistered);
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].subject_user, Some(user.id));

    // The registering browser (cookie) opens the link: the submitted
    // password and profile become the account's.
    let (token, _) = h.verification("alice@example.com");
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .cookie(REGISTRATION_COOKIE, &handle)
        .send(&h.app())
        .await
        .assert_status(StatusCode::OK);
    assert!(h.password_matches(user.id, PASSWORD).await);
    let profile = h.service.profile_of(user.id).await.unwrap().unwrap();
    assert_eq!(profile.display_name.as_deref(), Some("Alice Smith"));
    assert_eq!(profile.locale, authn_core::domain::Locale::Tr);
    assert_eq!(profile.time_zone, "Europe/Istanbul");
    assert_eq!(
        h.user("alice@example.com").await.unwrap().status,
        AccountStatus::Active
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_01_password_policy_is_enforced_through_the_validator_port(pool: PgPool) {
    let h = Harness::new(pool).await;
    let res = TestRequest::post("/v1/signup")
        .json(&body("bob@example.com", "Xq9!zv"))
        .send(&h.app())
        .await;
    let err = res.assert_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "password_policy_violation",
    );
    assert_eq!(err.details.unwrap()["violations"][0]["code"], "too_short");
    assert!(
        !res.text().contains("Xq9!zv"),
        "password must not be echoed"
    );
    h.ports.password_validator.add_weak("weak but long enough");
    TestRequest::post("/v1/signup")
        .json(&body("bob@example.com", "weak but long enough"))
        .send(&h.app())
        .await
        .assert_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "password_policy_violation",
        );
    h.drain().await;
    assert!(h.user("bob@example.com").await.is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_01_invalid_input_is_rejected_without_echoing_secrets(pool: PgPool) {
    let h = Harness::new(pool).await;
    TestRequest::post("/v1/signup")
        .json(&body("not-an-address", PASSWORD))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_email");
    // A numeric "password" makes serde fail with the value in its message;
    // the response (and the logged context) must not contain it.
    let res = TestRequest::post("/v1/signup")
        .json(&json!({ "email": "c@example.com", "password": 987654321 }))
        .send(&h.app())
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert!(!res.text().contains("987654321"));
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "c@example.com", "password": PASSWORD, "admin": true }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    TestRequest::post("/v1/signup")
        .body("{\"email\":")
        .header("content-type", "application/json")
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "bad_request");
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "c@example.com", "password": PASSWORD, "display_name": "\u{202E}evil" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_display_name");
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "c@example.com", "password": PASSWORD, "time_zone": "Mars/Base" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_time_zone");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_existing_address_gets_identical_status_and_body(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.active_user("owner@example.com").await;
    h.ports.notifier.take();

    let new = TestRequest::post("/v1/signup")
        .json(&body("fresh@example.com", PASSWORD))
        .send(&h.app())
        .await;
    let existing = TestRequest::post("/v1/signup")
        .json(&body("OWNER@example.com", PASSWORD_2))
        .send(&h.app())
        .await;
    assert_eq!(new.status, existing.status);
    // Same shape; the handle is fresh random data either way.
    let shape = |r: &authn_testkit::http::TestResponse| {
        let mut body = r.json::<serde_json::Value>();
        let handle = body["registration"].take();
        assert_eq!(handle.as_str().map(str::len), Some(43));
        let cookies = r.set_cookies();
        assert_eq!(cookies.len(), 1);
        let cookie = cookies[0].replace(handle.as_str().unwrap(), "<handle>");
        (body, cookie)
    };
    assert_eq!(shape(&new), shape(&existing));
    assert_ne!(
        new.json::<serde_json::Value>()["registration"],
        existing.json::<serde_json::Value>()["registration"]
    );
    let headers = |r: &authn_testkit::http::TestResponse| {
        let mut names: Vec<String> = r
            .headers
            .keys()
            .map(|k| k.as_str().to_owned())
            .filter(|k| k != "x-request-id")
            .collect();
        names.sort();
        names
    };
    assert_eq!(headers(&new), headers(&existing));
    h.drain().await;

    // The owner is told, the password is untouched, no verification is sent.
    let notices = h.mails("registration_attempt", "owner@example.com");
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].recipient.user_id, Some(owner));
    assert!(
        h.mails("email_verification", "owner@example.com")
            .is_empty()
    );
    assert!(h.password_matches(owner, PASSWORD).await);
    assert!(!h.password_matches(owner, PASSWORD_2).await);
    let attempts = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountRegistrationAttemptExisting);
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].subject_user, Some(owner));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_signup_timing_does_not_reveal_existing_accounts(pool: PgPool) {
    // Production Argon2 parameters: the hash dominates and is computed on
    // both paths; the account-specific work runs in the background.
    let h = Harness::build(
        pool,
        Options {
            production_argon2: true,
            ..Options::default()
        },
        |_| {},
    )
    .await;
    h.active_user("taken@example.com").await;
    let app = h.app();
    let samples = 15;
    let mut new_times = Vec::with_capacity(samples);
    let mut existing_times = Vec::with_capacity(samples);
    let send = |email: String| {
        let app = app.clone();
        async move {
            let started = Instant::now();
            let res = TestRequest::post("/v1/signup")
                .json(&body(&email, PASSWORD))
                .send(&app)
                .await;
            res.assert_status(StatusCode::ACCEPTED);
            started.elapsed()
        }
    };
    // Warm-up.
    for i in 0..3 {
        send(format!("warm{i}@example.com")).await;
        h.drain().await;
    }
    for i in 0..samples {
        let (a, b) = if i % 2 == 0 {
            let a = send(format!("new{i}@example.com")).await;
            h.drain().await;
            let b = send("taken@example.com".to_owned()).await;
            (a, b)
        } else {
            let b = send("taken@example.com".to_owned()).await;
            h.drain().await;
            let a = send(format!("new{i}@example.com")).await;
            (a, b)
        };
        h.drain().await;
        new_times.push(a);
        existing_times.push(b);
    }
    new_times.sort_unstable();
    existing_times.sort_unstable();
    let report = TimingReport {
        samples,
        median_a: new_times[samples / 2],
        median_b: existing_times[samples / 2],
    };
    report.assert_indistinguishable(0.3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_registration_notices_are_throttled_per_address(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.registration_notice_per_email =
            RateLimitPolicy::new(2, Duration::from_secs(86_400));
    })
    .await;
    h.active_user("victim@example.com").await;
    for _ in 0..5 {
        h.signup("victim@example.com").await;
    }
    assert_eq!(
        h.mails("registration_attempt", "victim@example.com").len(),
        2
    );
    let attempts = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountRegistrationAttemptExisting);
    assert_eq!(attempts.len(), 5, "every attempt is audited");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_03_addresses_differing_only_in_case_or_width_are_the_same_account(pool: PgPool) {
    let h = Harness::new(pool).await;
    let id = h.active_user("Zeynep@Example.com").await;
    for variant in [
        "zeynep@EXAMPLE.com",
        "ＺＥＹＮＥＰ＠example.com",
        " zeynep@example.com ",
    ] {
        h.signup(variant).await;
    }
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        h.mails("registration_attempt", "zeynep@example.com").len(),
        3
    );
    assert!(h.password_matches(id, PASSWORD).await);
    // Homograph addresses are rejected outright.
    TestRequest::post("/v1/signup")
        .json(&body("zeyn\u{0435}p@example.com", PASSWORD))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_email");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_12_disposable_domains_are_rejected(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.disposable_domains = Some(Arc::new(DisposableDomains::from_domains([
            "mailinator.com",
        ])));
    })
    .await;
    for email in ["x@mailinator.com", "x@sub.MAILINATOR.com"] {
        TestRequest::post("/v1/signup")
            .json(&body(email, PASSWORD))
            .send(&h.app())
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "email_domain_not_allowed");
    }
    TestRequest::post("/v1/signup")
        .json(&body("x@example.com", PASSWORD))
        .send(&h.app())
        .await
        .assert_status(StatusCode::ACCEPTED);
    h.drain().await;
    assert!(h.user("x@mailinator.com").await.is_none());
    assert!(h.user("x@example.com").await.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_12_block_list_is_disabled_by_default(pool: PgPool) {
    let h = Harness::new(pool).await;
    assert!(h.settings.disposable_domains.is_none());
    h.signup("x@mailinator.com").await;
    assert!(h.user("x@mailinator.com").await.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_13_captcha_always_policy(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.registration_captcha = CaptchaPolicy::Always;
    })
    .await;
    let res = TestRequest::post("/v1/signup")
        .json(&body("a@example.com", PASSWORD))
        .send(&h.app())
        .await;
    let err = res.assert_error(StatusCode::FORBIDDEN, "captcha_required");
    assert_eq!(err.details.unwrap()["captcha"]["type"], "widget");
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "a@example.com", "password": PASSWORD, "captcha": "wrong" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::FORBIDDEN, "captcha_failed");
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::CaptchaFailed)
            .len(),
        1
    );
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "a@example.com", "password": PASSWORD, "captcha": "pass" }))
        .send(&h.app())
        .await
        .assert_status(StatusCode::ACCEPTED);
    h.drain().await;
    assert!(h.user("a@example.com").await.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_13_risk_based_captcha_kicks_in_after_threshold(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.registration_captcha = CaptchaPolicy::RiskBased;
        s.account.registration_captcha_free_per_ip =
            RateLimitPolicy::new(2, Duration::from_secs(3600));
    })
    .await;
    for i in 0..2 {
        TestRequest::post("/v1/signup")
            .json(&body(&format!("u{i}@example.com"), PASSWORD))
            .send(&h.app())
            .await
            .assert_status(StatusCode::ACCEPTED);
    }
    TestRequest::post("/v1/signup")
        .json(&body("u3@example.com", PASSWORD))
        .send(&h.app())
        .await
        .assert_error(StatusCode::FORBIDDEN, "captcha_required");
    // Another IP is not affected.
    TestRequest::post("/v1/signup")
        .json(&body("u4@example.com", PASSWORD))
        .peer_ip("192.0.2.99".parse().unwrap())
        .send(&h.app())
        .await
        .assert_status(StatusCode::ACCEPTED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_13_unavailable_provider_fails_closed_unless_configured(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.registration_captcha = CaptchaPolicy::Always;
    })
    .await;
    h.ports.captcha.force(Some(CaptchaVerdict::Unavailable));
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "a@example.com", "password": PASSWORD, "captcha": "pass" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable");

    let open = Harness::with(h.pool.clone(), |s| {
        s.account.registration_captcha = CaptchaPolicy::Always;
        s.captcha_fail_open = true;
    })
    .await;
    open.ports.captcha.force(Some(CaptchaVerdict::Unavailable));
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "a@example.com", "password": PASSWORD, "captcha": "pass" }))
        .send(&open.app())
        .await
        .assert_status(StatusCode::ACCEPTED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_01_registrations_are_rate_limited_per_ip(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.registration_per_ip = RateLimitPolicy::new(2, Duration::from_secs(3600));
    })
    .await;
    for i in 0..2 {
        TestRequest::post("/v1/signup")
            .json(&body(&format!("r{i}@example.com"), PASSWORD))
            .send(&h.app())
            .await
            .assert_status(StatusCode::ACCEPTED);
    }
    let res = TestRequest::post("/v1/signup")
        .json(&body("r3@example.com", PASSWORD))
        .send(&h.app())
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_11_signup_records_terms_acceptance_when_required(pool: PgPool) {
    use authn_core::config::account::{TermsDocument, TermsVersionConfig};
    let published = time::OffsetDateTime::UNIX_EPOCH;
    let h = Harness::with(pool, |s| {
        s.account.require_terms_acceptance = true;
        s.account.terms = vec![
            TermsVersionConfig {
                document: TermsDocument::TermsOfService,
                version: "2026-01".to_owned(),
                url: Some("https://example.com/terms".to_owned()),
                published_at: published,
                requires_reacceptance: false,
            },
            TermsVersionConfig {
                document: TermsDocument::PrivacyPolicy,
                version: "2026-02".to_owned(),
                url: None,
                published_at: published,
                requires_reacceptance: false,
            },
        ];
    })
    .await;
    assert_eq!(h.service.sync_terms_versions().await.unwrap(), 2);
    assert_eq!(
        h.service.sync_terms_versions().await.unwrap(),
        0,
        "idempotent"
    );

    let res = TestRequest::post("/v1/signup")
        .json(&body("t@example.com", PASSWORD))
        .send(&h.app())
        .await;
    res.assert_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "terms_acceptance_required",
    );
    TestRequest::post("/v1/signup")
        .json(&json!({ "email": "t@example.com", "password": PASSWORD,
            "accepted_terms": [{ "document": "terms_of_service", "version": "2025-01" }] }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::CONFLICT, "terms_version_not_current");
    let res = TestRequest::post("/v1/signup")
        .json(&json!({ "email": "t@example.com", "password": PASSWORD,
            "accepted_terms": [
                { "document": "terms_of_service", "version": "2026-01" },
                { "document": "privacy_policy", "version": "2026-02" }
            ] }))
        .header("user-agent", "Mozilla/5.0 test")
        .send(&h.app())
        .await;
    res.assert_status(StatusCode::ACCEPTED);
    let handle = res.json::<serde_json::Value>()["registration"]
        .as_str()
        .unwrap()
        .to_owned();
    h.drain().await;
    let user = h.user("t@example.com").await.unwrap();
    // Recorded when the registration completes (with the time, IP and user
    // agent of the registration request).
    let (token, _) = h.verification("t@example.com");
    h.verify_link(&token, Some(&handle), None).await.unwrap();
    let rows: Vec<(Option<std::net::IpAddr>, Option<String>)> =
        sqlx::query_as("SELECT ip, user_agent FROM consents WHERE user_id = $1")
            .bind(user.id)
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|(ip, ua)| ip.is_some() && ua.as_deref() == Some("Mozilla/5.0 test"))
    );
}
