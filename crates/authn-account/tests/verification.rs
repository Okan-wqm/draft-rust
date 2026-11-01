#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! E-mail verification and unverified accounts: ACC-04, ACC-05.
//! The pre-hijacking scenarios are in `prehijack.rs`.

mod common;

use authn_core::ports::Clock as _;

use std::time::{Duration, Instant};

use authn_account::{DenialReason, LinkConfirmation, LoginAssessment, REGISTRATION_COOKIE};
use authn_core::config::account::UnverifiedLoginPolicy;
use authn_core::domain::AccountStatus;
use authn_core::ports::{
    Notification, NotificationKind, RateLimitPolicy, RequiredAction, SecurityEventKind,
};
use authn_testkit::http::TestRequest;
use common::{Harness, PASSWORD, registrations, secret};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

fn token_of(mail: &Notification) -> String {
    match &mail.kind {
        NotificationKind::EmailVerification { token, .. } => token.expose().to_owned(),
        other => panic!("unexpected {other:?}"),
    }
}

/// Registers over HTTP; returns the handle from the response body.
async fn http_signup(h: &Harness, email: &str) -> String {
    let res = TestRequest::post("/v1/signup")
        .json(&json!({ "email": email, "password": PASSWORD }))
        .send(&h.app())
        .await;
    res.assert_status(StatusCode::ACCEPTED);
    h.drain().await;
    res.json::<serde_json::Value>()["registration"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_link_verifies_and_activates_the_account(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = http_signup(&h, "ayse@example.com").await;
    let (token, _) = h.verification("ayse@example.com");
    let res = TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .cookie(REGISTRATION_COOKIE, &handle)
        .send(&h.app())
        .await;
    res.assert_status(StatusCode::OK);
    let user = h.user("ayse@example.com").await.unwrap();
    assert_eq!(user.status, AccountStatus::Active);
    assert!(user.email_verified_at.is_some());
    assert!(h.password_matches(user.id, PASSWORD).await);
    assert_eq!(registrations(&h.pool, user.id).await, 0);
    let changes = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountStatusChanged);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].metadata["from"], "pending_verification");
    assert_eq!(changes[0].metadata["to"], "active");
    let verified = h.audit.events.of_kind(SecurityEventKind::EmailVerified);
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].metadata["method"], "link_registering_client");
    // Single use: the same link (and the sibling code) no longer work.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .cookie(REGISTRATION_COOKIE, &handle)
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_code_verifies_and_revokes_the_link(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = http_signup(&h, "mobile@example.com").await;
    let (token, code) = h.verification("mobile@example.com");
    // Native client: the handle from the signup answer travels in the body.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "email": "Mobile@Example.com", "code": code, "registration": handle }))
        .send(&h.app())
        .await
        .assert_status(StatusCode::OK);
    let user = h.user("mobile@example.com").await.unwrap();
    assert_eq!(user.status, AccountStatus::Active);
    assert!(h.password_matches(user.id, PASSWORD).await);
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token, "registration": handle }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_link_and_code_expire(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = h.signup("late@example.com").await;
    let (token, code) = h.verification("late@example.com");
    // Code: 15 minutes.
    h.ports.clock.advance(Duration::from_secs(16 * 60));
    let err = h.verify_code(Some(&handle), &code).await.unwrap_err();
    assert_eq!(err.code().code(), "invalid_code");
    // Link: 24 hours.
    h.ports.clock.advance(Duration::from_secs(24 * 3600));
    let err = h
        .verify_link(&token, Some(&handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_code_brute_force_locks_the_code_after_five_attempts(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = h.signup("brute@example.com").await;
    let (_, code) = h.verification("brute@example.com");
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        TestRequest::post("/v1/email/verify")
            .json(&json!({ "code": wrong, "registration": handle }))
            .send(&h.app())
            .await
            .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    }
    // The correct code no longer works: the registration's code budget is
    // spent.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "code": code, "registration": handle }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    assert_eq!(
        h.user("brute@example.com").await.unwrap().status,
        AccountStatus::PendingVerification
    );
    let failures = h.audit.events.of_kind(SecurityEventKind::EmailVerified);
    assert!(
        failures
            .iter()
            .any(|e| e.reason.as_deref() == Some("locked_out"))
    );
    // The link still works for the registering client.
    let (token, _) = h.verification("brute@example.com");
    h.verify_link(&token, Some(&handle), None).await.unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_resending_does_not_multiply_code_guesses(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = h.signup("guess@example.com").await;
    let mut answers = Vec::new();
    for round in 0..3 {
        if round > 0 {
            h.ports.clock.advance(Duration::from_secs(61));
            h.service
                .resend_verification(&h.ctx(), "guess@example.com", Some(&secret(&handle)))
                .await
                .unwrap();
            h.drain().await;
        }
        for _ in 0..2 {
            answers.push(h.verify_code(Some(&handle), "000001").await.is_err());
        }
    }
    assert_eq!(h.mails("email_verification", "guess@example.com").len(), 3);
    // 6 wrong answers over three codes: the 5-attempt budget belongs to the
    // registration, so the newest correct code is refused as well.
    let (_, code) = h.verification("guess@example.com");
    if code != "000001" {
        let err = h.verify_code(Some(&handle), &code).await.unwrap_err();
        assert_eq!(err.code().code(), "invalid_code");
    }
    assert!(answers.iter().all(|failed| *failed));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_code_budget_is_per_address_across_registrations(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.verification.code_attempts_per_email =
            RateLimitPolicy::new(7, Duration::from_secs(3600));
    })
    .await;
    // Several registrations of one address must not multiply guesses.
    let first = h.signup("guess@example.com").await;
    let second = h.signup("guess@example.com").await;
    let mut statuses = Vec::new();
    for handle in [&first, &second] {
        for _ in 0..4 {
            let res = TestRequest::post("/v1/email/verify")
                .json(&json!({ "code": "000001", "registration": handle }))
                .send(&h.app())
                .await;
            statuses.push(res.status);
        }
    }
    let allowed = statuses
        .iter()
        .filter(|s| **s != StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!(allowed, 7, "{statuses:?}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_unknown_and_known_addresses_answer_code_attempts_identically(pool: PgPool) {
    let h = Harness::with(pool, |s| s.code_failure_floor = Duration::from_millis(60)).await;
    let handle = h.signup("known@example.com").await;
    h.active_user("verified@example.com").await;
    let unknown_handle = authn_crypto::token::OpaqueToken::generate()
        .unwrap()
        .expose()
        .to_owned();
    let mut bodies = Vec::new();
    for body in [
        json!({ "email": "known@example.com", "code": "123456" }),
        json!({ "email": "nobody@example.com", "code": "123456" }),
        json!({ "email": "verified@example.com", "code": "123456" }),
        json!({ "code": "123456", "registration": unknown_handle }),
        json!({ "code": "123456", "registration": handle, "email": "other@example.com" }),
    ] {
        let started = Instant::now();
        let res = TestRequest::post("/v1/email/verify")
            .json(&body)
            .send(&h.app())
            .await;
        assert!(
            started.elapsed() >= Duration::from_millis(60),
            "failure floor"
        );
        let mut error = res.assert_error(StatusCode::BAD_REQUEST, "invalid_code");
        error.request_id = None;
        bodies.push(serde_json::to_value(error).unwrap());
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_concurrent_link_use_succeeds_exactly_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = h.signup("race@example.com").await;
    let (token, _) = h.verification("race@example.com");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let token = token.clone();
        let handle = handle.clone();
        handles.push(tokio::spawn(async move {
            service
                .verify_email_link(
                    &ctx,
                    &secret(&token),
                    &LinkConfirmation {
                        registration: Some(secret(&handle)),
                        ..LinkConfirmation::default()
                    },
                )
                .await
        }));
    }
    let mut ok = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountStatusChanged)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_concurrent_code_use_succeeds_exactly_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = h.signup("race2@example.com").await;
    let (_, code) = h.verification("race2@example.com");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let code = code.clone();
        let handle = handle.clone();
        handles.push(tokio::spawn(async move {
            service
                .verify_email_code(&ctx, Some(&secret(&handle)), None, &secret(&code))
                .await
        }));
    }
    let mut ok = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_resend_rotates_the_registrations_link_and_code(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.verification.max_sends_per_hour = 3;
    })
    .await;
    let handle = h.signup("again@example.com").await;
    // Cooldown: the registration e-mail started it.
    h.service
        .resend_verification(&h.ctx(), "again@example.com", None)
        .await
        .unwrap();
    h.drain().await;
    assert_eq!(h.mails("email_verification", "again@example.com").len(), 1);
    for _ in 0..3 {
        h.ports.clock.advance(Duration::from_secs(61));
        h.service
            .resend_verification(&h.ctx(), "again@example.com", None)
            .await
            .unwrap();
        h.drain().await;
    }
    // Hourly limit: registration + 2 resends.
    let all = h.mails("email_verification", "again@example.com");
    assert_eq!(all.len(), 3);
    // Only the newest link works, still bound to the registering client.
    let err = h
        .verify_link(&token_of(&all[0]), Some(&handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    let err = h
        .verify_link(&token_of(&all[2]), None, None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "registration_confirmation_required");
    h.verify_link(&token_of(&all[2]), Some(&handle), None)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_resend_obeys_cooldown_and_hourly_limit(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.verification.max_sends_per_hour = 3;
    })
    .await;
    // A signed-in unverified account (limited mode).
    let user = h
        .unverified_with_password("slow@example.com", PASSWORD)
        .await;
    let app = h.app_as(&h.fresh(user));
    for _ in 0..3 {
        TestRequest::post("/v1/me/email/verification")
            .send(&app)
            .await
            .assert_status(StatusCode::ACCEPTED);
        let res = TestRequest::post("/v1/me/email/verification")
            .send(&app)
            .await;
        res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        assert!(res.header("retry-after").is_some());
        h.ports.clock.advance(Duration::from_secs(61));
    }
    // 3 sends within the hour: the hourly limit holds.
    TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    let all = h.mails("email_verification", "slow@example.com");
    assert_eq!(all.len(), 3);

    // Only the newest link works (resend revokes the earlier ones), and only
    // for the signed-in account holder.
    let holder = LinkConfirmation {
        signed_in_user: Some(user),
        ..LinkConfirmation::default()
    };
    assert!(
        h.service
            .verify_email_link(&h.ctx(), &secret(&token_of(&all[0])), &holder)
            .await
            .is_err()
    );
    h.service
        .verify_email_link(&h.ctx(), &secret(&token_of(&all[2])), &holder)
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_unauthenticated_resend_is_enumeration_safe(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("pending@example.com").await;
    h.active_user("done@example.com").await;
    h.ports.notifier.take();
    h.ports.clock.advance(Duration::from_secs(120));
    let mut answers = Vec::new();
    for email in [
        "pending@example.com",
        "done@example.com",
        "ghost@example.com",
    ] {
        let res = TestRequest::post("/v1/email/verification/resend")
            .json(&json!({ "email": email }))
            .send(&h.app())
            .await;
        answers.push((res.status, res.body.clone()));
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(answers[0].0, StatusCode::ACCEPTED);
    h.drain().await;
    assert_eq!(
        h.mails("email_verification", "pending@example.com").len(),
        1
    );
    assert!(h.mails("email_verification", "done@example.com").is_empty());
    assert!(h.ports.notifier.recorded().len() == 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_signed_in_user_verifies_with_code_and_cannot_reverify(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h
        .unverified_with_password("limited@example.com", PASSWORD)
        .await;
    let app = h.app_as(&h.fresh(user));
    TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await
        .assert_status(StatusCode::ACCEPTED);
    let (_, code) = h.verification("limited@example.com");
    TestRequest::post("/v1/me/email/verify")
        .json(&json!({ "code": "999999" }))
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    TestRequest::post("/v1/me/email/verify")
        .json(&json!({ "code": code }))
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    TestRequest::post("/v1/me/email/verify")
        .json(&json!({ "code": code }))
        .send(&app)
        .await
        .assert_error(StatusCode::CONFLICT, "email_already_verified");
    TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await
        .assert_error(StatusCode::CONFLICT, "email_already_verified");
    // The session-issued code is only valid in that session's flow: the
    // unauthenticated code endpoint never accepts it.
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_signed_in_code_brute_force_reports_lockout(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h
        .unverified_with_password("lock@example.com", PASSWORD)
        .await;
    let app = h.app_as(&h.fresh(user));
    TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await
        .assert_status(StatusCode::ACCEPTED);
    let (_, code) = h.verification("lock@example.com");
    // Not usable without the session.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "email": "lock@example.com", "code": code }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..4 {
        TestRequest::post("/v1/me/email/verify")
            .json(&json!({ "code": wrong }))
            .send(&app)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    }
    TestRequest::post("/v1/me/email/verify")
        .json(&json!({ "code": wrong }))
        .send(&app)
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "too_many_attempts");
    TestRequest::post("/v1/me/email/verify")
        .json(&json!({ "code": code }))
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_malformed_tokens_and_codes_are_rejected_early(pool: PgPool) {
    let h = Harness::new(pool).await;
    for body in [
        json!({ "token": "short" }),
        json!({ "token": "x".repeat(5000) }),
        json!({ "email": "a@example.com", "code": "12345a" }),
        json!({ "email": "a@example.com", "code": "1234567" }),
    ] {
        let res = TestRequest::post("/v1/email/verify")
            .json(&body)
            .send(&h.app())
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
    }
    for body in [
        json!({ "token": "a", "email": "a@example.com", "code": "123456" }),
        json!({ "token": "a", "password": PASSWORD, "new_password": PASSWORD }),
        json!({ "token": "a", "email": "a@example.com" }),
        json!({ "code": "123456", "password": PASSWORD }),
        json!({ "token": "a", "accepted_terms": [{ "document": "terms_of_service", "version": "1" }] }),
        json!({}),
    ] {
        TestRequest::post("/v1/email/verify")
            .json(&body)
            .send(&h.app())
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_login_assessment_follows_the_unverified_policy(pool: PgPool) {
    let h = Harness::new(pool.clone()).await;
    h.signup("unverified@example.com").await;
    let user = h.user("unverified@example.com").await.unwrap();
    // A registration's account has no credential before it is verified, so
    // a password login cannot even reach the assessment (ADR 0002).
    assert!(
        authn_store::UserRepository::find_password(&h.pool, user.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.service.assess_login(&user).await.unwrap(),
        LoginAssessment::Denied(DenialReason::EmailNotVerified)
    );
    let err = DenialReason::EmailNotVerified.into_error(h.ports.clock.now());
    assert_eq!(err.code().code(), "email_verification_required");

    let limited = Harness::with(pool, |s| {
        s.account.unverified_login = UnverifiedLoginPolicy::Limited;
    })
    .await;
    assert_eq!(
        limited.service.unverified_login_policy(),
        UnverifiedLoginPolicy::Limited
    );
    match limited.service.assess_login(&user).await.unwrap() {
        LoginAssessment::Allowed {
            required_actions, ..
        } => assert_eq!(required_actions, vec![RequiredAction::VerifyEmail]),
        other @ LoginAssessment::Denied(_) => panic!("{other:?}"),
    }
    let active = h.active_user("ok@example.com").await;
    let record = h.user_by_id(active).await.unwrap();
    assert_eq!(
        h.service.assess_login(&record).await.unwrap(),
        LoginAssessment::Allowed {
            required_actions: vec![],
            deletion_scheduled_for: None
        }
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_unverified_accounts_are_purged_after_seven_days(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("stale@example.com").await;
    let stale = h.user("stale@example.com").await.unwrap().id;
    let verified = h.active_user("kept@example.com").await;
    h.ports.clock.advance(Duration::from_secs(6 * 86_400));
    h.signup("recent@example.com").await;
    assert_eq!(h.service.purge_unverified_accounts(100).await.unwrap(), 0);
    h.ports.clock.advance(Duration::from_secs(86_400 + 60));
    assert_eq!(h.service.purge_unverified_accounts(100).await.unwrap(), 1);
    assert!(h.user_by_id(stale).await.is_none());
    assert!(h.user_by_id(verified).await.is_some());
    assert!(h.user("recent@example.com").await.is_some());
    // Cascade: registrations, profile, password and tokens are gone.
    for sql in [
        "SELECT count(*) FROM user_profiles WHERE user_id = $1",
        "SELECT count(*) FROM one_time_tokens WHERE user_id = $1",
        "SELECT count(*) FROM pending_registrations WHERE user_id = $1",
    ] {
        assert_eq!(h.count(sql, stale).await, 0, "{sql}");
    }
    assert_eq!(h.audit.pseudonymized.lock().unwrap().as_slice(), &[stale]);
    let deleted = h.audit.events.of_kind(SecurityEventKind::AccountDeleted);
    assert_eq!(deleted[0].metadata["reason"], "unverified_expired");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_purge_keeps_unverified_last_owners(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("owner@example.com").await;
    let owner = h.user("owner@example.com").await.unwrap().id;
    h.ownership
        .0
        .lock()
        .unwrap()
        .insert(owner, vec![authn_core::id::OrgId::generate()]);
    h.ports.clock.advance(Duration::from_secs(8 * 86_400));
    assert_eq!(h.service.purge_unverified_accounts(10).await.unwrap(), 0);
    assert!(h.user_by_id(owner).await.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_verification_token_is_bound_to_the_address(pool: PgPool) {
    let h = Harness::new(pool).await;
    let handle = h.signup("first@example.com").await;
    let user = h.user("first@example.com").await.unwrap();
    let (token, code) = h.verification("first@example.com");
    // The address changes behind the registration's back (e.g. by an admin
    // tool).
    let mut conn = h.pool.acquire().await.unwrap();
    authn_store::UserRepository::update_email(
        &mut conn,
        user.id,
        &authn_core::domain::EmailAddress::parse("second@example.com").unwrap(),
        None,
    )
    .await
    .unwrap();
    let err = h.verify_code(Some(&handle), &code).await.unwrap_err();
    assert_eq!(err.code().code(), "invalid_code");
    let err = h
        .verify_link(&token, Some(&handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    let record = h.user_by_id(user.id).await.unwrap();
    assert!(record.email_verified_at.is_none());
    assert_eq!(
        registrations(&h.pool, user.id).await,
        0,
        "stale registration dropped"
    );
}

/// Security review: anybody can make the service mail any address (sign up
/// with it, or request an e-mail change to it). Text chosen by that person
/// — the display name — must not appear in those mails ("Hello <name>,",
/// `To:` name), or the service sends attacker-written text in genuine
/// e-mails. Mails to the account's proven address keep the name.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_mail_to_unproven_address_omits_the_chosen_display_name(pool: PgPool) {
    let h = Harness::new(pool).await;
    let lure = "Claim Your Prize At Example.org";
    let input = serde_json::from_value(json!({
        "email": "target@example.com",
        "password": common::PASSWORD,
        "display_name": lure,
        "locale": "tr",
    }))
    .unwrap();
    let handle = h
        .service
        .signup(&h.ctx(), input)
        .await
        .unwrap()
        .handle()
        .expose()
        .to_owned();
    h.drain().await;
    let mail = h
        .mails("email_verification", "target@example.com")
        .pop()
        .unwrap();
    assert_eq!(mail.recipient.display_name, None);
    assert_eq!(
        mail.locale,
        authn_core::domain::Locale::Tr,
        "language is kept"
    );
    // Resend (unauthenticated) does the same.
    h.ports.clock.advance(Duration::from_secs(120));
    h.service
        .resend_verification(&h.ctx(), "target@example.com", None)
        .await
        .unwrap();
    h.drain().await;
    let mails = h.mails("email_verification", "target@example.com");
    assert_eq!(mails.len(), 2);
    assert!(mails.iter().all(|m| m.recipient.display_name.is_none()));
    assert!(
        mails
            .iter()
            .all(|m| m.locale == authn_core::domain::Locale::Tr)
    );

    // A verified account with a lure as display name asks to move to
    // somebody else's address: the verification there carries no name.
    let (token, _) = h.verification("target@example.com");
    h.verify_link(&token, Some(&handle), None).await.unwrap();
    let user = h.user("target@example.com").await.unwrap().id;
    TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": "someone-else@example.net" }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_status(StatusCode::ACCEPTED);
    h.drain().await;
    let change = h
        .mails("email_change_verification", "someone-else@example.net")
        .pop()
        .unwrap();
    assert_eq!(change.recipient.display_name, None);
    // The account's own (proven) address still gets the name.
    h.service
        .request_deletion(&h.fresh(user), &h.ctx())
        .await
        .unwrap();
    let scheduled = h
        .mails("account_deletion_scheduled", "target@example.com")
        .pop()
        .unwrap();
    assert_eq!(scheduled.recipient.display_name.as_deref(), Some(lure));
}
