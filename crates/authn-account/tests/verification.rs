#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! E-mail verification and unverified accounts: ACC-04, ACC-05.

mod common;

use authn_core::ports::Clock as _;

use std::time::{Duration, Instant};

use authn_account::{DenialReason, LoginAssessment};
use authn_core::config::account::UnverifiedLoginPolicy;
use authn_core::domain::AccountStatus;
use authn_core::ports::{RateLimitPolicy, RequiredAction, SecurityEventKind};
use authn_testkit::http::TestRequest;
use common::{Harness, secret};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_link_verifies_and_activates_the_account(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("ayse@example.com").await;
    let (token, _) = h.verification("ayse@example.com");
    let res = TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await;
    res.assert_status(StatusCode::OK);
    let user = h.user("ayse@example.com").await.unwrap();
    assert_eq!(user.status, AccountStatus::Active);
    assert!(user.email_verified_at.is_some());
    let changes = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountStatusChanged);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].metadata["from"], "pending_verification");
    assert_eq!(changes[0].metadata["to"], "active");
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::EmailVerified)
            .len(),
        1
    );
    // Single use: the same link (and the sibling code) no longer work.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_code_verifies_and_revokes_the_link(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("mobile@example.com").await;
    let (token, code) = h.verification("mobile@example.com");
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "email": "Mobile@Example.com", "code": code }))
        .send(&h.app())
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(
        h.user("mobile@example.com").await.unwrap().status,
        AccountStatus::Active
    );
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_link_and_code_expire(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("late@example.com").await;
    let (token, code) = h.verification("late@example.com");
    // Code: 15 minutes.
    h.ports.clock.advance(Duration::from_secs(16 * 60));
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "email": "late@example.com", "code": code }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    // Link: 24 hours.
    h.ports.clock.advance(Duration::from_secs(24 * 3600));
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_code_brute_force_locks_the_code_after_five_attempts(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("brute@example.com").await;
    let (_, code) = h.verification("brute@example.com");
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        TestRequest::post("/v1/email/verify")
            .json(&json!({ "email": "brute@example.com", "code": wrong }))
            .send(&h.app())
            .await
            .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    }
    // The correct code no longer works: it was revoked at the limit.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "email": "brute@example.com", "code": code }))
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
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_resending_does_not_multiply_code_guesses(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.verification.code_attempts_per_email =
            RateLimitPolicy::new(7, Duration::from_secs(3600));
    })
    .await;
    h.signup("guess@example.com").await;
    let mut statuses = Vec::new();
    for round in 0..3 {
        if round > 0 {
            h.ports.clock.advance(Duration::from_secs(61));
            h.service
                .resend_verification(&h.ctx(), "guess@example.com")
                .await
                .unwrap();
            h.drain().await;
        }
        for _ in 0..4 {
            let res = TestRequest::post("/v1/email/verify")
                .json(&json!({ "email": "guess@example.com", "code": "000001" }))
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
    h.signup("known@example.com").await;
    h.active_user("verified@example.com").await;
    let mut bodies = Vec::new();
    for email in [
        "known@example.com",
        "nobody@example.com",
        "verified@example.com",
    ] {
        let started = Instant::now();
        let res = TestRequest::post("/v1/email/verify")
            .json(&json!({ "email": email, "code": "123456" }))
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
    h.signup("race@example.com").await;
    let (token, _) = h.verification("race@example.com");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            service.verify_email_link(&ctx, &secret(&token)).await
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
    h.signup("race2@example.com").await;
    let (_, code) = h.verification("race2@example.com");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let code = code.clone();
        handles.push(tokio::spawn(async move {
            service
                .verify_email_code(&ctx, "race2@example.com", &secret(&code))
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
async fn acc_04_resend_obeys_cooldown_and_hourly_limit(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.verification.max_sends_per_hour = 3;
    })
    .await;
    h.signup("slow@example.com").await;
    let user = h.user("slow@example.com").await.unwrap();
    let app = h.app_as(&h.fresh(user.id));
    // The registration e-mail started the 60 s cooldown.
    let res = TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
    h.ports.clock.advance(Duration::from_secs(61));
    TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await
        .assert_status(StatusCode::ACCEPTED);
    h.ports.clock.advance(Duration::from_secs(61));
    TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await
        .assert_status(StatusCode::ACCEPTED);
    // 3 sends within the hour (registration + 2): the hourly limit holds.
    h.ports.clock.advance(Duration::from_secs(61));
    TestRequest::post("/v1/me/email/verification")
        .send(&app)
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert_eq!(h.mails("email_verification", "slow@example.com").len(), 3);

    // Only the newest link works (resend revokes the earlier ones).
    let all = h.mails("email_verification", "slow@example.com");
    let token_of = |n: &authn_core::ports::Notification| match &n.kind {
        authn_core::ports::NotificationKind::EmailVerification { token, .. } => {
            token.expose().to_owned()
        }
        _ => unreachable!(),
    };
    assert!(
        h.service
            .verify_email_link(&h.ctx(), &secret(&token_of(&all[0])))
            .await
            .is_err()
    );
    h.service
        .verify_email_link(&h.ctx(), &secret(&token_of(&all[2])))
        .await
        .unwrap();
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
    h.signup("limited@example.com").await;
    let user = h.user("limited@example.com").await.unwrap();
    let (_, code) = h.verification("limited@example.com");
    let app = h.app_as(&h.fresh(user.id));
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
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_signed_in_code_brute_force_reports_lockout(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("lock@example.com").await;
    let user = h.user("lock@example.com").await.unwrap();
    let (_, code) = h.verification("lock@example.com");
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let app = h.app_as(&h.fresh(user.id));
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
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": "a", "email": "a@example.com", "code": "123456" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_login_assessment_follows_the_unverified_policy(pool: PgPool) {
    let h = Harness::new(pool.clone()).await;
    h.signup("unverified@example.com").await;
    let user = h.user("unverified@example.com").await.unwrap();
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
    // Cascade: profile, password and tokens are gone with the user.
    assert_eq!(
        h.count(
            "SELECT count(*) FROM user_profiles WHERE user_id = $1",
            stale
        )
        .await,
        0
    );
    assert_eq!(
        h.count(
            "SELECT count(*) FROM one_time_tokens WHERE user_id = $1",
            stale
        )
        .await,
        0
    );
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
    h.signup("first@example.com").await;
    let user = h.user("first@example.com").await.unwrap();
    let (token, _) = h.verification("first@example.com");
    // The address changes behind the token's back (e.g. by an admin tool).
    let mut conn = h.pool.acquire().await.unwrap();
    authn_store::UserRepository::update_email(
        &mut conn,
        user.id,
        &authn_core::domain::EmailAddress::parse("second@example.com").unwrap(),
        None,
    )
    .await
    .unwrap();
    let err = h
        .service
        .verify_email_link(&h.ctx(), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    assert!(
        h.user_by_id(user.id)
            .await
            .unwrap()
            .email_verified_at
            .is_none()
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
    h.service.signup(&h.ctx(), input).await.unwrap();
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
        .resend_verification(&h.ctx(), "target@example.com")
        .await
        .unwrap();
    h.drain().await;
    let mails = h.mails("email_verification", "target@example.com");
    assert_eq!(mails.len(), 2);
    assert!(mails.iter().all(|m| m.recipient.display_name.is_none()));

    // A verified account with a lure as display name asks to move to
    // somebody else's address: the verification there carries no name.
    let (token, _) = h.verification("target@example.com");
    h.service
        .verify_email_link(&h.ctx(), &secret(&token))
        .await
        .unwrap();
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
