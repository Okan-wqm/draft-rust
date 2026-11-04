#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! MFA-05 (e-mail OTP) and MFA-06 (SMS OTP: E.164, verified number,
//! pumping protection, weak factor).

mod common;

use std::sync::Arc;
use std::time::Duration;

use authn_core::domain::{AuthMethodRef, FactorKind};
use authn_core::error::codes;
use authn_core::ports::{RateLimitKey, RateLimitPolicy, SmsNotificationKind};
use authn_mfa::service::actions;
use authn_mfa::{CodeChannel, FactorProof, FactorState, OtpChannel};
use authn_testkit::fakes::InMemoryRateLimiter;
use common::{Harness, phone, secret_str, wrong};

fn email_proof(code: &str) -> FactorProof {
    FactorProof::EmailOtp {
        code: secret_str(code),
    }
}

fn sms_proof(code: &str) -> FactorProof {
    FactorProof::SmsOtp {
        code: secret_str(code),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_05_email_factor_enrollment_and_login_code(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let delivery = h
        .service
        .begin_email_enrollment(&h.ctx(), &h.fresh(user))
        .await
        .unwrap();
    assert_eq!(delivery.channel, CodeChannel::Email);
    assert_eq!(delivery.destination, "a***@example.com");
    assert_eq!(delivery.expires_at, h.now() + Duration::from_secs(600));
    let status = h.service.status_for_user(user).await.unwrap();
    assert_eq!(status.factors[0].status, FactorState::Pending);
    assert_eq!(status.factors[0].email.as_deref(), Some("a***@example.com"));
    let code = h.last_email_code();
    assert_eq!(code.len(), 6);
    h.service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            delivery.factor_id,
            &secret_str(&code),
        )
        .await
        .unwrap();
    // A second e-mail factor cannot be enrolled.
    let err = h
        .service
        .begin_email_enrollment(&h.ctx(), &h.fresh(user))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_ALREADY_ENROLLED);

    // Login: code bound to the challenge.
    h.advance(Duration::from_secs(61));
    let challenge = h.challenge(user).await;
    h.service
        .send_code(&h.ctx(), user, Some(challenge), OtpChannel::Email)
        .await
        .unwrap();
    let code = h.last_email_code();
    let ok = h
        .verify(user, Some(challenge), email_proof(&code))
        .await
        .unwrap();
    assert_eq!(ok.kind, FactorKind::Email);
    assert_eq!(ok.factor_id, Some(delivery.factor_id));
    assert_eq!(ok.amr, vec![AuthMethodRef::Email]);
    // Single use.
    let err = h
        .verify(user, Some(challenge), email_proof(&code))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_05_code_of_a_challenge_is_useless_elsewhere(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_email(user).await;
    let first = h.challenge(user).await;
    let other = h.challenge(user).await;
    h.service
        .send_code(&h.ctx(), user, Some(first), OtpChannel::Email)
        .await
        .unwrap();
    let code = h.last_email_code();
    let err = h
        .verify(user, Some(other), email_proof(&code))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    assert!(
        h.verify(user, Some(first), email_proof(&code))
            .await
            .is_ok()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_05_resend_cooldown_and_new_code_revokes_old(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_email(user).await;
    h.service
        .send_code(&h.ctx(), user, None, OtpChannel::Email)
        .await
        .unwrap();
    let old = h.last_email_code();
    let err = h
        .service
        .send_code(&h.ctx(), user, None, OtpChannel::Email)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert!(err.retry_after().is_some());
    h.advance(Duration::from_secs(61));
    h.service
        .send_code(&h.ctx(), user, None, OtpChannel::Email)
        .await
        .unwrap();
    let new = h.last_email_code();
    if old != new {
        let err = h.verify(user, None, email_proof(&old)).await.unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE);
        // The failed old code did not burn the new one.
        assert!(h.verify(user, None, email_proof(&new)).await.is_ok());
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_05_code_expires_after_ten_minutes(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_email(user).await;
    h.service
        .send_code(&h.ctx(), user, None, OtpChannel::Email)
        .await
        .unwrap();
    let code = h.last_email_code();
    h.advance(Duration::from_secs(10 * 60 + 1));
    let err = h.verify(user, None, email_proof(&code)).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_05_email_factor_can_be_disabled_by_configuration(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| s.mfa.email_otp.enabled = false).await;
    let user = h.user("alice@example.com").await;
    let err = h
        .service
        .begin_email_enrollment(&h.ctx(), &h.fresh(user))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_NOT_AVAILABLE);
    let err = h
        .service
        .send_code(&h.ctx(), user, None, OtpChannel::Email)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_NOT_AVAILABLE);
    assert!(!h.service.available_factors().contains(&FactorKind::Email));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_06_phone_must_be_verified_before_it_becomes_a_factor(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let delivery = h
        .service
        .begin_sms_enrollment(
            &h.ctx(),
            &h.fresh(user),
            "+905551112233",
            Some("Mobile".into()),
        )
        .await
        .unwrap();
    assert_eq!(delivery.channel, CodeChannel::Sms);
    assert_eq!(delivery.destination, "+90*******233");
    let sms = h.last_sms();
    assert_eq!(sms.to, phone("+905551112233"));
    assert_eq!(sms.user_id, Some(user));
    assert!(matches!(
        sms.kind,
        SmsNotificationKind::PhoneVerification { .. }
    ));
    let code = h.last_sms_code();
    // Unverified number: no SMS login code can be requested, and the
    // verification code is not a login code.
    let err = h
        .service
        .send_code(&h.ctx(), user, None, OtpChannel::Sms { factor_id: None })
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_NOT_AVAILABLE);
    let err = h.verify(user, None, sms_proof(&code)).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);

    // Purpose separation consumed nothing: the verification code still
    // confirms the number.
    let confirmed = h
        .service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            delivery.factor_id,
            &secret_str(&code),
        )
        .await
        .unwrap();
    assert_eq!(confirmed.factor.status, FactorState::Active);
    assert!(confirmed.factor.weak, "SMS is a weak factor");
    assert_eq!(
        confirmed.factor.phone_number.as_deref(),
        Some("+90*******233")
    );
    assert_eq!(confirmed.factor.label.as_deref(), Some("Mobile"));

    h.advance(Duration::from_secs(61));
    h.service
        .send_code(&h.ctx(), user, None, OtpChannel::Sms { factor_id: None })
        .await
        .unwrap();
    assert!(matches!(
        h.last_sms().kind,
        SmsNotificationKind::MfaSmsCode { .. }
    ));
    let ok = h
        .verify(user, None, sms_proof(&h.last_sms_code()))
        .await
        .unwrap();
    assert_eq!(ok.kind, FactorKind::Sms);
    assert_eq!(ok.amr, vec![AuthMethodRef::Sms]);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_06_numbers_are_strict_e164_from_allowed_countries(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    for bad in [
        "05551112233",
        "+90 555 111 22 33",
        "+90-555-111-2233",
        "+٩٠٥٥٥١١١٢٢٣٣",
        "+0905551112233",
        "",
    ] {
        let err = h
            .service
            .begin_sms_enrollment(&h.ctx(), &h.fresh(user), bad, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::mfa::MFA_INVALID_PHONE_NUMBER, "{bad:?}");
    }
    // Premium-rate pumping targets abroad: not on the allow-list.
    let err = h
        .service
        .begin_sms_enrollment(&h.ctx(), &h.fresh(user), "+4470123456789", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_PHONE_COUNTRY_NOT_ALLOWED);
    assert!(h.notifier.recorded_sms().is_empty(), "nothing was sent");
    assert_eq!(
        h.count("SELECT count(*) FROM mfa_factors WHERE user_id = $1", user)
            .await,
        0
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_06_sms_unavailable_without_provider_or_countries(pool: sqlx::PgPool) {
    // No allowed country (the default): SMS is off.
    let h = Harness::with(pool.clone(), |s| s.mfa.sms.allowed_country_codes.clear()).await;
    let user = h.user("alice@example.com").await;
    let err = h
        .service
        .begin_sms_enrollment(&h.ctx(), &h.fresh(user), "+905551112233", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_NOT_AVAILABLE);
    assert!(!h.service.available_factors().contains(&FactorKind::Sms));

    // Provider not configured (ARC-11).
    let h = Harness::new(pool).await;
    let bob = h.user("bob@example.com").await;
    h.ports.sms.set_configured(false);
    let err = h
        .service
        .begin_sms_enrollment(&h.ctx(), &h.fresh(bob), "+905551112233", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_NOT_AVAILABLE);
    let err = h.verify(bob, None, sms_proof("123456")).await.unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_NOT_AVAILABLE);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_06_pumping_protection_per_number_ip_and_global_budget(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.mfa.sms.per_number = RateLimitPolicy::new(2, Duration::from_secs(3600));
        s.mfa.sms.per_ip = RateLimitPolicy::new(3, Duration::from_secs(3600));
        s.mfa.sms.global_daily_budget = RateLimitPolicy::new(5, Duration::from_secs(86_400));
    })
    .await;
    let service = h.with_rate_limiter(Arc::new(InMemoryRateLimiter::new(h.ports.clock.clone())));
    let attacker = h.ctx_from("198.51.100.66".parse().unwrap());
    let mut users = Vec::new();
    for i in 0..8 {
        users.push(h.user(&format!("u{i}@example.com")).await);
    }
    let begin = |user, ctx: authn_core::http::RequestContext, number: &'static str| {
        let service = service.clone();
        let principal = h.fresh(user);
        async move {
            service
                .begin_sms_enrollment(&ctx, &principal, number, None)
                .await
        }
    };
    // Per number: 2 per hour, whoever asks (global budget 2/5).
    assert!(begin(users[0], h.ctx(), "+905550000001").await.is_ok());
    assert!(begin(users[1], h.ctx(), "+905550000001").await.is_ok());
    let err = begin(users[2], h.ctx(), "+905550000001").await.unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    // Per IP: 3 per hour across numbers and accounts (global 5/5).
    assert!(
        begin(users[3], attacker.clone(), "+905550000002")
            .await
            .is_ok()
    );
    assert!(
        begin(users[4], attacker.clone(), "+905550000003")
            .await
            .is_ok()
    );
    assert!(
        begin(users[5], attacker.clone(), "+905550000004")
            .await
            .is_ok()
    );
    let err = begin(users[6], attacker.clone(), "+905550000005")
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    // Global daily budget: exhausted although user, number and IP are new.
    let err = begin(
        users[7],
        h.ctx_from("192.0.2.1".parse().unwrap()),
        "+14155550123",
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert!(err.retry_after().is_some());
    assert_eq!(h.notifier.recorded_sms().len(), 5);
    // Refused requests left no pending factor behind.
    assert_eq!(
        h.count(
            "SELECT count(*) FROM mfa_factors WHERE user_id = $1",
            users[7]
        )
        .await,
        0
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_06_sms_resend_cooldown_and_unique_number(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let first = h
        .service
        .begin_sms_enrollment(&h.ctx(), &h.fresh(user), "+905551112233", None)
        .await
        .unwrap();
    let err = h
        .service
        .resend_enrollment_code(&h.ctx(), &h.fresh(user), first.factor_id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    h.advance(Duration::from_secs(61));
    let again = h
        .service
        .resend_enrollment_code(&h.ctx(), &h.fresh(user), first.factor_id)
        .await
        .unwrap();
    assert_eq!(again.factor_id, first.factor_id);
    h.service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            first.factor_id,
            &secret_str(&h.last_sms_code()),
        )
        .await
        .unwrap();
    h.advance(Duration::from_secs(61));
    let err = h
        .service
        .begin_sms_enrollment(&h.ctx(), &h.fresh(user), "+905551112233", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_ALREADY_ENROLLED);
    // A wrong code never confirms another number.
    let second = h
        .service
        .begin_sms_enrollment(&h.ctx(), &h.fresh(user), "+14155550123", None)
        .await
        .unwrap();
    let err = h
        .service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            second.factor_id,
            &secret_str(&wrong(&h.last_sms_code())),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
}

/// Security review: the store's user-only lookup (step-up, no challenge)
/// also finds the newest code bound to a login challenge; such a code must
/// only ever verify together with its own challenge.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_05_login_challenge_code_is_rejected_without_its_challenge(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_email(user).await;
    let challenge = h.challenge(user).await;
    h.service
        .send_code(&h.ctx(), user, Some(challenge), OtpChannel::Email)
        .await
        .unwrap();
    let code = h.last_email_code();
    let err = h.verify(user, None, email_proof(&code)).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);

    // The same for SMS login codes.
    h.advance(Duration::from_secs(61));
    h.enroll_sms(user, "+905551112233").await;
    let challenge = h.challenge(user).await;
    h.service
        .send_code(
            &h.ctx(),
            user,
            Some(challenge),
            OtpChannel::Sms { factor_id: None },
        )
        .await
        .unwrap();
    let code = h.last_sms_code();
    let err = h.verify(user, None, sms_proof(&code)).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
}

/// Security review: a request refused for another reason (here the
/// per-user factor limit) must not consume SMS pumping budgets — least of
/// all the global daily budget shared by every user.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_06_refused_enrollment_consumes_no_sms_budget(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| s.mfa.max_factors_per_user = 1).await;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    let err = h
        .service
        .begin_sms_enrollment(&h.ctx(), &h.fresh(user), "+905551112233", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_LIMIT_REACHED);
    let limiter = &h.ports.rate_limiter;
    for key in [
        RateLimitKey::global(actions::SMS_GLOBAL),
        RateLimitKey::user(actions::SMS_PER_USER, user),
        RateLimitKey::user(actions::SMS_COOLDOWN, user),
        RateLimitKey::phone(actions::SMS_PER_NUMBER, &phone("+905551112233")),
        RateLimitKey::ip(actions::SMS_PER_IP, h.ctx().client_ip),
    ] {
        assert_eq!(limiter.used(&key), 0, "{key:?}");
    }
    assert!(h.notifier.recorded_sms().is_empty());
}
