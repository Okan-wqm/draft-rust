#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! MFA-03: attempt limits per factor and per user, temporary lock with
//! `Retry-After` and a security event; exactness under concurrency.

mod common;

use std::time::Duration;

use authn_core::error::codes;
use authn_core::ports::SecurityEventKind;
use authn_mfa::FactorProof;
use common::{Harness, secret_str, wrong};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_03_factor_locks_after_max_failures_with_security_event(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let bad = wrong(&h.totp_code(&f.secret, 0));
    for _ in 0..4 {
        let err = h.verify_totp(user, &bad).await.unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE);
    }
    // The 5th failure engages the 15-minute lock.
    let err = h.verify_totp(user, &bad).await.unwrap_err();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
    assert_eq!(err.retry_after(), Some(Duration::from_secs(15 * 60)));
    let locked = h.ports.audit.of_kind(SecurityEventKind::MfaLocked);
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].metadata["scope"], "factor");
    assert_eq!(locked[0].subject_user, Some(user));
    assert_eq!(h.ports.audit.of_kind(SecurityEventKind::MfaFailed).len(), 5);

    // While locked even the right code is refused (and not evaluated).
    let good = h.totp_code(&f.secret, 0);
    let err = h.verify_totp(user, &good).await.unwrap_err();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
    let status = h.service.status_for_user(user).await.unwrap();
    assert!(status.factors[0].locked_until.is_some());

    // After the lock the factor works again and the counter is reset.
    h.advance(Duration::from_secs(15 * 60 + 1));
    let good = h.totp_code(&f.secret, 0);
    assert!(h.verify_totp(user, &good).await.is_ok());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_03_user_limit_spans_all_factors(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    // Recovery codes have no factor row: only the per-user window limits
    // them (10 failures per 15 minutes by default).
    for i in 0..9 {
        let err = h
            .verify(
                user,
                None,
                FactorProof::RecoveryCode {
                    code: secret_str("AAAAA-AAAAA"),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE, "attempt {i}");
    }
    let err = h
        .verify(
            user,
            None,
            FactorProof::RecoveryCode {
                code: secret_str("BBBBB-BBBBB"),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
    let locked = h.ports.audit.of_kind(SecurityEventKind::MfaLocked);
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].metadata["scope"], "user");

    // The user lock blocks every factor, including a correct TOTP code and
    // a correct recovery code.
    let good = h.totp_code(&f.secret, 0);
    let err = h.verify_totp(user, &good).await.unwrap_err();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
    let err = h
        .verify(
            user,
            None,
            FactorProof::RecoveryCode {
                code: secret_str(&f.recovery_codes[0]),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
    // Sending codes is refused as well.
    h.advance(Duration::from_secs(15 * 60 + 1));
    let good = h.totp_code(&f.secret, 0);
    assert!(h.verify_totp(user, &good).await.is_ok());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_03_failure_window_expires(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    let attempt = || async {
        h.verify(
            user,
            None,
            FactorProof::RecoveryCode {
                code: secret_str("AAAAA-AAAAA"),
            },
        )
        .await
        .unwrap_err()
    };
    for _ in 0..9 {
        assert_eq!(attempt().await.code(), codes::common::INVALID_CODE);
    }
    // A new window starts after 15 minutes: no lock.
    h.advance(Duration::from_secs(15 * 60));
    for _ in 0..9 {
        assert_eq!(attempt().await.code(), codes::common::INVALID_CODE);
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_03_concurrent_wrong_guesses_are_counted_exactly(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let bad = wrong(&h.totp_code(&f.secret, 0));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let bad = bad.clone();
        tasks.push(tokio::spawn(async move {
            service
                .verify_factor(
                    &ctx,
                    user,
                    None,
                    FactorProof::Totp {
                        code: secret_str(&bad),
                        factor_id: None,
                    },
                )
                .await
        }));
    }
    let mut evaluated = 0;
    let mut refused = 0;
    for task in tasks {
        let err = task.await.unwrap().unwrap_err();
        if err.is(codes::common::INVALID_CODE) {
            evaluated += 1;
        } else {
            assert!(err.is(codes::common::TOO_MANY_ATTEMPTS), "{err:?}");
            refused += 1;
        }
    }
    // Serialized on the user's row lock: exactly max_failed_attempts - 1
    // plain failures, the 5th engages the lock, the rest are refused.
    assert_eq!(evaluated, 4);
    assert_eq!(refused, 12);
    assert_eq!(h.ports.audit.of_kind(SecurityEventKind::MfaFailed).len(), 5);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_03_email_code_attempts_survive_resends(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_email(user).await;
    // Each resend gives a fresh code with 5 attempts, but the factor
    // counter keeps counting across codes: 5 failures lock the factor.
    let mut errors = Vec::new();
    for _ in 0..3 {
        h.service
            .send_code(&h.ctx(), user, None, authn_mfa::OtpChannel::Email)
            .await
            .unwrap();
        let code = h.last_email_code();
        for _ in 0..2 {
            errors.push(
                h.verify(
                    user,
                    None,
                    FactorProof::EmailOtp {
                        code: secret_str(&wrong(&code)),
                    },
                )
                .await
                .unwrap_err(),
            );
        }
        h.advance(Duration::from_secs(61));
    }
    assert!(
        errors[..4]
            .iter()
            .all(|e| e.is(codes::common::INVALID_CODE))
    );
    assert!(errors[4].is(codes::common::TOO_MANY_ATTEMPTS));
    assert!(errors[5].is(codes::common::TOO_MANY_ATTEMPTS));
    // Locked factor: no new code is sent.
    let err = h
        .service
        .send_code(&h.ctx(), user, None, authn_mfa::OtpChannel::Email)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
}

/// Security review (contracts §8, PRT-04): the `429` that discards a
/// pending enrollment after too many wrong confirmation codes carries
/// `Retry-After` like every other `429`.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_03_discarded_enrollment_answers_429_with_retry_after(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let enrollment = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap();
    let mut last = None;
    for _ in 0..h.settings.mfa.max_failed_attempts {
        last = Some(
            h.service
                .confirm_enrollment(
                    &h.ctx(),
                    &h.fresh(user),
                    enrollment.factor.id,
                    &secret_str("abcdef"),
                )
                .await
                .unwrap_err(),
        );
    }
    let err = last.unwrap();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
    assert!(err.retry_after().is_some(), "429 without Retry-After");
}
