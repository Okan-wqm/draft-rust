#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! MFA-01 (TOTP enrollment, envelope-encrypted secret, pending until
//! confirmed) and MFA-02 (replay protection, including concurrent
//! duplicate submissions).

mod common;

use std::time::Duration;

use authn_core::domain::{AuthMethodRef, FactorKind};
use authn_core::error::codes;
use authn_core::ports::{NotificationKind, SecurityEventKind};
use authn_crypto::totp::TotpSecret;
use authn_mfa::{FactorProof, FactorState};
use common::{Harness, secret_str, wrong};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_totp_enrollment_returns_secret_uri_qr_and_stays_pending(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let enrollment = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), Some("  Work phone ".into()))
        .await
        .unwrap();
    let p = &enrollment.provisioning;
    // 160-bit secret, base32.
    let secret = TotpSecret::from_base32(&p.secret_base32).unwrap();
    assert_eq!(secret.expose().len(), 20);
    assert!(
        p.otpauth_uri
            .starts_with("otpauth://totp/rust-authentication:alice%40example.com?secret=")
    );
    assert!(p.otpauth_uri.contains(p.secret_base32.as_str()));
    assert!(p.otpauth_uri.contains("algorithm=SHA1&digits=6&period=30"));
    assert!(p.qr_svg.contains("<svg") && p.qr_svg.ends_with("</svg>"));
    assert_eq!(enrollment.factor.status, FactorState::Pending);
    assert_eq!(enrollment.factor.label.as_deref(), Some("Work phone"));
    assert_eq!(
        enrollment.expires_at,
        h.now() + Duration::from_secs(15 * 60)
    );
    assert!(!format!("{enrollment:?}").contains(p.secret_base32.as_str()));

    // A pending factor is not a factor: login verification fails.
    let code = h.totp_code(&secret, 0);
    let err = h.verify_totp(user, &code).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    let status = h.service.status_for_user(user).await.unwrap();
    assert!(!status.enabled);
    assert!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::MfaFactorAdded)
            .is_empty()
    );

    // Confirmation with a valid code activates it.
    let confirmed = h
        .service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            enrollment.factor.id,
            &secret_str(&code),
        )
        .await
        .unwrap();
    assert_eq!(confirmed.factor.status, FactorState::Active);
    assert!(h.service.status_for_user(user).await.unwrap().enabled);
    let added = h.ports.audit.of_kind(SecurityEventKind::MfaFactorAdded);
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].metadata["factor"], "totp");
    let notices = h.notifier.email.with_template("mfa_factor_added");
    assert!(matches!(
        notices[0].kind,
        NotificationKind::MfaFactorAdded {
            factor: FactorKind::Totp,
            ..
        }
    ));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_secret_is_envelope_encrypted_and_bound_to_its_row(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let a = h.enroll_totp(alice).await;
    let b = h.enroll_totp(bob).await;
    let (ciphertext,): (Vec<u8>,) =
        sqlx::query_as("SELECT secret_ciphertext FROM mfa_factors WHERE id = $1")
            .bind(a.id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    // Neither the raw secret nor its base32 form is stored.
    let raw = a.secret.expose();
    assert!(!ciphertext.windows(raw.len()).any(|w| w == raw));
    let b32 = a.secret.to_base32();
    assert!(!ciphertext.windows(b32.len()).any(|w| w == b32.as_bytes()));

    // Copy-paste attack: Alice's ciphertext moved into Bob's row does not
    // decrypt (AAD = table/column/row id), so Alice's codes never work for
    // Bob and the verification fails closed.
    sqlx::query("UPDATE mfa_factors SET secret_ciphertext = $1 WHERE id = $2")
        .bind(&ciphertext)
        .bind(b.id)
        .execute(&h.pool)
        .await
        .unwrap();
    let alice_code = h.totp_code(&a.secret, 0);
    let err = h.verify_totp(bob, &alice_code).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INTERNAL_ERROR);
    // Alice is unaffected.
    assert!(h.verify_totp(alice, &alice_code).await.is_ok());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_wrong_confirmation_codes_are_counted_and_discard_the_enrollment(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let enrollment = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap();
    let secret = TotpSecret::from_base32(&enrollment.provisioning.secret_base32).unwrap();
    let bad = wrong(&h.totp_code(&secret, 0));
    for _ in 0..4 {
        let err = h
            .service
            .confirm_enrollment(
                &h.ctx(),
                &h.fresh(user),
                enrollment.factor.id,
                &secret_str(&bad),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE);
    }
    let err = h
        .service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            enrollment.factor.id,
            &secret_str(&bad),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::TOO_MANY_ATTEMPTS);
    // The pending factor is gone; even the right code cannot confirm it.
    let good = h.totp_code(&secret, 0);
    let err = h
        .service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            enrollment.factor.id,
            &secret_str(&good),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    assert_eq!(
        h.count("SELECT count(*) FROM mfa_factors WHERE user_id = $1", user)
            .await,
        0
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_expired_pending_enrollment_cannot_be_confirmed(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let enrollment = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap();
    let secret = TotpSecret::from_base32(&enrollment.provisioning.secret_base32).unwrap();
    h.advance(Duration::from_secs(16 * 60));
    let code = h.totp_code(&secret, 0);
    let err = h
        .service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            enrollment.factor.id,
            &secret_str(&code),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_ENROLLMENT_NOT_PENDING);
    // The purge job removes abandoned enrollments.
    let report = h.service.purge_expired().await.unwrap();
    assert_eq!(report.pending_factors, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_new_enrollment_replaces_abandoned_pending_totp(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let first = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap();
    let second = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap();
    assert_ne!(first.factor.id, second.factor.id);
    assert_ne!(
        first.provisioning.secret_base32.as_str(),
        second.provisioning.secret_base32.as_str()
    );
    assert_eq!(
        h.count(
            "SELECT count(*) FROM mfa_factors WHERE user_id = $1 AND status = 'pending'",
            user
        )
        .await,
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_codes_of_the_adjacent_steps_are_accepted(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    // Two steps after the confirmation step: the previous one is unused.
    h.advance(Duration::from_secs(30));
    let previous = h.totp_code(&f.secret, -1);
    let ok = h.verify_totp(user, &previous).await.unwrap();
    assert_eq!(ok.kind, FactorKind::Totp);
    assert_eq!(ok.factor_id, Some(f.id));
    assert_eq!(ok.amr, vec![AuthMethodRef::Otp]);
    h.advance(Duration::from_secs(30));
    let next = h.totp_code(&f.secret, 1);
    assert!(h.verify_totp(user, &next).await.is_ok());
    // Two steps away is outside the ±1 window.
    h.advance(Duration::from_secs(60));
    let far = h.totp_code(&f.secret, 2);
    let err = h.verify_totp(user, &far).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_02_totp_code_cannot_be_replayed(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let current = h.totp_code(&f.secret, 0);
    assert!(h.verify_totp(user, &current).await.is_ok());
    // Same code again: rejected.
    let err = h.verify_totp(user, &current).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    // An *earlier* step (still inside the window) is rejected too.
    let previous = h.totp_code(&f.secret, -1);
    let err = h.verify_totp(user, &previous).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    let (step,): (Option<i64>,) =
        sqlx::query_as("SELECT last_used_step FROM mfa_factors WHERE id = $1")
            .bind(f.id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(step.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_02_confirmation_code_cannot_be_replayed_at_login(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let enrollment = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap();
    let secret = TotpSecret::from_base32(&enrollment.provisioning.secret_base32).unwrap();
    let code = h.totp_code(&secret, 0);
    h.service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(user),
            enrollment.factor.id,
            &secret_str(&code),
        )
        .await
        .unwrap();
    let err = h.verify_totp(user, &code).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_02_concurrent_duplicate_submissions_only_one_succeeds(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let code = h.totp_code(&f.secret, 0);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let code = code.clone();
        tasks.push(tokio::spawn(async move {
            service
                .verify_factor(
                    &ctx,
                    user,
                    None,
                    FactorProof::Totp {
                        code: secret_str(&code),
                        factor_id: None,
                    },
                )
                .await
        }));
    }
    let mut ok = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => ok += 1,
            Err(err) => assert!(
                err.is(codes::common::INVALID_CODE) || err.is(codes::common::TOO_MANY_ATTEMPTS),
                "{err:?}"
            ),
        }
    }
    assert_eq!(ok, 1, "exactly one concurrent submission may succeed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_01_malformed_codes_are_rejected_and_counted(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    for bad in [
        "",
        "12345",
        "1234567",
        "12a456",
        "١٢٣٤٥٦",
        &"9".repeat(4096),
    ] {
        let err = h.verify_totp(user, bad).await.unwrap_err();
        assert!(
            err.is(codes::common::INVALID_CODE) || err.is(codes::common::TOO_MANY_ATTEMPTS),
            "{bad:?}: {err:?}"
        );
    }
    assert!(
        !h.ports
            .audit
            .of_kind(SecurityEventKind::MfaFailed)
            .is_empty()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_user_can_have_several_totp_factors(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let a = h.enroll_totp(user).await;
    let b = h.enroll_totp(user).await;
    assert_ne!(a.id, b.id);
    // Either authenticator works; a code can be pinned to one factor.
    let ok = h
        .verify_totp(user, &h.totp_code(&b.secret, 0))
        .await
        .unwrap();
    assert_eq!(ok.factor_id, Some(b.id));
    h.advance(Duration::from_secs(30));
    let err = h
        .verify(
            user,
            None,
            FactorProof::Totp {
                code: secret_str(&h.totp_code(&b.secret, 0)),
                factor_id: Some(a.id),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    // First factor generated the recovery codes; the second did not
    // replace them.
    assert_eq!(a.recovery_codes.len(), 10);
    assert!(b.recovery_codes.is_empty());
}
