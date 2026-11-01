#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! MFA-04: recovery codes — 10 × 50 bit, readable, stored hashed,
//! single use (also under concurrency), regeneration with step-up
//! invalidates old codes, remaining count, notification on use.

mod common;

use std::time::Duration;

use authn_core::domain::{AuthMethodRef, FactorKind};
use authn_core::error::codes;
use authn_core::ports::{NotificationKind, SecurityEventKind};
use authn_mfa::FactorProof;
use authn_mfa::recovery::RecoveryCode;
use common::{Harness, secret_str};

fn proof(code: &str) -> FactorProof {
    FactorProof::RecoveryCode {
        code: secret_str(code),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_04_first_factor_generates_ten_readable_codes_stored_hashed(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    assert_eq!(f.recovery_codes.len(), 10);
    for code in &f.recovery_codes {
        assert_eq!(code.len(), 11);
        assert_eq!(code.as_bytes()[5], b'-');
        assert!(RecoveryCode::parse(code).is_some());
        assert!(!code.contains(['I', 'L', 'O', 'U']));
    }
    let status = h.service.status_for_user(user).await.unwrap();
    assert_eq!(status.recovery_codes.remaining, 10);
    assert_eq!(status.recovery_codes.total, 10);
    // Only 32-byte keyed hashes are stored.
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT code_hash FROM recovery_codes WHERE user_id = $1")
            .bind(user)
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 10);
    for (hash,) in &rows {
        assert_eq!(hash.len(), 32);
        for code in &f.recovery_codes {
            let canonical = code.replace('-', "");
            assert!(
                !hash
                    .windows(canonical.len())
                    .any(|w| w == canonical.as_bytes())
            );
            assert_ne!(
                hash.as_slice(),
                authn_crypto::sha256(canonical.as_bytes()).as_slice()
            );
        }
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_04_recovery_code_is_single_use_and_notifies(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let code = &f.recovery_codes[3];
    // Lower case and without the hyphen is accepted too.
    let typed = code.replace('-', "").to_lowercase();
    let ok = h.verify(user, None, proof(&typed)).await.unwrap();
    assert_eq!(ok.kind, FactorKind::RecoveryCode);
    assert_eq!(ok.amr, vec![AuthMethodRef::Kba]);
    assert_eq!(ok.recovery_codes_remaining, Some(9));
    let notices = h.notifier.email.with_template("recovery_code_used");
    assert_eq!(notices.len(), 1);
    assert!(matches!(
        notices[0].kind,
        NotificationKind::RecoveryCodeUsed { remaining: 9, .. }
    ));
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::RecoveryCodeUsed)
            .len(),
        1
    );
    // Second use fails.
    let err = h.verify(user, None, proof(code)).await.unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    let status = h.service.status_for_user(user).await.unwrap();
    assert_eq!(status.recovery_codes.remaining, 9);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_04_concurrent_use_of_the_same_code_has_exactly_one_winner(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let code = f.recovery_codes[0].clone();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let code = code.clone();
        tasks.push(tokio::spawn(async move {
            service.verify_factor(&ctx, user, None, proof(&code)).await
        }));
    }
    let mut wins = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            wins += 1;
        }
    }
    assert_eq!(wins, 1);
    assert_eq!(
        h.count(
            "SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NOT NULL",
            user
        )
        .await,
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_04_regeneration_requires_step_up_and_invalidates_old_codes(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    // Stale authentication: step-up required.
    let stale = h.principal(user, Duration::from_secs(11 * 60));
    let err = h
        .service
        .regenerate_recovery_codes(&h.ctx(), &stale)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    // Impersonation can never regenerate codes.
    let err = h
        .service
        .regenerate_recovery_codes(&h.ctx(), &h.impersonated(user, false))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);

    let fresh = h
        .service
        .regenerate_recovery_codes(&h.ctx(), &h.fresh(user))
        .await
        .unwrap();
    assert_eq!(fresh.codes.len(), 10);
    assert!(!format!("{fresh:?}").contains(fresh.codes[0].as_str()));
    for old in &f.recovery_codes {
        assert!(!fresh.codes.iter().any(|c| c.as_str() == old));
    }
    let err = h
        .verify(user, None, proof(&f.recovery_codes[1]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    assert!(h.verify(user, None, proof(&fresh.codes[1])).await.is_ok());
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::RecoveryCodesGenerated)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_04_codes_need_an_active_factor_and_belong_to_one_user(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let err = h
        .service
        .regenerate_recovery_codes(&h.ctx(), &h.fresh(bob))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_NOT_AVAILABLE);
    let a = h.enroll_totp(alice).await;
    h.enroll_totp(bob).await;
    // Alice's code does not work for Bob (hash bound to the user).
    let err = h
        .verify(bob, None, proof(&a.recovery_codes[0]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    assert!(
        h.verify(alice, None, proof(&a.recovery_codes[0]))
            .await
            .is_ok()
    );
}
