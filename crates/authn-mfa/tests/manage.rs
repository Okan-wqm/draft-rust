#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! MFA-07 (several factors, step-up, notifications, last-factor rule),
//! MFA-08 (policy evaluation over stored state), MFA-10 (status without
//! secrets), ADM-03 support (admin reset) and IDOR protection.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use authn_core::domain::FactorKind;
use authn_core::error::codes;
use authn_core::ports::{NotificationKind, SecurityEventKind};
use authn_mfa::{MfaRequirement, OrgMfaPolicy, OtpChannel};
use common::{Harness, secret_str};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_factor_changes_require_step_up_and_a_real_session(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    let stale = h.principal(user, Duration::from_secs(11 * 60));
    let err = h
        .service
        .begin_totp_enrollment(&h.ctx(), &stale, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let err = h
        .service
        .begin_email_enrollment(&h.ctx(), &stale)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let err = h
        .service
        .begin_sms_enrollment(&h.ctx(), &stale, "+905551112233", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let err = h
        .service
        .remove_factor(&h.ctx(), &stale, f.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    // Impersonation (even read-write) cannot change factors.
    for read_only in [true, false] {
        let err = h
            .service
            .remove_factor(&h.ctx(), &h.impersonated(user, read_only), f.id)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::FORBIDDEN);
    }
    // API-key principals (no session) are refused.
    let mut api = h.fresh(user);
    api.credential = authn_core::domain::PrincipalCredential::ApiKey {
        api_key_id: authn_core::id::ApiKeyId::generate(),
    };
    let err = h
        .service
        .begin_totp_enrollment(&h.ctx(), &api, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    // Reading works under read-only impersonation (MFA-10).
    let status = h.service.status(&h.impersonated(user, true)).await.unwrap();
    assert_eq!(status.factors.len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_removal_notifies_audits_and_revokes_trusted_devices(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let totp = h.enroll_totp(user).await;
    let email = h.enroll_email(user).await;
    let device = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    assert!(
        h.service
            .is_trusted_device(user, device.token.expose(), true)
            .await
            .unwrap()
    );

    h.service
        .remove_factor(&h.ctx(), &h.fresh(user), email)
        .await
        .unwrap();
    let removed = h.notifier.with_template("mfa_factor_removed");
    assert_eq!(removed.len(), 1);
    assert!(matches!(
        removed[0].kind,
        NotificationKind::MfaFactorRemoved {
            factor: FactorKind::Email,
            ..
        }
    ));
    let events = h.ports.audit.of_kind(SecurityEventKind::MfaFactorRemoved);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["last_factor"], false);
    // MFA change: trusted devices revoked (MFA-09).
    assert!(
        !h.service
            .is_trusted_device(user, device.token.expose(), true)
            .await
            .unwrap()
    );
    // TOTP and recovery codes are still there.
    let status = h.service.status_for_user(user).await.unwrap();
    assert_eq!(status.factors.len(), 1);
    assert_eq!(status.factors[0].id, totp.id);
    assert_eq!(status.recovery_codes.remaining, 10);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_last_factor_cannot_be_removed_while_mfa_is_required(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let totp = h.enroll_totp(user).await;
    h.policy.require_mfa();
    let err = h
        .service
        .remove_factor(&h.ctx(), &h.fresh(user), totp.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_LAST_FACTOR_REQUIRED);
    // With a second factor, either one can go.
    let email = h.enroll_email(user).await;
    h.service
        .remove_factor(&h.ctx(), &h.fresh(user), totp.id)
        .await
        .unwrap();
    let err = h
        .service
        .remove_factor(&h.ctx(), &h.fresh(user), email)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_LAST_FACTOR_REQUIRED);
    // A passkey (authn-webauthn) counts as the remaining factor.
    h.policy.webauthn.store(1, Ordering::SeqCst);
    h.service
        .remove_factor(&h.ctx(), &h.fresh(user), email)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_factor_not_permitted_by_policy_does_not_count(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let totp = h.enroll_totp(user).await;
    h.enroll_sms(user, "+905551112233").await;
    // The organization requires MFA and forbids SMS: TOTP is the last
    // *permitted* factor.
    *h.policy.org.lock().unwrap() = Some(OrgMfaPolicy {
        mfa_required: true,
        allowed_factors: Some(vec![
            FactorKind::Totp,
            FactorKind::Webauthn,
            FactorKind::RecoveryCode,
        ]),
        ..OrgMfaPolicy::default()
    });
    let err = h
        .service
        .remove_factor(&h.ctx(), &h.fresh(user), totp.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_LAST_FACTOR_REQUIRED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_removing_the_last_factor_without_requirement_cleans_up(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let totp = h.enroll_totp(user).await;
    h.service
        .remove_factor(&h.ctx(), &h.fresh(user), totp.id)
        .await
        .unwrap();
    let status = h.service.status_for_user(user).await.unwrap();
    assert!(!status.enabled);
    assert!(status.factors.is_empty());
    assert_eq!(
        status.recovery_codes.total, 0,
        "orphan recovery codes deleted"
    );
    assert_eq!(
        h.service
            .evaluate_for_user(user, None, false)
            .await
            .unwrap(),
        MfaRequirement::NotRequired
    );
    let events = h.ports.audit.of_kind(SecurityEventKind::MfaFactorRemoved);
    assert_eq!(events[0].metadata["last_factor"], true);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_concurrent_removal_of_the_last_two_factors_keeps_one(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let a = h.enroll_totp(user).await;
    let b = h.enroll_totp(user).await;
    h.policy.require_mfa();
    let mut tasks = Vec::new();
    for id in [a.id, b.id] {
        let service = h.service.clone();
        let ctx = h.ctx();
        let principal = h.fresh(user);
        tasks.push(tokio::spawn(async move {
            service.remove_factor(&ctx, &principal, id).await
        }));
    }
    let mut removed = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(()) => removed += 1,
            Err(err) => assert_eq!(err.code(), codes::mfa::MFA_LAST_FACTOR_REQUIRED),
        }
    }
    assert_eq!(removed, 1);
    assert_eq!(
        h.count(
            "SELECT count(*) FROM mfa_factors WHERE user_id = $1 AND status = 'active'",
            user
        )
        .await,
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_foreign_factor_ids_are_not_found(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mallory = h.user("mallory@example.com").await;
    let totp = h.enroll_totp(alice).await;
    let pending = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(alice), None)
        .await
        .unwrap();
    let err = h
        .service
        .remove_factor(&h.ctx(), &h.fresh(mallory), totp.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    let code = h.totp_code(
        &authn_crypto::totp::TotpSecret::from_base32(&pending.provisioning.secret_base32).unwrap(),
        0,
    );
    let err = h
        .service
        .confirm_enrollment(
            &h.ctx(),
            &h.fresh(mallory),
            pending.factor.id,
            &secret_str(&code),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    let err = h
        .service
        .resend_enrollment_code(&h.ctx(), &h.fresh(mallory), pending.factor.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    let err = h
        .service
        .send_code(
            &h.ctx(),
            mallory,
            None,
            OtpChannel::Sms {
                factor_id: Some(totp.id),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    assert_eq!(
        h.service
            .status_for_user(alice)
            .await
            .unwrap()
            .factors
            .len(),
        2
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_factor_limit_per_user(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| s.mfa.max_factors_per_user = 2).await;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    h.enroll_totp(user).await;
    let err = h
        .service
        .begin_totp_enrollment(&h.ctx(), &h.fresh(user), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_FACTOR_LIMIT_REACHED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_10_status_lists_factors_without_secrets(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let totp = h.enroll_totp(user).await;
    h.enroll_sms(user, "+905551112233").await;
    let status = h.service.status(&h.fresh(user)).await.unwrap();
    assert!(status.enabled);
    assert_eq!(status.factors.len(), 2);
    let json = serde_json::to_string(&status).unwrap();
    assert!(!json.contains(totp.secret.to_base32().as_str()));
    assert!(!json.contains("5551112233"), "phone number is masked");
    assert!(json.contains("+90*******233"));
    assert!(!json.contains("secret"));
    assert!(!json.contains("ciphertext"));
    let sms = status
        .factors
        .iter()
        .find(|f| f.kind == FactorKind::Sms)
        .unwrap();
    assert!(sms.weak);
    assert!(!sms.phishing_resistant);
    assert_eq!(status.recovery_codes.remaining, 10);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_08_policy_evaluation_over_stored_state(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    assert_eq!(
        h.service
            .evaluate_for_user(user, None, false)
            .await
            .unwrap(),
        MfaRequirement::NotRequired
    );
    let org = OrgMfaPolicy {
        mfa_required: true,
        ..OrgMfaPolicy::default()
    };
    assert_eq!(
        h.service
            .evaluate_for_user(user, Some(org.clone()), false)
            .await
            .unwrap(),
        MfaRequirement::EnrollmentRequired {
            allowed_factors: vec![
                FactorKind::Totp,
                FactorKind::Webauthn,
                FactorKind::Email,
                FactorKind::Sms
            ]
        }
    );
    h.enroll_totp(user).await;
    let input = h.service.policy_input(user, None, false).await.unwrap();
    assert!(input.user_opted_in);
    assert_eq!(
        input.enrolled_factors,
        vec![FactorKind::Totp, FactorKind::RecoveryCode]
    );
    assert_eq!(
        h.service
            .evaluate_for_user(user, None, false)
            .await
            .unwrap(),
        MfaRequirement::Required {
            allowed_factors: vec![FactorKind::Totp, FactorKind::RecoveryCode]
        }
    );
    // Phishing-resistant requirement: TOTP no longer suffices.
    assert_eq!(
        h.service.evaluate_for_user(user, None, true).await.unwrap(),
        MfaRequirement::EnrollmentRequired {
            allowed_factors: vec![FactorKind::Webauthn]
        }
    );
    // Platform admins need passkeys.
    h.make_admin(user).await;
    h.policy.webauthn.store(1, Ordering::SeqCst);
    assert_eq!(
        h.service
            .evaluate_for_user(user, None, false)
            .await
            .unwrap(),
        MfaRequirement::Required {
            allowed_factors: vec![FactorKind::Webauthn]
        }
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_admin_reset_removes_everything_and_notifies(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let f = h.enroll_totp(user).await;
    h.enroll_email(user).await;
    h.service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    let mut tx = h.pool.begin().await.unwrap();
    let summary = h
        .service
        .reset_user_mfa_in_tx(&mut tx, &h.ctx(), user)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(summary.factors, 2);
    assert_eq!(summary.recovery_codes, 10);
    assert_eq!(summary.trusted_devices, 1);
    let status = h.service.status_for_user(user).await.unwrap();
    assert!(!status.enabled && status.factors.is_empty());
    assert_eq!(h.notifier.with_template("mfa_reset").len(), 1);
    let err = h
        .verify_totp(user, &h.totp_code(&f.secret, 0))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    assert_eq!(
        h.service
            .evaluate_for_user(user, None, false)
            .await
            .unwrap(),
        MfaRequirement::NotRequired
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_admin_reset_rolls_back_with_the_caller(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    let mut tx = h.pool.begin().await.unwrap();
    h.service
        .reset_user_mfa_in_tx(&mut tx, &h.ctx(), user)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(h.service.status_for_user(user).await.unwrap().enabled);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_10_data_export_contains_no_secrets(pool: sqlx::PgPool) {
    use authn_core::ports::DataExporter as _;
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let totp = h.enroll_totp(user).await;
    h.enroll_sms(user, "+905551112233").await;
    let device = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    let mut conn = h.pool.acquire().await.unwrap();
    let exporter = authn_mfa::MfaDataExporter;
    assert_eq!(exporter.section(), "mfa");
    let export = exporter.export(&mut conn, user).await.unwrap();
    assert_eq!(export["mfa_enabled"], true);
    assert_eq!(export["factors"].as_array().unwrap().len(), 2);
    assert_eq!(export["recovery_codes"]["remaining"], 10);
    assert_eq!(export["trusted_devices"].as_array().unwrap().len(), 1);
    // The user's own phone number is their personal data: exported in full.
    let text = export.to_string();
    assert!(text.contains("+905551112233"));
    // Secrets never are.
    assert!(!text.contains(totp.secret.to_base32().as_str()));
    assert!(!text.contains(device.token.expose()));
    for code in &totp.recovery_codes {
        assert!(!text.contains(code.as_str()));
    }
    assert!(!text.contains("ciphertext") && !text.contains("hash"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_10_status_needs_a_session_principal(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let mut api = h.fresh(user);
    api.credential = authn_core::domain::PrincipalCredential::ApiKey {
        api_key_id: authn_core::id::ApiKeyId::generate(),
    };
    let err = h.service.status(&api).await.unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    let err = h.service.list_trusted_devices(&api).await.unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    assert!(h.service.status(&h.fresh(user)).await.is_ok());
}
