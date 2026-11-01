#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Passkey management: PKY-04 (list, rename, delete, last login method,
//! notifications, tenant isolation) and the data export.

mod common;

use std::sync::atomic::Ordering;

use authn_core::domain::FactorKind;
use authn_core::error::codes;
use authn_core::id::CredentialId;
use authn_core::ports::{DataExporter, NotificationKind, SecurityEventKind};
use authn_webauthn::service::RegistrationIntent;
use authn_webauthn::{MfaFacts, PasskeyDataExporter};
use common::Harness;
use sqlx::PgPool;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_list_shows_metadata_without_key_material(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let list = h.service.list_passkeys(&h.fresh(alice)).await.unwrap();
    let json = serde_json::to_value(&list).unwrap();
    let entry = &json[0];
    for field in [
        "id",
        "name",
        "created_at",
        "last_used_at",
        "usage",
        "user_verified",
        "backup_eligible",
        "backup_state",
        "discoverable",
        "aaguid",
        "transports",
        "attestation_format",
        "clone_suspected_at",
    ] {
        assert!(entry.get(field).is_some(), "{field} missing: {entry}");
    }
    let text = json.to_string();
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&passkey.raw_id);
    assert!(!text.contains(&raw), "credential id leaked: {text}");
    for secretish in ["cred_id", "counter", "public", "\"key\"", "x5c"] {
        assert!(!text.contains(secretish), "{secretish} leaked: {text}");
    }
    // Read-only impersonation may read the list.
    assert_eq!(
        h.service
            .list_passkeys(&h.impersonated(alice, true))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_rename_validates_and_audits_without_the_name(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let renamed = h
        .service
        .rename_passkey(
            &h.ctx(),
            &h.stale(alice),
            passkey.summary.id,
            "  Work laptop  ",
        )
        .await
        .unwrap();
    assert_eq!(renamed.name, "Work laptop");
    for bad in ["", "   ", "a\u{202E}b", &"x".repeat(65)] {
        let err = h
            .service
            .rename_passkey(&h.ctx(), &h.fresh(alice), passkey.summary.id, bad)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
    }
    let events = h.ports.audit.of_kind(SecurityEventKind::PasskeyRenamed);
    assert_eq!(events.len(), 1);
    assert!(
        !serde_json::to_string(&events[0])
            .unwrap()
            .contains("Work laptop")
    );
    let err = h
        .service
        .rename_passkey(
            &h.ctx(),
            &h.impersonated(alice, true),
            passkey.summary.id,
            "x",
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_delete_requires_step_up(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    h.set_password(alice.user).await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let err = h
        .service
        .delete_passkey(&h.ctx(), &h.stale(alice), passkey.summary.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    h.service
        .delete_passkey(&h.ctx(), &h.fresh(alice), passkey.summary.id)
        .await
        .unwrap();
    assert!(
        h.service
            .list_passkeys(&h.fresh(alice))
            .await
            .unwrap()
            .is_empty()
    );

    // Audit + notification on removal.
    let events = h.ports.audit.of_kind(SecurityEventKind::PasskeyRemoved);
    assert_eq!(events.len(), 1);
    let removed = h.ports.notifier.with_template("mfa_factor_removed");
    assert_eq!(removed.len(), 1);
    assert!(matches!(
        removed[0].kind,
        NotificationKind::MfaFactorRemoved {
            factor: FactorKind::Webauthn,
            ..
        }
    ));
    assert_eq!(removed[0].recipient.user_id, Some(alice.user));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_last_login_method_cannot_be_deleted(pool: PgPool) {
    let h = Harness::new(pool).await;
    // A passwordless account: the passkey is the only way in.
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let first = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let err = h
        .service
        .delete_passkey(&h.ctx(), &h.fresh(alice), first.summary.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_LAST_LOGIN_METHOD);

    // A second-factor-only key does not count as a login method.
    let mut key = SoftPasskey::new(false);
    h.register(&mut key, alice, RegistrationIntent::SecondFactor)
        .await;
    let err = h
        .service
        .delete_passkey(&h.ctx(), &h.fresh(alice), first.summary.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_LAST_LOGIN_METHOD);

    // Another passwordless passkey or a linked identity unblocks it.
    h.methods.social.store(true, Ordering::SeqCst);
    h.service
        .delete_passkey(&h.ctx(), &h.fresh(alice), first.summary.id)
        .await
        .unwrap();
    assert!(h.ports.notifier.with_template("mfa_factor_removed").len() == 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_deleting_the_last_required_second_factor_is_blocked(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    h.set_password(alice.user).await;
    let mut key = SoftPasskey::new(false);
    let registered = h
        .register(&mut key, alice, RegistrationIntent::SecondFactor)
        .await;
    *h.methods.mfa.lock().unwrap() = MfaFacts {
        mfa_required: true,
        other_factor_count: 0,
    };
    let err = h
        .service
        .delete_passkey(&h.ctx(), &h.fresh(alice), registered.summary.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_LAST_FACTOR_REQUIRED);
    *h.methods.mfa.lock().unwrap() = MfaFacts {
        mfa_required: true,
        other_factor_count: 1,
    };
    h.service
        .delete_passkey(&h.ctx(), &h.fresh(alice), registered.summary.id)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_concurrent_deletes_never_remove_the_last_login_method(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut a = SoftPasskey::new(true);
    let mut b = SoftPasskey::new(true);
    let first = h
        .register(&mut a, alice, RegistrationIntent::Passwordless)
        .await;
    let second = h
        .register(&mut b, alice, RegistrationIntent::Passwordless)
        .await;
    let attempts = [first.summary.id, second.summary.id]
        .into_iter()
        .map(|id| {
            let service = h.service.clone();
            let ctx = h.ctx();
            let principal = h.fresh(alice);
            async move { service.delete_passkey(&ctx, &principal, id).await }
        })
        .collect();
    let results = common::spawn_all(attempts).await;
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "{results:?}"
    );
    let err = results.into_iter().find_map(Result::err).unwrap();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_LAST_LOGIN_METHOD);
    assert_eq!(
        h.service
            .list_passkeys(&h.fresh(alice))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_other_users_passkeys_are_not_found(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mallory = h.account("mallory@example.com").await;
    h.set_password(mallory.user).await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let err = h
        .service
        .rename_passkey(&h.ctx(), &h.fresh(mallory), passkey.summary.id, "pwned")
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    let err = h
        .service
        .delete_passkey(&h.ctx(), &h.fresh(mallory), passkey.summary.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    let err = h
        .service
        .delete_passkey(&h.ctx(), &h.fresh(mallory), CredentialId::generate())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    assert!(
        h.service
            .list_passkeys(&h.fresh(mallory))
            .await
            .unwrap()
            .is_empty()
    );
    let list = h.service.list_passkeys(&h.fresh(alice)).await.unwrap();
    assert_eq!(list[0].name, "Passkey");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_passkey_counts_for_other_modules(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut a = SoftPasskey::new(true);
    let mut b = SoftPasskey::new(false);
    h.register(&mut a, alice, RegistrationIntent::Passwordless)
        .await;
    h.register(&mut b, alice, RegistrationIntent::SecondFactor)
        .await;
    let mut conn = h.pool.acquire().await.unwrap();
    assert_eq!(
        h.service
            .passkey_count_in(&mut conn, alice.user, false)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        h.service
            .passkey_count_in(&mut conn, alice.user, true)
            .await
            .unwrap(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_data_export_lists_passkeys_without_key_material(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let mut conn = h.pool.acquire().await.unwrap();
    let exporter = PasskeyDataExporter;
    assert_eq!(exporter.section(), "passkeys");
    let export = exporter.export(&mut conn, alice.user).await.unwrap();
    assert_eq!(export["passkeys"].as_array().unwrap().len(), 1);
    assert!(export["user_handle"].is_string());
    let text = export.to_string();
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&passkey.raw_id);
    assert!(!text.contains(&raw));
    assert!(!text.contains("counter"));
}
