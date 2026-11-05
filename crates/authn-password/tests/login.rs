#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Login-time verification for authn-session: CRY-03 rehash, CRY-04 legacy
//! upgrade, CRY-05 dummy verification, PWD-02 normalization, PWD-12
//! `must_change_password`.

mod common;

use authn_core::domain::AccountStatus;
use authn_core::error::codes;
use authn_core::ports::{Actor, Clock as _, SecurityEventKind};
use authn_crypto::password::{Argon2Settings, LegacyDigest, PasswordHasher, Peppers};
use authn_password::LoginPasswordOutcome;
use authn_store::{NewPasswordHash, UserRepository};
use authn_testkit::timing::compare_timings;
use common::{Harness, STRONG, STRONG_2, secret};
use sha1::Digest as _;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_02_password_is_normalized_before_hashing_and_verification(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    // Registered on a system that sends NFD, logs in from one that sends NFC.
    let nfd = "kahve\u{301} makinesi c\u{327}ok gu\u{308}zel";
    let nfc = "kahvé makinesi çok güzel";
    let user = h.user("nfkc@example.com", Some(nfd)).await;
    let outcome = h
        .service
        .verify_login_password(&h.ctx(), Some(user), &secret(nfc))
        .await
        .unwrap();
    assert_eq!(outcome, LoginPasswordOutcome::Valid);
    // Compatibility forms fold too (fullwidth digits).
    let user = h.user("fullwidth@example.com", Some(STRONG)).await;
    let fullwidth = "tramway galaxy orchid lantern ４７";
    assert!(
        h.service
            .verify_login_password(&h.ctx(), Some(user), &secret(fullwidth))
            .await
            .unwrap()
            .is_valid()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_05_unknown_and_passwordless_accounts_fail_uniformly(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let known = h.user("known@example.com", Some(STRONG)).await;
    let passwordless = h.user("passkey-only@example.com", None).await;
    for user in [None, Some(passwordless), Some(known)] {
        let outcome = h
            .service
            .verify_login_password(&h.ctx(), user, &secret(STRONG_2))
            .await
            .unwrap();
        assert_eq!(outcome, LoginPasswordOutcome::Invalid, "{user:?}");
    }
    // Equal work: unknown account vs. wrong password for a real one.
    let report = compare_timings(
        15,
        || async {
            let _ = h
                .service
                .verify_login_password(&h.ctx(), Some(known), &secret(STRONG_2))
                .await
                .unwrap();
        },
        || async {
            let _ = h
                .service
                .verify_login_password(&h.ctx(), None, &secret(STRONG_2))
                .await
                .unwrap();
        },
    )
    .await;
    report.assert_indistinguishable(0.3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_03_outdated_argon2_parameters_are_upgraded_after_login(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let config = authn_testkit::config::test_config();
    let old = PasswordHasher::new(
        Argon2Settings {
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        },
        Peppers::from_config(&config.crypto).unwrap(),
        1,
    )
    .await
    .unwrap();
    let user = h.user("old-params@example.com", None).await;
    let record = old.hash(&secret(STRONG)).await.unwrap();
    let mut conn = h.pool.acquire().await.unwrap();
    UserRepository::set_password(
        &mut conn,
        user,
        &NewPasswordHash {
            password_hash: &record.hash,
            algorithm: record.algorithm.as_str(),
            pepper_version: record.pepper_version,
        },
        false,
        FakeNow::now(&h),
    )
    .await
    .unwrap();
    drop(conn);

    let outcome = h
        .service
        .verify_login_password(&h.ctx(), Some(user), &secret(STRONG))
        .await
        .unwrap();
    assert_eq!(outcome, LoginPasswordOutcome::Valid);
    let stored = UserRepository::find_password(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(stored.password_hash, record.hash);
    assert!(stored.password_hash.expose().contains("m=7168"));
    assert!(h.password_is(user, STRONG).await);
    let events = h.ports.audit.of_kind(SecurityEventKind::PasswordRehashed);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["reason"], "outdated_parameters");
    assert_eq!(events[0].actor, Actor::User(user));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_04_legacy_wrapped_sha1_hash_is_migrated_to_argon2id(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("legacy@example.com", None).await;
    let legacy_hex = data_encoding::HEXLOWER.encode(&sha1::Sha1::digest(STRONG.as_bytes()));
    let record = h
        .crypto
        .passwords
        .wrap_legacy_digest(LegacyDigest::Sha1, &legacy_hex)
        .await
        .unwrap();
    let mut conn = h.pool.acquire().await.unwrap();
    UserRepository::set_password(
        &mut conn,
        user,
        &NewPasswordHash {
            password_hash: &record.hash,
            algorithm: record.algorithm.as_str(),
            pepper_version: record.pepper_version,
        },
        false,
        FakeNow::now(&h),
    )
    .await
    .unwrap();
    drop(conn);
    // Wrong password: no upgrade.
    assert_eq!(
        h.service
            .verify_login_password(&h.ctx(), Some(user), &secret(STRONG_2))
            .await
            .unwrap(),
        LoginPasswordOutcome::Invalid
    );
    assert_eq!(
        UserRepository::find_password(&h.pool, user)
            .await
            .unwrap()
            .unwrap()
            .algorithm,
        "argon2id_wrapped_sha1"
    );
    // Correct password: verified against the legacy scheme, then upgraded.
    assert_eq!(
        h.service
            .verify_login_password(&h.ctx(), Some(user), &secret(STRONG))
            .await
            .unwrap(),
        LoginPasswordOutcome::Valid
    );
    let stored = UserRepository::find_password(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.algorithm, "argon2id");
    assert!(h.password_is(user, STRONG).await);
    let events = h.ports.audit.of_kind(SecurityEventKind::PasswordRehashed);
    assert_eq!(events[0].metadata["reason"], "legacy_algorithm");
    assert_eq!(
        events[0].metadata["from_algorithm"],
        "argon2id_wrapped_sha1"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_12_must_change_password_is_reported_after_a_correct_password(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("flagged@example.com", Some(STRONG)).await;
    let admin = h.user("admin@example.com", Some(STRONG_2)).await;

    h.service
        .set_must_change_password(&h.ctx(), Actor::User(admin), user, true)
        .await
        .unwrap();
    assert_eq!(
        h.service
            .verify_login_password(&h.ctx(), Some(user), &secret(STRONG))
            .await
            .unwrap(),
        LoginPasswordOutcome::MustChangePassword
    );
    // A wrong password never reveals the flag.
    assert_eq!(
        h.service
            .verify_login_password(&h.ctx(), Some(user), &secret(STRONG_2))
            .await
            .unwrap(),
        LoginPasswordOutcome::Invalid
    );
    let events = h
        .ports
        .audit
        .of_kind(SecurityEventKind::PasswordChangeRequiredSet);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, Actor::User(admin));
    assert_eq!(events[0].subject_user, Some(user));
    assert_eq!(events[0].metadata["must_change_password"], true);

    h.service
        .set_must_change_password(&h.ctx(), Actor::User(admin), user, false)
        .await
        .unwrap();
    assert_eq!(
        h.service
            .verify_login_password(&h.ctx(), Some(user), &secret(STRONG))
            .await
            .unwrap(),
        LoginPasswordOutcome::Valid
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_12_flag_requires_an_existing_account_with_a_password(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let passwordless = h
        .user_with_status("nopw@example.com", None, AccountStatus::Active)
        .await;
    let err = h
        .service
        .set_must_change_password(&h.ctx(), Actor::System, passwordless, true)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_NOT_SET);
    let err = h
        .service
        .set_must_change_password(
            &h.ctx(),
            Actor::System,
            authn_core::id::UserId::generate(),
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    assert!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::PasswordChangeRequiredSet)
            .is_empty()
    );
}

/// Small helper to read the harness clock.
struct FakeNow;

impl FakeNow {
    fn now(h: &Harness) -> time::OffsetDateTime {
        use authn_core::ports::Clock as _;
        h.ports.clock.now()
    }
}

/// ADM-05 / K-110: a password whose expiry passed (the unused one-time
/// initial password of a break-glass admin) is refused like a wrong one;
/// before the expiry it still works.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_05_k110_expired_password_is_rejected_like_a_wrong_one(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("glass@example.com", Some(STRONG)).await;
    let deadline = h.ports.clock.now() + time::Duration::hours(24);
    let mut conn = h.pool.acquire().await.unwrap();
    assert!(
        UserRepository::set_password_expiry(&mut conn, user, Some(deadline))
            .await
            .unwrap()
    );
    let password = secret(STRONG);
    let outcome = h
        .service
        .verify_login_password(&h.ctx(), Some(user), &password)
        .await
        .unwrap();
    assert_eq!(outcome, LoginPasswordOutcome::Valid);
    h.ports
        .clock
        .advance(std::time::Duration::from_secs(24 * 60 * 60));
    let outcome = h
        .service
        .verify_login_password(&h.ctx(), Some(user), &password)
        .await
        .unwrap();
    assert_eq!(outcome, LoginPasswordOutcome::Invalid);
}
