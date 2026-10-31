//! Integration tests of the base user repository against real PostgreSQL.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::id::UserId;
use authn_core::secret::SensitiveString;
use authn_store::users::EMAIL_UNIQUE_CONSTRAINT;
use authn_store::{NewPasswordHash, NewUser, StoreError, UserRepository};
use sqlx::PgPool;
use time::OffsetDateTime;
use time::macros::datetime;

const NOW: OffsetDateTime = datetime!(2026-01-01 12:00:00 UTC);

fn new_user(email: &str) -> NewUser {
    NewUser {
        id: UserId::generate(),
        email: EmailAddress::parse(email).unwrap(),
        status: AccountStatus::PendingVerification,
        created_at: NOW,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_03_create_and_find_by_normalized_email(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let new = new_user("Alice.Smith@Example.COM");
    let created = UserRepository::create(&mut conn, &new).await.unwrap();
    assert_eq!(created.id, new.id);
    assert_eq!(created.email.as_deref(), Some("Alice.Smith@example.com"));
    assert_eq!(
        created.email_normalized.as_deref(),
        Some("alice.smith@example.com")
    );
    assert_eq!(created.status, AccountStatus::PendingVerification);
    assert_eq!(created.created_at, NOW);
    assert!(!created.is_email_verified());

    let by_email = UserRepository::find_by_email(
        &pool,
        &EmailAddress::parse("ALICE.smith@example.com").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(by_email.id, new.id);
    let by_id = UserRepository::find_by_id(&pool, new.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_id, by_email);
    assert!(
        UserRepository::find_by_id(&pool, UserId::generate())
            .await
            .unwrap()
            .is_none()
    );
    // Debug output never contains the full address.
    assert!(!format!("{by_id:?}").contains("Alice.Smith@"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_03_duplicate_normalized_email_is_a_classified_unique_violation(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    UserRepository::create(&mut conn, &new_user("bob@example.com"))
        .await
        .unwrap();
    let err = UserRepository::create(&mut conn, &new_user("BOB@Example.com"))
        .await
        .unwrap_err();
    assert!(err.is_unique_violation(EMAIL_UNIQUE_CONSTRAINT), "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_06_status_update_is_compare_and_set(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    let user = UserRepository::create(&mut tx, &new_user("carol@example.com"))
        .await
        .unwrap();
    let later = NOW + time::Duration::minutes(5);
    let changed = UserRepository::update_status(
        &mut tx,
        user.id,
        AccountStatus::PendingVerification,
        AccountStatus::Active,
        Some("email_verified"),
        None,
        later,
    )
    .await
    .unwrap();
    assert!(changed);
    // Stale expectation: no change.
    let changed = UserRepository::update_status(
        &mut tx,
        user.id,
        AccountStatus::PendingVerification,
        AccountStatus::Suspended,
        None,
        None,
        later,
    )
    .await
    .unwrap();
    assert!(!changed);
    let locked = UserRepository::lock_for_update(&mut tx, user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(locked.status, AccountStatus::Active);
    assert_eq!(locked.status_reason.as_deref(), Some("email_verified"));
    assert_eq!(locked.status_changed_at, later);
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_06_locked_status_requires_lock_end(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let user = UserRepository::create(&mut conn, &new_user("dave@example.com"))
        .await
        .unwrap();
    let err = UserRepository::update_status(
        &mut conn,
        user.id,
        AccountStatus::PendingVerification,
        AccountStatus::Locked,
        None,
        None,
        NOW,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, StoreError::CheckViolation { ref constraint } if constraint == "users_locked_until_check"),
        "{err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_07_email_update_and_verification(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let user = UserRepository::create(&mut conn, &new_user("erin@example.com"))
        .await
        .unwrap();
    assert!(
        UserRepository::mark_email_verified(&mut conn, user.id, NOW)
            .await
            .unwrap()
    );
    // Idempotent: keeps the first timestamp.
    UserRepository::mark_email_verified(&mut conn, user.id, NOW + time::Duration::hours(1))
        .await
        .unwrap();
    let new_email = EmailAddress::parse("erin.new@example.org").unwrap();
    assert!(
        UserRepository::update_email(&mut conn, user.id, &new_email, Some(NOW))
            .await
            .unwrap()
    );
    let reloaded = UserRepository::find_by_email(&pool, &new_email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.email_verified_at, Some(NOW));
    assert!(
        UserRepository::find_by_email(&pool, &EmailAddress::parse("erin@example.com").unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cry_03_password_credential_lifecycle(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let user = UserRepository::create(&mut conn, &new_user("frank@example.com"))
        .await
        .unwrap();
    assert!(
        UserRepository::find_password(&pool, user.id)
            .await
            .unwrap()
            .is_none()
    );

    let first = SensitiveString::new("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo");
    let hash = NewPasswordHash {
        password_hash: &first,
        algorithm: "argon2id",
        pepper_version: Some(1),
    };
    UserRepository::set_password(&mut conn, user.id, &hash, true, NOW)
        .await
        .unwrap();
    let stored = UserRepository::find_password(&pool, user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.password_hash, first);
    assert_eq!(stored.pepper_version, Some(1));
    assert!(stored.must_change);
    assert_eq!(stored.changed_at, NOW);
    assert!(!format!("{stored:?}").contains("argon2id$v=19"));

    // Rehash keeps changed_at / must_change, and only replaces the verified hash.
    let second =
        SensitiveString::new("$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo");
    let upgraded = NewPasswordHash {
        password_hash: &second,
        algorithm: "argon2id",
        pepper_version: Some(2),
    };
    assert!(
        UserRepository::rehash_password(&mut conn, user.id, &first, &upgraded)
            .await
            .unwrap()
    );
    assert!(
        !UserRepository::rehash_password(&mut conn, user.id, &first, &upgraded)
            .await
            .unwrap()
    );
    let stored = UserRepository::find_password(&pool, user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.password_hash, second);
    assert_eq!(stored.pepper_version, Some(2));
    assert!(stored.must_change);
    assert_eq!(stored.changed_at, NOW);

    assert!(
        UserRepository::set_must_change_password(&mut conn, user.id, false)
            .await
            .unwrap()
    );
    assert!(
        UserRepository::delete_password(&mut conn, user.id)
            .await
            .unwrap()
    );
    assert!(
        UserRepository::find_password(&pool, user.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cry_02_argon2id_hash_requires_pepper_version(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let user = UserRepository::create(&mut conn, &new_user("gina@example.com"))
        .await
        .unwrap();
    let h = SensitiveString::new("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA");
    let hash = NewPasswordHash {
        password_hash: &h,
        algorithm: "argon2id",
        pepper_version: None,
    };
    let err = UserRepository::set_password(&mut conn, user.id, &hash, false, NOW)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::CheckViolation { .. }), "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_09_hard_delete_cascades(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let user = UserRepository::create(&mut conn, &new_user("hank@example.com"))
        .await
        .unwrap();
    let h = SensitiveString::new("$2b$12$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWX");
    let hash = NewPasswordHash {
        password_hash: &h,
        algorithm: "bcrypt",
        pepper_version: None,
    };
    UserRepository::set_password(&mut conn, user.id, &hash, false, NOW)
        .await
        .unwrap();
    assert!(UserRepository::delete(&mut conn, user.id).await.unwrap());
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM password_credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}
