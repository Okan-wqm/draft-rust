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

async fn create_user(pool: &PgPool, email: &str, created_at: OffsetDateTime) -> UserId {
    let mut conn = pool.acquire().await.unwrap();
    let mut new = new_user(email);
    new.created_at = created_at;
    UserRepository::create(&mut conn, &new).await.unwrap().id
}

#[sqlx::test(migrations = "../../migrations")]
async fn org_02_find_many_loads_a_page_in_one_query(pool: PgPool) {
    let a = create_user(&pool, "many-a@example.com", NOW).await;
    let b = create_user(&pool, "many-b@example.com", NOW).await;
    let _other = create_user(&pool, "many-c@example.com", NOW).await;
    assert!(
        UserRepository::find_many(&pool, &[])
            .await
            .unwrap()
            .is_empty()
    );
    // Unknown ids are skipped, duplicates collapse, order is by id.
    let found = UserRepository::find_many(&pool, &[b, UserId::generate(), a, b])
        .await
        .unwrap();
    let mut expected = vec![a, b];
    expected.sort();
    assert_eq!(found.iter().map(|u| u.id).collect::<Vec<_>>(), expected);
    assert_eq!(
        found[0],
        UserRepository::find_by_id(&pool, found[0].id)
            .await
            .unwrap()
            .unwrap()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_05_claim_next_returns_only_expired_unverified_accounts(pool: PgPool) {
    let cutoff = NOW;
    let old = create_user(&pool, "old@example.com", NOW - time::Duration::days(8)).await;
    let older = create_user(&pool, "older@example.com", NOW - time::Duration::days(9)).await;
    let _recent = create_user(&pool, "recent@example.com", NOW).await;
    let verified = create_user(&pool, "verified@example.com", NOW - time::Duration::days(9)).await;
    let active = create_user(&pool, "active@example.com", NOW - time::Duration::days(9)).await;
    {
        let mut conn = pool.acquire().await.unwrap();
        UserRepository::mark_email_verified(&mut conn, verified, NOW - time::Duration::days(8))
            .await
            .unwrap();
        UserRepository::update_status(
            &mut conn,
            active,
            AccountStatus::PendingVerification,
            AccountStatus::Active,
            Some("email_verified"),
            None,
            NOW,
        )
        .await
        .unwrap();
    }

    let claim = authn_store::UserClaim::UnverifiedCreatedBefore(cutoff);
    let mut tx = pool.begin().await.unwrap();
    // Oldest first; `skip` moves past rows this run already handled.
    let first = UserRepository::claim_next(&mut tx, claim, &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.id, older);
    let second = UserRepository::claim_next(&mut tx, claim, &[older])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.id, old);
    assert!(
        UserRepository::claim_next(&mut tx, claim, &[older, old])
            .await
            .unwrap()
            .is_none(),
        "recent, verified and active accounts are never claimed"
    );
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn acc_06_claim_next_is_exclusive_across_instances(pool: PgPool) {
    let mut ids = Vec::new();
    for (i, minutes) in [30_i64, 20, 10].into_iter().enumerate() {
        let id = create_user(&pool, &format!("locked{i}@example.com"), NOW).await;
        let mut conn = pool.acquire().await.unwrap();
        UserRepository::update_status(
            &mut conn,
            id,
            AccountStatus::PendingVerification,
            AccountStatus::Locked,
            Some("too_many_attempts"),
            Some(NOW - time::Duration::minutes(minutes)),
            NOW - time::Duration::hours(1),
        )
        .await
        .unwrap();
        ids.push(id);
    }
    // A lock that has not ended yet is never claimed.
    let still_locked = create_user(&pool, "still@example.com", NOW).await;
    {
        let mut conn = pool.acquire().await.unwrap();
        UserRepository::update_status(
            &mut conn,
            still_locked,
            AccountStatus::PendingVerification,
            AccountStatus::Locked,
            Some("too_many_attempts"),
            Some(NOW + time::Duration::minutes(5)),
            NOW,
        )
        .await
        .unwrap();
    }

    let claim = authn_store::UserClaim::LockExpiredAt(NOW);
    // Two instances of the job, overlapping transactions: SKIP LOCKED hands
    // each one a different row and nobody blocks.
    let mut job_a = pool.begin().await.unwrap();
    let mut job_b = pool.begin().await.unwrap();
    let a = UserRepository::claim_next(&mut job_a, claim, &[])
        .await
        .unwrap()
        .unwrap();
    let b = UserRepository::claim_next(&mut job_b, claim, &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.id, ids[0], "earliest lock end first");
    assert_eq!(
        b.id, ids[1],
        "the row held by the other instance is skipped"
    );
    assert_eq!(a.status, AccountStatus::Locked);
    let c = UserRepository::claim_next(&mut job_b, claim, &[b.id])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.id, ids[2]);
    assert!(
        UserRepository::claim_next(&mut job_b, claim, &[b.id, c.id])
            .await
            .unwrap()
            .is_none()
    );
    job_a.rollback().await.unwrap();
    job_b.rollback().await.unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn cry_04_wrapped_legacy_hashes_require_pepper_version(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let user = UserRepository::create(&mut conn, &new_user("wrapped@example.com"))
        .await
        .unwrap();
    let h = SensitiveString::new("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA");
    for algorithm in ["argon2id_wrapped_md5", "argon2id_wrapped_sha1"] {
        let unpeppered = NewPasswordHash {
            password_hash: &h,
            algorithm,
            pepper_version: None,
        };
        let err = UserRepository::set_password(&mut conn, user.id, &unpeppered, false, NOW)
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::CheckViolation { ref constraint }
                if constraint == "password_credentials_wrapped_pepper_check"),
            "{algorithm}: {err:?}"
        );
        let peppered = NewPasswordHash {
            pepper_version: Some(1),
            ..unpeppered
        };
        UserRepository::set_password(&mut conn, user.id, &peppered, false, NOW)
            .await
            .unwrap();
    }
    // Plain legacy formats stay pepper-free (CRY-04 import).
    let bcrypt = SensitiveString::new("$2b$12$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWX");
    UserRepository::set_password(
        &mut conn,
        user.id,
        &NewPasswordHash {
            password_hash: &bcrypt,
            algorithm: "bcrypt",
            pepper_version: None,
        },
        false,
        NOW,
    )
    .await
    .unwrap();
}
