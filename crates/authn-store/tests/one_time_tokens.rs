#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Integration tests of the one-time token repository (ARC-06, CRY-06,
//! CRY-07, TST-02) against real PostgreSQL.

use std::sync::Arc;
use std::time::Duration;

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::id::{ChallengeId, OneTimeTokenId, UserId};
use authn_crypto::kdf::KeyRing;
use authn_crypto::otp::{OtpCode, OtpHasher};
use authn_crypto::token::{OpaqueToken, TokenHash};
use authn_store::{
    CodeVerification, NewOneTimeToken, NewUser, OneTimeTokenRepository, StoreError, TokenKind,
    TokenPurpose, TokenSubject, UserRepository,
};
use sqlx::PgPool;
use time::OffsetDateTime;
use time::macros::datetime;
use tokio::sync::Barrier;
use uuid::Uuid;

const NOW: OffsetDateTime = datetime!(2026-01-01 12:00:00 UTC);
const PARALLEL: usize = 8;

async fn user(pool: &PgPool) -> UserId {
    let mut conn = pool.acquire().await.unwrap();
    let id = UserId::generate();
    UserRepository::create(
        &mut conn,
        &NewUser {
            id,
            email: EmailAddress::parse(&format!("u{}@example.com", id.as_uuid().simple())).unwrap(),
            status: AccountStatus::Active,
            created_at: NOW,
        },
    )
    .await
    .unwrap();
    id
}

async fn challenge(pool: &PgPool, user: UserId) -> ChallengeId {
    let id = ChallengeId::generate();
    sqlx::query(
        "INSERT INTO auth_challenges (id, kind, user_id, token_hash, client_kind, created_at, expires_at) \
         VALUES ($1, 'passwordless', $2, $3, 'web', $4, $4 + interval '10 minutes')",
    )
    .bind(id)
    .bind(user)
    .bind(OpaqueToken::generate().unwrap().hash().as_bytes().as_slice())
    .bind(NOW)
    .execute(pool)
    .await
    .unwrap();
    id
}

fn hasher() -> OtpHasher {
    OtpHasher::new(&KeyRing::derive(&[42; 32]).unwrap()).unwrap()
}

fn new_token(
    purpose: TokenPurpose,
    hash: TokenHash,
    subject: TokenSubject,
    ttl: Duration,
) -> NewOneTimeToken<'static> {
    NewOneTimeToken {
        id: OneTimeTokenId::generate(),
        purpose,
        token_hash: hash,
        subject,
        group_id: None,
        target: None,
        max_attempts: 5,
        metadata: serde_json::json!({}),
        created_ip: Some("203.0.113.7".parse().unwrap()),
        created_at: NOW,
        expires_at: NOW + ttl,
    }
}

async fn create(pool: &PgPool, new: &NewOneTimeToken<'_>, invalidate: bool) {
    let mut conn = pool.acquire().await.unwrap();
    OneTimeTokenRepository::create(&mut conn, new, invalidate)
        .await
        .unwrap();
}

async fn consume(
    pool: &PgPool,
    purpose: TokenPurpose,
    hash: &TokenHash,
    at: OffsetDateTime,
) -> bool {
    let mut conn = pool.acquire().await.unwrap();
    OneTimeTokenRepository::consume_link(&mut conn, purpose, hash, at)
        .await
        .unwrap()
        .is_some()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_06_link_token_is_single_use(pool: PgPool) {
    let user = user(&pool).await;
    let token = OpaqueToken::generate().unwrap();
    let mut new = new_token(
        TokenPurpose::PasswordReset,
        token.hash(),
        TokenSubject::user(user),
        Duration::from_secs(1800),
    );
    new.target = Some("alice@example.com");
    new.metadata = serde_json::json!({"locale": "tr"});
    let mut conn = pool.acquire().await.unwrap();
    let created = OneTimeTokenRepository::create(&mut conn, &new, true)
        .await
        .unwrap();
    assert_eq!(created.kind, TokenKind::Link);
    assert_eq!(created.user_id, Some(user));
    assert!(!format!("{created:?}").contains("alice@"));

    // Only the hash is stored.
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM one_time_tokens WHERE id = $1")
            .bind(created.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, token.hash().as_bytes().to_vec());
    assert!(
        !stored
            .windows(8)
            .any(|w| token.expose().as_bytes().windows(8).any(|t| t == w))
    );

    // Peeking does not consume (SES-18 confirmation page).
    let parsed = OpaqueToken::parse(token.expose()).unwrap();
    assert!(
        OneTimeTokenRepository::find_active_link(
            &pool,
            TokenPurpose::PasswordReset,
            &parsed.hash(),
            NOW
        )
        .await
        .unwrap()
        .is_some()
    );
    let consumed = OneTimeTokenRepository::consume_link(
        &mut conn,
        TokenPurpose::PasswordReset,
        &parsed.hash(),
        NOW,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(consumed.id, created.id);
    assert_eq!(consumed.consumed_at, Some(NOW));
    assert_eq!(consumed.target.as_deref(), Some("alice@example.com"));
    assert_eq!(consumed.metadata, serde_json::json!({"locale": "tr"}));
    assert!(!consume(&pool, TokenPurpose::PasswordReset, &parsed.hash(), NOW).await);
    assert!(
        OneTimeTokenRepository::find_active_link(
            &pool,
            TokenPurpose::PasswordReset,
            &parsed.hash(),
            NOW
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_06_expired_wrong_purpose_and_unknown_links_are_refused(pool: PgPool) {
    let user = user(&pool).await;
    let token = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::EmailVerification,
            token.hash(),
            TokenSubject::user(user),
            Duration::from_secs(60),
        ),
        false,
    )
    .await;
    // Cross-purpose use (a verification link presented as a reset link).
    assert!(!consume(&pool, TokenPurpose::PasswordReset, &token.hash(), NOW).await);
    // A code purpose never consumes links.
    assert!(!consume(&pool, TokenPurpose::PasswordResetCode, &token.hash(), NOW).await);
    // Unknown token.
    assert!(
        !consume(
            &pool,
            TokenPurpose::EmailVerification,
            &OpaqueToken::generate().unwrap().hash(),
            NOW
        )
        .await
    );
    // Expired (boundary: expires_at itself is already invalid).
    assert!(
        !consume(
            &pool,
            TokenPurpose::EmailVerification,
            &token.hash(),
            NOW + Duration::from_secs(60)
        )
        .await
    );
    // Still valid just before expiry.
    assert!(
        consume(
            &pool,
            TokenPurpose::EmailVerification,
            &token.hash(),
            NOW + Duration::from_secs(59)
        )
        .await
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_02_concurrent_link_consumers_exactly_one_succeeds(pool: PgPool) {
    let user = user(&pool).await;
    let token = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::MagicLink,
            token.hash(),
            TokenSubject::user(user),
            Duration::from_secs(900),
        ),
        false,
    )
    .await;
    let barrier = Arc::new(Barrier::new(PARALLEL));
    let hash = token.hash();
    let mut tasks = Vec::new();
    for _ in 0..PARALLEL {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            // Wait first, then race for connections: holding a connection at
            // the barrier could exhaust the shared test pool.
            barrier.wait().await;
            let mut conn = pool.acquire().await.unwrap();
            OneTimeTokenRepository::consume_link(&mut conn, TokenPurpose::MagicLink, &hash, NOW)
                .await
                .unwrap()
                .is_some()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_06_consumption_rolls_back_with_the_callers_transaction(pool: PgPool) {
    let user = user(&pool).await;
    let token = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::PasswordReset,
            token.hash(),
            TokenSubject::user(user),
            Duration::from_secs(900),
        ),
        false,
    )
    .await;
    let mut tx = pool.begin().await.unwrap();
    assert!(
        OneTimeTokenRepository::consume_link(
            &mut tx,
            TokenPurpose::PasswordReset,
            &token.hash(),
            NOW
        )
        .await
        .unwrap()
        .is_some()
    );
    // e.g. the new password was rejected by policy
    tx.rollback().await.unwrap();
    assert!(consume(&pool, TokenPurpose::PasswordReset, &token.hash(), NOW).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_new_request_invalidates_previous_tokens(pool: PgPool) {
    let user = user(&pool).await;
    let first = OpaqueToken::generate().unwrap();
    let second = OpaqueToken::generate().unwrap();
    let subject = TokenSubject::user(user);
    create(
        &pool,
        &new_token(
            TokenPurpose::PasswordReset,
            first.hash(),
            subject,
            Duration::from_secs(900),
        ),
        true,
    )
    .await;
    // A token of another purpose is untouched by the invalidation.
    let other = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::EmailVerification,
            other.hash(),
            subject,
            Duration::from_secs(900),
        ),
        true,
    )
    .await;
    create(
        &pool,
        &new_token(
            TokenPurpose::PasswordReset,
            second.hash(),
            subject,
            Duration::from_secs(900),
        ),
        true,
    )
    .await;
    assert!(!consume(&pool, TokenPurpose::PasswordReset, &first.hash(), NOW).await);
    assert!(consume(&pool, TokenPurpose::PasswordReset, &second.hash(), NOW).await);
    assert!(consume(&pool, TokenPurpose::EmailVerification, &other.hash(), NOW).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_concurrent_requests_leave_a_single_active_token(pool: PgPool) {
    let user = user(&pool).await;
    let barrier = Arc::new(Barrier::new(PARALLEL));
    let mut tasks = Vec::new();
    for _ in 0..PARALLEL {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let token = OpaqueToken::generate().unwrap();
            let new = new_token(
                TokenPurpose::PasswordReset,
                token.hash(),
                TokenSubject::user(user),
                Duration::from_secs(900),
            );
            barrier.wait().await;
            let mut tx = pool.begin().await.unwrap();
            OneTimeTokenRepository::create(&mut tx, &new, true)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM one_time_tokens WHERE user_id = $1 AND purpose = 'password_reset' \
         AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_07_code_attempts_are_counted_and_lock_out(pool: PgPool) {
    let user = user(&pool).await;
    let h = hasher();
    let purpose = TokenPurpose::PasswordResetCode;
    let code = OtpCode::parse("123456").unwrap();
    let mut new = new_token(
        purpose,
        h.hash(purpose.as_str(), &code),
        TokenSubject::user(user),
        Duration::from_secs(900),
    );
    new.max_attempts = 3;
    create(&pool, &new, true).await;
    let wrong = h.hash(purpose.as_str(), &OtpCode::parse("654321").unwrap());
    let subject = TokenSubject::user(user);

    let verify = |candidate: TokenHash| {
        let pool = pool.clone();
        async move {
            OneTimeTokenRepository::verify_code(&pool, purpose, subject, &candidate, NOW)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        verify(wrong).await,
        CodeVerification::Invalid {
            remaining_attempts: 2
        }
    );
    assert_eq!(
        verify(wrong).await,
        CodeVerification::Invalid {
            remaining_attempts: 1
        }
    );
    // The attempt counter is durable (own committed transaction).
    let attempts: i32 = sqlx::query_scalar("SELECT attempts FROM one_time_tokens WHERE id = $1")
        .bind(new.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(verify(wrong).await, CodeVerification::LockedOut);
    // Even the correct code no longer works.
    assert_eq!(
        verify(h.hash(purpose.as_str(), &code)).await,
        CodeVerification::NotFound
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_07_correct_code_is_single_use_and_purpose_bound(pool: PgPool) {
    let user = user(&pool).await;
    let h = hasher();
    let purpose = TokenPurpose::MfaEmailOtp;
    let code = OtpCode::generate().unwrap();
    create(
        &pool,
        &new_token(
            purpose,
            h.hash(purpose.as_str(), &code),
            TokenSubject::user(user),
            Duration::from_secs(600),
        ),
        true,
    )
    .await;
    let subject = TokenSubject::user(user);
    // The same code hashed for another purpose does not match.
    let cross = h.hash(TokenPurpose::LoginCode.as_str(), &code);
    assert!(matches!(
        OneTimeTokenRepository::verify_code(&pool, purpose, subject, &cross, NOW)
            .await
            .unwrap(),
        CodeVerification::Invalid { .. }
    ));
    // Link purposes never verify codes; another user's subject finds nothing.
    let right = h.hash(purpose.as_str(), &code);
    assert_eq!(
        OneTimeTokenRepository::verify_code(
            &pool,
            TokenPurpose::PasswordReset,
            subject,
            &right,
            NOW
        )
        .await
        .unwrap(),
        CodeVerification::NotFound
    );
    assert_eq!(
        OneTimeTokenRepository::verify_code(
            &pool,
            purpose,
            TokenSubject::user(UserId::generate()),
            &right,
            NOW
        )
        .await
        .unwrap(),
        CodeVerification::NotFound
    );
    // Expired.
    assert_eq!(
        OneTimeTokenRepository::verify_code(
            &pool,
            purpose,
            subject,
            &right,
            NOW + Duration::from_secs(600)
        )
        .await
        .unwrap(),
        CodeVerification::NotFound
    );
    let CodeVerification::Verified(record) =
        OneTimeTokenRepository::verify_code(&pool, purpose, subject, &right, NOW)
            .await
            .unwrap()
    else {
        panic!("expected verification");
    };
    assert_eq!(record.attempts, 2);
    assert_eq!(record.consumed_at, Some(NOW));
    assert_eq!(
        OneTimeTokenRepository::verify_code(&pool, purpose, subject, &right, NOW)
            .await
            .unwrap(),
        CodeVerification::NotFound
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_02_concurrent_code_verification_exactly_one_succeeds(pool: PgPool) {
    let user = user(&pool).await;
    let h = hasher();
    let purpose = TokenPurpose::LoginCode;
    let code = OtpCode::generate().unwrap();
    let challenge = challenge(&pool, user).await;
    let subject = TokenSubject::user_and_challenge(user, challenge);
    create(
        &pool,
        &new_token(
            purpose,
            h.hash(purpose.as_str(), &code),
            subject,
            Duration::from_secs(600),
        ),
        true,
    )
    .await;
    let right = h.hash(purpose.as_str(), &code);
    let barrier = Arc::new(Barrier::new(PARALLEL));
    let mut tasks = Vec::new();
    for _ in 0..PARALLEL {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            // Lookup by challenge only (SES-19).
            OneTimeTokenRepository::verify_code(
                &pool,
                purpose,
                TokenSubject::challenge(challenge),
                &right,
                NOW,
            )
            .await
            .unwrap()
        }));
    }
    let mut verified = 0;
    for task in tasks {
        match task.await.unwrap() {
            CodeVerification::Verified(_) => verified += 1,
            CodeVerification::NotFound => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(verified, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_03_concurrent_guessing_never_exceeds_the_attempt_limit(pool: PgPool) {
    let user = user(&pool).await;
    let h = hasher();
    let purpose = TokenPurpose::MfaSmsOtp;
    let code = OtpCode::parse("000001").unwrap();
    let mut new = new_token(
        purpose,
        h.hash(purpose.as_str(), &code),
        TokenSubject::user(user),
        Duration::from_secs(600),
    );
    new.max_attempts = 5;
    create(&pool, &new, true).await;
    let subject = TokenSubject::user(user);
    let barrier = Arc::new(Barrier::new(PARALLEL * 2));
    let mut tasks = Vec::new();
    for i in 0..PARALLEL * 2 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        let guess = h.hash(
            purpose.as_str(),
            &OtpCode::parse(&format!("{:06}", 100 + i)).unwrap(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            OneTimeTokenRepository::verify_code(&pool, purpose, subject, &guess, NOW)
                .await
                .unwrap()
        }));
    }
    let (mut invalid, mut locked, mut not_found) = (0, 0, 0);
    for task in tasks {
        match task.await.unwrap() {
            CodeVerification::Invalid { .. } => invalid += 1,
            CodeVerification::LockedOut => locked += 1,
            CodeVerification::NotFound => not_found += 1,
            CodeVerification::Verified(_) => panic!("a wrong guess verified"),
        }
    }
    assert_eq!(invalid, 4);
    assert_eq!(locked, 1);
    assert_eq!(not_found, PARALLEL * 2 - 5);
    let (attempts, revoked): (i32, bool) = sqlx::query_as(
        "SELECT attempts, revoked_at IS NOT NULL FROM one_time_tokens WHERE id = $1",
    )
    .bind(new.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attempts, 5);
    assert!(revoked);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_link_and_code_of_a_group_revoke_each_other(pool: PgPool) {
    let user = user(&pool).await;
    let h = hasher();
    let subject = TokenSubject::user(user);
    for consume_link_first in [true, false] {
        let group = Uuid::now_v7();
        let link = OpaqueToken::generate().unwrap();
        let code = OtpCode::generate().unwrap();
        let mut link_row = new_token(
            TokenPurpose::EmailVerification,
            link.hash(),
            subject,
            Duration::from_secs(900),
        );
        link_row.group_id = Some(group);
        let code_purpose = TokenPurpose::EmailVerificationCode;
        let mut code_row = new_token(
            code_purpose,
            h.hash(code_purpose.as_str(), &code),
            subject,
            Duration::from_secs(900),
        );
        code_row.group_id = Some(group);
        create(&pool, &link_row, true).await;
        create(&pool, &code_row, true).await;
        let code_hash = h.hash(code_purpose.as_str(), &code);
        if consume_link_first {
            assert!(consume(&pool, TokenPurpose::EmailVerification, &link.hash(), NOW).await);
            assert_eq!(
                OneTimeTokenRepository::verify_code(&pool, code_purpose, subject, &code_hash, NOW)
                    .await
                    .unwrap(),
                CodeVerification::NotFound
            );
        } else {
            assert!(matches!(
                OneTimeTokenRepository::verify_code(&pool, code_purpose, subject, &code_hash, NOW)
                    .await
                    .unwrap(),
                CodeVerification::Verified(_)
            ));
            assert!(!consume(&pool, TokenPurpose::EmailVerification, &link.hash(), NOW).await);
        }
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_06_revocation_and_cleanup(pool: PgPool) {
    let user = user(&pool).await;
    let subject = TokenSubject::user(user);
    let a = OpaqueToken::generate().unwrap();
    let b = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::PasswordReset,
            a.hash(),
            subject,
            Duration::from_secs(60),
        ),
        false,
    )
    .await;
    create(
        &pool,
        &new_token(
            TokenPurpose::NotMe,
            b.hash(),
            subject,
            Duration::from_secs(3600),
        ),
        false,
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    let revoked = OneTimeTokenRepository::revoke_for_user(
        &mut conn,
        user,
        &[TokenPurpose::PasswordReset, TokenPurpose::PasswordResetCode],
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(revoked, 1);
    assert!(!consume(&pool, TokenPurpose::PasswordReset, &a.hash(), NOW).await);
    assert_eq!(
        OneTimeTokenRepository::revoke_active(&mut conn, subject, TokenPurpose::NotMe, NOW)
            .await
            .unwrap(),
        1
    );
    let deleted =
        OneTimeTokenRepository::delete_expired(&mut conn, NOW + Duration::from_secs(120), 100)
            .await
            .unwrap();
    assert_eq!(deleted, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_06_invalid_inputs_are_refused_before_sql(pool: PgPool) {
    let user = user(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let base = new_token(
        TokenPurpose::PasswordReset,
        OpaqueToken::generate().unwrap().hash(),
        TokenSubject::user(user),
        Duration::from_secs(60),
    );
    let mut expired = base.clone();
    expired.expires_at = NOW;
    let mut attempts = base.clone();
    attempts.max_attempts = 0;
    let mut metadata = base.clone();
    metadata.metadata = serde_json::json!([1]);
    let long_target = "x".repeat(321);
    let mut target = base.clone();
    target.target = Some(&long_target);
    for case in [expired, attempts, metadata, target] {
        assert!(matches!(
            OneTimeTokenRepository::create(&mut conn, &case, true)
                .await
                .unwrap_err(),
            StoreError::CheckViolation { .. }
        ));
    }
    // A challenge that does not exist violates the foreign key.
    let orphan = new_token(
        TokenPurpose::LoginCode,
        OpaqueToken::generate().unwrap().hash(),
        TokenSubject::challenge(ChallengeId::generate()),
        Duration::from_secs(60),
    );
    assert!(matches!(
        OneTimeTokenRepository::create(&mut conn, &orphan, true)
            .await
            .unwrap_err(),
        StoreError::ForeignKeyViolation { .. }
    ));
}

/// Creates a revert link issued at `at` (each with its own id; UUIDv7 ids
/// break timestamp ties in issue order).
async fn revert_link(
    pool: &PgPool,
    user: UserId,
    at: OffsetDateTime,
) -> (OpaqueToken, OneTimeTokenId) {
    let token = OpaqueToken::generate().unwrap();
    let mut new = new_token(
        TokenPurpose::EmailChangeRevert,
        token.hash(),
        TokenSubject::user(user),
        Duration::from_secs(7 * 86_400),
    );
    new.created_at = at;
    new.expires_at = at + Duration::from_secs(7 * 86_400);
    create(pool, &new, false).await;
    (token, new.id)
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_revoke_since_cancels_later_links_but_keeps_earlier_ones(pool: PgPool) {
    let victim = user(&pool).await;
    let other = user(&pool).await;
    // Owner's change (t0), attacker's change from the intermediate address
    // (t1, same instant as t2), and one more change (t2).
    let (owner_link, _) = revert_link(&pool, victim, NOW).await;
    let t1 = NOW + Duration::from_secs(60);
    let (attacker_link, attacker_id) = revert_link(&pool, victim, t1).await;
    let (later_link, _) = revert_link(&pool, victim, t1).await;
    let (unrelated, _) = revert_link(&pool, other, t1).await;

    let mut conn = pool.acquire().await.unwrap();
    let revoked = OneTimeTokenRepository::revoke_for_user_since(
        &mut conn,
        victim,
        &[TokenPurpose::EmailChangeRevert],
        (t1, attacker_id),
        t1,
    )
    .await
    .unwrap();
    assert_eq!(revoked, 2, "the reference link and the later one");
    drop(conn);
    let later = t1 + Duration::from_secs(1);
    assert!(
        !consume(
            &pool,
            TokenPurpose::EmailChangeRevert,
            &attacker_link.hash(),
            later
        )
        .await
    );
    assert!(
        !consume(
            &pool,
            TokenPurpose::EmailChangeRevert,
            &later_link.hash(),
            later
        )
        .await
    );
    // The owner's earlier link and other users' links survive.
    assert!(
        consume(
            &pool,
            TokenPurpose::EmailChangeRevert,
            &owner_link.hash(),
            later
        )
        .await
    );
    assert!(
        consume(
            &pool,
            TokenPurpose::EmailChangeRevert,
            &unrelated.hash(),
            later
        )
        .await
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_active_for_user_lists_only_usable_tokens_of_the_given_purposes(pool: PgPool) {
    let owner = user(&pool).await;
    let stranger = user(&pool).await;
    let subject = TokenSubject::user(owner);
    let live = OpaqueToken::generate().unwrap();
    let mut live_new = new_token(
        TokenPurpose::EmailChange,
        live.hash(),
        subject,
        Duration::from_secs(3600),
    );
    live_new.target = Some("new@example.com");
    create(&pool, &live_new, false).await;
    let newer = OpaqueToken::generate().unwrap();
    let mut newer_new = new_token(
        TokenPurpose::AccountDeletionCancel,
        newer.hash(),
        subject,
        Duration::from_secs(3600),
    );
    newer_new.created_at = NOW + Duration::from_secs(1);
    newer_new.expires_at = NOW + Duration::from_secs(3600);
    create(&pool, &newer_new, false).await;
    // Consumed, revoked, expired, another module's purpose, another user.
    let consumed = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::EmailVerification,
            consumed.hash(),
            subject,
            Duration::from_secs(3600),
        ),
        false,
    )
    .await;
    assert!(
        consume(
            &pool,
            TokenPurpose::EmailVerification,
            &consumed.hash(),
            NOW
        )
        .await
    );
    let expired = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::EmailVerification,
            expired.hash(),
            subject,
            Duration::from_secs(10),
        ),
        false,
    )
    .await;
    let foreign = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::PasswordReset,
            foreign.hash(),
            subject,
            Duration::from_secs(3600),
        ),
        false,
    )
    .await;
    let strangers = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::EmailChange,
            strangers.hash(),
            TokenSubject::user(stranger),
            Duration::from_secs(3600),
        ),
        false,
    )
    .await;
    let revoked = OpaqueToken::generate().unwrap();
    create(
        &pool,
        &new_token(
            TokenPurpose::EmailChangeRevert,
            revoked.hash(),
            subject,
            Duration::from_secs(3600),
        ),
        false,
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    OneTimeTokenRepository::revoke_for_user(
        &mut conn,
        owner,
        &[TokenPurpose::EmailChangeRevert],
        NOW,
    )
    .await
    .unwrap();

    let account_purposes = [
        TokenPurpose::EmailVerification,
        TokenPurpose::EmailChange,
        TokenPurpose::EmailChangeRevert,
        TokenPurpose::AccountDeletionCancel,
    ];
    let at = NOW + Duration::from_secs(30);
    let active = OneTimeTokenRepository::active_for_user(&pool, owner, &account_purposes, at)
        .await
        .unwrap();
    assert_eq!(
        active.iter().map(|t| t.id).collect::<Vec<_>>(),
        vec![newer_new.id, live_new.id],
        "newest first, unusable and foreign rows excluded"
    );
    assert_eq!(active[1].target.as_deref(), Some("new@example.com"));
    // Debug never shows the target (personal data).
    assert!(!format!("{:?}", active[1]).contains("new@example.com"));
    assert!(
        OneTimeTokenRepository::active_for_user(&pool, owner, &[], at)
            .await
            .unwrap()
            .is_empty()
    );
}
