#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Integration tests of the signing-key lifecycle (CRY-08, CRY-09, CRY-10,
//! SES-09) against real PostgreSQL.

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::crypto::SigningKeyConfig;
use authn_crypto::envelope::{EnvKeyProvider, EnvelopeCipher, KekId};
use authn_crypto::jwt::{JwtError, JwtValidation, TYP_ACCESS_TOKEN};
use authn_crypto::secret::SecretKey;
use authn_crypto::signing::SigningKeyStatus;
use authn_store::signing_keys::RotationReport;
use authn_store::{SigningKeyError, SigningKeyRepository};
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use time::macros::datetime;
use tokio::sync::Barrier;

const T0: OffsetDateTime = datetime!(2026-01-01 00:00:00 UTC);
const ISS: &str = "https://auth.test.example";
const AUD: &str = "https://api.test.example";

fn cipher(current: &str, keys: &[(&str, u8)]) -> EnvelopeCipher {
    EnvelopeCipher::new(Arc::new(
        EnvKeyProvider::new(
            current,
            keys.iter()
                .map(|(id, b)| (KekId::new(id).unwrap(), SecretKey::from_bytes([*b; 32]))),
        )
        .unwrap(),
    ))
}

fn kek1() -> EnvelopeCipher {
    cipher("kek-1", &[("kek-1", 1)])
}

fn config() -> SigningKeyConfig {
    SigningKeyConfig::default()
}

fn claims(at: OffsetDateTime) -> Value {
    let now = at.unix_timestamp();
    json!({"iss": ISS, "aud": AUD, "sub": "u", "iat": now, "exp": now + 600})
}

async fn rotate(pool: &PgPool, cipher: &EnvelopeCipher, at: OffsetDateTime) -> RotationReport {
    let mut conn = pool.acquire().await.unwrap();
    SigningKeyRepository::rotate_if_due(&mut conn, cipher, at, &config())
        .await
        .unwrap()
}

async fn sign(pool: &PgPool, cipher: &EnvelopeCipher, at: OffsetDateTime) -> String {
    SigningKeyRepository::load_active_signer(pool, cipher)
        .await
        .unwrap()
        .sign(TYP_ACCESS_TOKEN, &claims(at))
        .unwrap()
}

async fn verify(pool: &PgPool, token: &str, at: OffsetDateTime) -> Result<(), JwtError> {
    SigningKeyRepository::verifier(pool, at)
        .await
        .unwrap()
        .verify::<Value>(token, &JwtValidation::access_token(ISS, AUD), at)
        .map(|_| ())
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_10_first_start_bootstraps_an_active_key(pool: PgPool) {
    let c = kek1();
    let mut conn = pool.acquire().await.unwrap();
    assert!(matches!(
        SigningKeyRepository::load_active_signer(&pool, &c)
            .await
            .unwrap_err(),
        SigningKeyError::NoActiveKey
    ));
    let report = rotate(&pool, &c, T0).await;
    let id = report.bootstrapped.unwrap();
    assert_eq!(report.activated, None);
    assert_eq!(report.created_pending, None);
    let active = SigningKeyRepository::active(&mut *conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.id, id);
    assert_eq!(active.status, SigningKeyStatus::Active);
    assert_eq!(active.activated_at, Some(T0));

    let token = sign(&pool, &c, T0).await;
    assert_eq!(verify(&pool, &token, T0).await, Ok(()));
    let jwks = serde_json::to_value(SigningKeyRepository::jwks(&pool, T0).await.unwrap()).unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    assert_eq!(jwks["keys"][0]["kid"], json!(id.to_string()));
    assert!(jwks["keys"][0].get("d").is_none());
    // Nothing else to do right away.
    assert_eq!(rotate(&pool, &c, T0).await, RotationReport::default());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_10_full_rotation_lifecycle(pool: PgPool) {
    let c = kek1();
    let cfg = config();
    let first = rotate(&pool, &c, T0).await.bootstrapped.unwrap();
    let old_token = sign(&pool, &c, T0).await;

    // Rotation interval reached: a pending key is published but not used.
    let t1 = T0 + cfg.rotation_interval;
    let second = rotate(&pool, &c, t1).await.created_pending.unwrap();
    let pending = SigningKeyRepository::find(&pool, second)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.status, SigningKeyStatus::Pending);
    assert_eq!(pending.activate_after, t1 + cfg.pending_period);
    let kids: Vec<String> = SigningKeyRepository::publishable(&pool, t1)
        .await
        .unwrap()
        .iter()
        .map(authn_store::SigningKeyRecord::kid)
        .collect();
    assert_eq!(kids, vec![first.to_string(), second.to_string()]);
    let signer = SigningKeyRepository::load_active_signer(&pool, &c)
        .await
        .unwrap();
    assert_eq!(signer.kid(), first.to_string());
    // Running again before the pending period ends changes nothing.
    assert_eq!(
        rotate(&pool, &c, t1 + Duration::from_secs(60)).await,
        RotationReport::default()
    );

    // Pending period over: the new key signs, the old one is retired but
    // still published for retired_retention.
    let t2 = t1 + cfg.pending_period;
    assert_eq!(rotate(&pool, &c, t2).await.activated, Some(second));
    let retired = SigningKeyRepository::find(&pool, first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.status, SigningKeyStatus::Retired);
    assert_eq!(retired.retired_at, Some(t2));
    assert_eq!(retired.publish_until, Some(t2 + cfg.retired_retention));
    let new_token = sign(&pool, &c, t2).await;
    assert_eq!(
        SigningKeyRepository::load_active_signer(&pool, &c)
            .await
            .unwrap()
            .kid(),
        second.to_string()
    );
    // Old tokens still verify while the retired key is published (the
    // verification time is the token's lifetime, here: inside its exp).
    let old_at = T0 + Duration::from_secs(60);
    assert_eq!(
        SigningKeyRepository::verifier(&pool, t2)
            .await
            .unwrap()
            .verify::<Value>(&old_token, &JwtValidation::access_token(ISS, AUD), old_at)
            .map(|_| ()),
        Ok(())
    );
    assert_eq!(verify(&pool, &new_token, t2).await, Ok(()));

    // After retention the retired key leaves the JWKS and stops verifying.
    let t3 = t2 + cfg.retired_retention;
    let kids: Vec<String> = SigningKeyRepository::publishable(&pool, t3)
        .await
        .unwrap()
        .iter()
        .map(authn_store::SigningKeyRecord::kid)
        .collect();
    assert_eq!(kids, vec![second.to_string()]);
    assert_eq!(
        SigningKeyRepository::verifier(&pool, t3)
            .await
            .unwrap()
            .verify::<Value>(&old_token, &JwtValidation::access_token(ISS, AUD), old_at)
            .map(|_| ()),
        Err(JwtError::UnknownKey)
    );
    assert_eq!(SigningKeyRepository::list(&pool).await.unwrap().len(), 2);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_10_pending_keys_cannot_sign_before_their_period(pool: PgPool) {
    let c = kek1();
    let cfg = config();
    rotate(&pool, &c, T0).await;
    let mut conn = pool.acquire().await.unwrap();
    let pending = SigningKeyRepository::create_pending(&mut conn, &c, T0, cfg.pending_period)
        .await
        .unwrap();
    assert!(matches!(
        SigningKeyRepository::activate(&mut conn, pending.id, T0, cfg.retired_retention, false)
            .await
            .unwrap_err(),
        SigningKeyError::InvalidTransition
    ));
    assert_eq!(
        SigningKeyRepository::activate_due(&mut conn, T0, cfg.retired_retention)
            .await
            .unwrap(),
        None
    );
    let activated =
        SigningKeyRepository::activate(&mut conn, pending.id, T0, cfg.retired_retention, true)
            .await
            .unwrap();
    assert_eq!(activated.status, SigningKeyStatus::Active);
    // An active key cannot be activated again.
    assert!(matches!(
        SigningKeyRepository::activate(&mut conn, pending.id, T0, cfg.retired_retention, true)
            .await
            .unwrap_err(),
        SigningKeyError::InvalidTransition
    ));
    assert!(matches!(
        SigningKeyRepository::activate(
            &mut conn,
            authn_core::id::SigningKeyId::generate(),
            T0,
            cfg.retired_retention,
            true
        )
        .await
        .unwrap_err(),
        SigningKeyError::NotFound
    ));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_emergency_rotation_revokes_immediately(pool: PgPool) {
    let c = kek1();
    let compromised = rotate(&pool, &c, T0).await.bootstrapped.unwrap();
    let token = sign(&pool, &c, T0).await;
    let mut conn = pool.acquire().await.unwrap();
    let fresh = SigningKeyRepository::emergency_rotate(&mut conn, &c, T0)
        .await
        .unwrap();
    assert_ne!(fresh.id, compromised);
    assert_eq!(fresh.status, SigningKeyStatus::Active);
    let revoked = SigningKeyRepository::find(&pool, compromised)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.status, SigningKeyStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(T0));
    // Gone from the JWKS and from verification at once.
    assert_eq!(verify(&pool, &token, T0).await, Err(JwtError::UnknownKey));
    let kids: Vec<String> = SigningKeyRepository::publishable(&pool, T0)
        .await
        .unwrap()
        .iter()
        .map(authn_store::SigningKeyRecord::kid)
        .collect();
    assert_eq!(kids, vec![fresh.id.to_string()]);
    let token = sign(&pool, &c, T0).await;
    assert_eq!(verify(&pool, &token, T0).await, Ok(()));
    // Revoking is idempotent; revoking a pending key works too.
    let again = SigningKeyRepository::revoke(&mut conn, compromised, T0 + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(again.revoked_at, Some(T0));
    let pending = SigningKeyRepository::create_pending(&mut conn, &c, T0, config().pending_period)
        .await
        .unwrap();
    assert_eq!(
        SigningKeyRepository::revoke(&mut conn, pending.id, T0)
            .await
            .unwrap()
            .status,
        SigningKeyStatus::Revoked
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_10_missing_active_key_promotes_the_pending_one(pool: PgPool) {
    let c = kek1();
    let first = rotate(&pool, &c, T0).await.bootstrapped.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let pending = SigningKeyRepository::create_pending(&mut conn, &c, T0, config().pending_period)
        .await
        .unwrap();
    SigningKeyRepository::revoke(&mut conn, first, T0)
        .await
        .unwrap();
    let report = rotate(&pool, &c, T0).await;
    assert_eq!(report.activated, Some(pending.id));
    assert_eq!(report.bootstrapped, None);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_10_concurrent_rotation_keeps_a_single_active_key(pool: PgPool) {
    const PARALLEL: usize = 8;
    let c = kek1();
    let barrier = Arc::new(Barrier::new(PARALLEL));
    let mut tasks = Vec::new();
    for _ in 0..PARALLEL {
        let pool = pool.clone();
        let c = c.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            rotate(&pool, &c, T0).await
        }));
    }
    let mut bootstrapped = 0;
    for task in tasks {
        bootstrapped += usize::from(task.await.unwrap().bootstrapped.is_some());
    }
    assert_eq!(bootstrapped, 1);
    let (total, active): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE status = 'active') FROM signing_keys",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((total, active), (1, 1));

    // Concurrent activation of a due pending key: exactly one activation.
    let mut conn = pool.acquire().await.unwrap();
    let pending = SigningKeyRepository::create_pending(&mut conn, &c, T0, Duration::ZERO)
        .await
        .unwrap();
    drop(conn);
    let barrier = Arc::new(Barrier::new(PARALLEL));
    let mut tasks = Vec::new();
    for _ in 0..PARALLEL {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut conn = pool.acquire().await.unwrap();
            SigningKeyRepository::activate_due(&mut conn, T0, Duration::from_secs(60))
                .await
                .unwrap()
        }));
    }
    let mut activations = Vec::new();
    for task in tasks {
        activations.extend(task.await.unwrap());
    }
    assert_eq!(activations.len(), 1);
    assert_eq!(activations[0].id, pending.id);
    let active: i64 =
        sqlx::query_scalar("SELECT count(*) FROM signing_keys WHERE status = 'active'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(active, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_08_private_keys_are_encrypted_and_bound_to_the_kek(pool: PgPool) {
    let c = kek1();
    let id = rotate(&pool, &c, T0).await.bootstrapped.unwrap();
    let signer = SigningKeyRepository::load_active_signer(&pool, &c)
        .await
        .unwrap();
    let (public, sealed): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT public_key, private_key_ciphertext FROM signing_keys WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(public, signer.public_key().to_bytes().to_vec());
    assert!(sealed.len() > 32 + 16);
    // Another KEK cannot open it.
    let stranger = cipher("kek-x", &[("kek-x", 9)]);
    assert!(matches!(
        SigningKeyRepository::load_active_signer(&pool, &stranger)
            .await
            .unwrap_err(),
        SigningKeyError::Crypto(_)
    ));
    // A ciphertext copied from another key row does not open (AAD binds the id).
    let mut conn = pool.acquire().await.unwrap();
    let other = SigningKeyRepository::create_pending(&mut conn, &c, T0, Duration::ZERO)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE signing_keys SET private_key_ciphertext = \
         (SELECT private_key_ciphertext FROM signing_keys WHERE id = $2) WHERE id = $1",
    )
    .bind(id)
    .bind(other.id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        SigningKeyRepository::load_active_signer(&pool, &c)
            .await
            .unwrap_err(),
        SigningKeyError::Crypto(_)
    ));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_08_kek_rotation_rewraps_signing_keys(pool: PgPool) {
    let old = kek1();
    rotate(&pool, &old, T0).await;
    let mut conn = pool.acquire().await.unwrap();
    SigningKeyRepository::create_pending(&mut conn, &old, T0, config().pending_period)
        .await
        .unwrap();
    let both = cipher("kek-2", &[("kek-1", 1), ("kek-2", 2)]);
    assert_eq!(
        SigningKeyRepository::rewrap_private_keys(&mut conn, &both)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        SigningKeyRepository::rewrap_private_keys(&mut conn, &both)
            .await
            .unwrap(),
        0
    );
    let only_new = cipher("kek-2", &[("kek-2", 2)]);
    let token = sign(&pool, &only_new, T0).await;
    assert_eq!(verify(&pool, &token, T0).await, Ok(()));
    assert!(
        SigningKeyRepository::load_active_signer(&pool, &old)
            .await
            .is_err()
    );
}
