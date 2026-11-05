#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Operational commands (OPS-01, CRY-08, SOC-07 / K-34, K-51): `rotate-kek`
//! covers every envelope-encrypted column of the schema, including the
//! social-login ones, and the configured Apple key; `seal-apple-key`.

use std::collections::BTreeSet;

use authn_core::config::crypto::KekConfig;
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::CryptoServices;
use authn_crypto::envelope::EnvelopeContext;
use authn_server::operations::{self, AppleKeyRewrap};
use sqlx::PgPool;

const EC_KEY: &str = include_str!("../../authn-oidc-client/tests/fixtures/test_ec_p256.pem");
const KEK_2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_08_rotate_kek_covers_every_sealed_column_of_the_schema(pool: PgPool) {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns \
         WHERE table_schema = current_schema() \
         AND (column_name LIKE '%\\_ciphertext' OR column_name = 'sealed_payload')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let in_schema: BTreeSet<(String, String)> = rows.into_iter().collect();
    // Re-wrapped by their owners' own functions.
    let mut covered: BTreeSet<(String, String)> = [
        ("signing_keys", "private_key_ciphertext"),
        ("webhook_endpoints", "secret_ciphertext"),
        ("webhook_endpoints", "previous_secret_ciphertext"),
    ]
    .into_iter()
    .map(|(t, c)| (t.to_owned(), c.to_owned()))
    .collect();
    covered.extend(
        operations::sealed_columns()
            .into_iter()
            .map(|(t, c)| (t.to_owned(), c.to_owned())),
    );
    assert_eq!(
        in_schema, covered,
        "every envelope-encrypted column must be re-wrapped by rotate-kek"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_08_rotate_kek_rewraps_social_login_ciphertexts_and_the_apple_key(pool: PgPool) {
    authn_core::tls::install_crypto_provider();
    let mut config = authn_testkit::config::test_config();
    let old = CryptoServices::from_config(&config.crypto).await.unwrap();

    // A queued provider token (K-35) and the configured Apple key, sealed
    // with the old KEK.
    let id = uuid::Uuid::now_v7();
    let sealed = old
        .envelopes
        .seal(
            b"apple-refresh-token",
            &EnvelopeContext::new("oauth_token_revocations", "token_ciphertext", id).unwrap(),
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO oauth_token_revocations \
         (id, provider, client_id, token_ciphertext, token_type_hint, attempts, next_attempt_at, created_at) \
         VALUES ($1, 'apple', 'com.example.web', $2, 'refresh_token', 0, now(), now())",
    )
    .bind(id)
    .bind(&sealed)
    .execute(&pool)
    .await
    .unwrap();
    let apple = operations::seal_apple_key(&old.envelopes, EC_KEY)
        .await
        .unwrap();

    // Rotation: a new current KEK, the old one still configured.
    config.crypto.keks.push(KekConfig {
        id: "test-kek-2".to_owned(),
        key: SecretString::from(KEK_2.to_owned()),
    });
    config.crypto.current_kek_id = "test-kek-2".to_owned();
    config.oidc_client.apple = Some(authn_core::config::oidc_client::AppleProvider {
        client_id: "com.example.web".to_owned(),
        team_id: "TEAMID1234".to_owned(),
        key_id: "APPLEKEY01".to_owned(),
        private_key_pem: None,
        private_key_file: None,
        private_key_ciphertext: Some(SecretString::from(apple.clone())),
        native_client_ids: Vec::new(),
        revoke_tokens_on_deletion: true,
    });
    let both = CryptoServices::from_config(&config.crypto).await.unwrap();
    let report = operations::rotate_kek(&pool, &both.envelopes)
        .await
        .unwrap();
    assert_eq!(report.other, 1, "{report:?}");
    let AppleKeyRewrap::Rewrapped(new_apple) =
        operations::rewrap_apple_key(&config, &both.envelopes)
            .await
            .unwrap()
    else {
        panic!("the Apple key must be re-wrapped")
    };
    assert_ne!(new_apple, apple);
    // Idempotent: a second run has nothing left to do.
    assert_eq!(
        operations::rotate_kek(&pool, &both.envelopes)
            .await
            .unwrap()
            .other,
        0
    );

    // Only the new KEK remains: everything still opens.
    config.crypto.keks.retain(|k| k.id == "test-kek-2");
    let new = CryptoServices::from_config(&config.crypto).await.unwrap();
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_ciphertext FROM oauth_token_revocations WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let opened = new
        .envelopes
        .open(
            &stored,
            &EnvelopeContext::new("oauth_token_revocations", "token_ciphertext", id).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(opened.expose(), b"apple-refresh-token");
    let mut provider = config.oidc_client.apple.clone().unwrap();
    provider.private_key_ciphertext = Some(SecretString::from(new_apple));
    authn_oidc_client::apple::resolve_private_key(&mut provider, &new.envelopes)
        .await
        .unwrap();
    assert_eq!(
        provider.private_key_pem.unwrap().expose_secret().trim(),
        EC_KEY.trim()
    );
    // The old envelope no longer opens without the old KEK.
    let mut stale = config.oidc_client.apple.clone().unwrap();
    stale.private_key_ciphertext = Some(SecretString::from(apple));
    assert!(
        authn_oidc_client::apple::resolve_private_key(&mut stale, &new.envelopes)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn soc_07_seal_apple_key_refuses_non_keys_without_echoing_them() {
    authn_core::tls::install_crypto_provider();
    let config = authn_testkit::config::test_config();
    let crypto = CryptoServices::from_config(&config.crypto).await.unwrap();
    let secret_looking =
        "-----BEGIN PRIVATE KEY-----\nNOTAKEYsecretmaterial42\n-----END PRIVATE KEY-----";
    let err = operations::seal_apple_key(&crypto.envelopes, secret_looking)
        .await
        .unwrap_err();
    assert!(!format!("{err} {err:?}").contains("secretmaterial42"));
    // The CLI maps exactly this context to an input error (exit code 65).
    assert_eq!(err.context(), Some(operations::NOT_AN_APPLE_KEY));
    let sealed = operations::seal_apple_key(&crypto.envelopes, EC_KEY)
        .await
        .unwrap();
    assert!(!sealed.contains("PRIVATE KEY"));
}

/// Wave 3A audit: `rotate-kek` reads in keyset pages (bounded memory on
/// large tables) and still re-wraps every row across page boundaries.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_08_rotate_kek_rewraps_every_row_across_pages(pool: PgPool) {
    authn_core::tls::install_crypto_provider();
    let mut config = authn_testkit::config::test_config();
    let old = CryptoServices::from_config(&config.crypto).await.unwrap();
    const ROWS: usize = 1_203;
    for _ in 0..ROWS {
        let id = uuid::Uuid::now_v7();
        let sealed = old
            .envelopes
            .seal(
                b"queued-token",
                &EnvelopeContext::new("oauth_token_revocations", "token_ciphertext", id).unwrap(),
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO oauth_token_revocations \
             (id, provider, client_id, token_ciphertext, token_type_hint, attempts, next_attempt_at, created_at) \
             VALUES ($1, 'apple', 'com.example.web', $2, 'refresh_token', 0, now(), now())",
        )
        .bind(id)
        .bind(&sealed)
        .execute(&pool)
        .await
        .unwrap();
    }
    config.crypto.keks.push(KekConfig {
        id: "test-kek-2".to_owned(),
        key: SecretString::from(KEK_2.to_owned()),
    });
    config.crypto.current_kek_id = "test-kek-2".to_owned();
    let both = CryptoServices::from_config(&config.crypto).await.unwrap();
    let report = operations::rotate_kek(&pool, &both.envelopes)
        .await
        .unwrap();
    assert_eq!(report.other, ROWS as u64);
    config.crypto.keks.retain(|k| k.id == "test-kek-2");
    let new = CryptoServices::from_config(&config.crypto).await.unwrap();
    let rows: Vec<(uuid::Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT id, token_ciphertext FROM oauth_token_revocations")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), ROWS);
    for (id, sealed) in rows {
        new.envelopes
            .open(
                &sealed,
                &EnvelopeContext::new("oauth_token_revocations", "token_ciphertext", id).unwrap(),
            )
            .await
            .unwrap();
    }
}
