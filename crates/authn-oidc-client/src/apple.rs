//! Sign in with Apple specifics (SOC-07).
//!
//! * **`client_secret`** is an ES256-signed JWT (`iss` = team id, `sub` =
//!   services id, `aud` = `https://appleid.apple.com`, `kid` = key id). It is
//!   signed **only with `p256` 0.14** (RFC 6979 deterministic ECDSA, no RNG);
//!   the older `p256`/`p384` 0.13 pulled in by `openidconnect`
//!   (RUSTSEC-2026-0387) is used for public-key verification only. The JWT
//!   is cached and regenerated when less than a quarter of its lifetime is
//!   left.
//! * The **`user`** form field Apple posts on the first authorization only
//!   (`{"name":{"firstName":…,"lastName":…},"email":…}`) is unsigned: only
//!   the name is taken from it (a display name), never the e-mail address —
//!   the address always comes from the verified ID token.
//! * Private relay addresses (`…@privaterelay.appleid.com`) are ordinary
//!   verified addresses; `is_private_email` is kept for the identity.
//! * The **private key** comes from exactly one of `private_key_pem`,
//!   `private_key_file` or `private_key_ciphertext` (K-34): the latter is
//!   an authn-crypto envelope sealed with the `[crypto]` KEK for the fixed
//!   context [`private_key_context`], decrypted once at start-up
//!   ([`resolve_private_key`], called by `OidcClientService::build`) and
//!   produced with [`seal_private_key`]. Key material never appears in
//!   `Debug` output, logs or error messages.
//! * Client secrets are signed per **client id** (K-35): the web flow uses
//!   the services id, a native authorization-code exchange or a token
//!   revocation for a native token uses the app's bundle id (Apple checks
//!   that `sub` equals the `client_id` of the request). Only configured
//!   client ids can be signed for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use authn_core::config::oidc_client::AppleProvider;
use authn_core::error::AuthError;
use authn_core::secret::{ExposeSecret, SecretString, SensitiveString};
use authn_crypto::envelope::{EnvelopeCipher, EnvelopeContext};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use secrecy::zeroize::Zeroizing;
use time::OffsetDateTime;

/// `aud` of Apple client secrets.
pub const APPLE_AUDIENCE: &str = "https://appleid.apple.com";

/// Largest accepted `user` form field.
const MAX_USER_FIELD_BYTES: usize = 4096;

#[derive(Clone)]
struct Cached {
    jwt: SensitiveString,
    expires_at: OffsetDateTime,
}

struct Inner {
    key: SigningKey,
    team_id: String,
    key_id: String,
    /// The web services id (`client_id` of the browser flow).
    client_id: String,
    /// Every client id a secret may be signed for: the services id and the
    /// native bundle ids.
    client_ids: Vec<String>,
    ttl: Duration,
    cache: Mutex<HashMap<String, Cached>>,
}

/// Generates and caches Apple `client_secret` JWTs. Cheap to clone.
#[derive(Clone)]
pub struct AppleClientSecret {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for AppleClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleClientSecret")
            .field("team_id", &self.inner.team_id)
            .field("key_id", &self.inner.key_id)
            .finish_non_exhaustive()
    }
}

fn b64_json(value: &serde_json::Value) -> Result<String, AuthError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AuthError::internal("serializing the apple client secret"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

impl AppleClientSecret {
    /// Parses the configured PKCS#8 PEM key — inline
    /// (`private_key_pem`) or from `private_key_file` (SOC-07) — and fails
    /// fast at start-up. The file's content and path never appear in errors.
    ///
    /// An envelope-encrypted key (`private_key_ciphertext`) must have been
    /// decrypted first ([`resolve_private_key`]); otherwise this fails.
    pub fn from_config(config: &AppleProvider, ttl: Duration) -> Result<Self, AuthError> {
        let pem = match (
            &config.private_key_pem,
            &config.private_key_file,
            &config.private_key_ciphertext,
        ) {
            (Some(inline), None, None) => Zeroizing::new(inline.expose_secret().to_owned()),
            (None, Some(path), None) => {
                Zeroizing::new(std::fs::read_to_string(path).map_err(|_| {
                    AuthError::internal("oidc_client.apple.private_key_file could not be read")
                })?)
            }
            (None, None, Some(_)) => {
                return Err(AuthError::internal(
                    "oidc_client.apple.private_key_ciphertext must be decrypted at start-up \
                     (OidcClientService::build)",
                ));
            }
            _ => {
                return Err(AuthError::internal(
                    "exactly one of oidc_client.apple.private_key_pem, private_key_file and \
                     private_key_ciphertext must be set",
                ));
            }
        };
        let mut secret = Self::new(
            &pem,
            &config.team_id,
            &config.key_id,
            &config.client_id,
            ttl,
        )?;
        if let Some(inner) = Arc::get_mut(&mut secret.inner) {
            for id in &config.native_client_ids {
                if !inner.client_ids.contains(id) {
                    inner.client_ids.push(id.clone());
                }
            }
        }
        Ok(secret)
    }

    /// A generator from explicit values.
    pub fn new(
        pem: &str,
        team_id: &str,
        key_id: &str,
        client_id: &str,
        ttl: Duration,
    ) -> Result<Self, AuthError> {
        let key = SigningKey::from_pkcs8_pem(pem.trim()).map_err(|_| {
            AuthError::internal("oidc_client.apple.private_key_pem is not a PKCS#8 P-256 key")
        })?;
        if ttl < Duration::from_secs(60) || ttl > Duration::from_secs(180 * 86_400) {
            return Err(AuthError::internal(
                "apple client secret lifetime must be between 1 minute and 180 days",
            ));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                key,
                team_id: team_id.to_owned(),
                key_id: key_id.to_owned(),
                client_id: client_id.to_owned(),
                client_ids: vec![client_id.to_owned()],
                ttl,
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// The current client secret of the web services id; a new one is
    /// signed when none is cached or less than a quarter of the lifetime is
    /// left.
    pub fn current(&self, now: OffsetDateTime) -> Result<SensitiveString, AuthError> {
        self.current_for(&self.inner.client_id, now)
    }

    /// The current client secret for `client_id` (the services id or a
    /// configured native bundle id; anything else is refused).
    pub fn current_for(
        &self,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<SensitiveString, AuthError> {
        let inner = &self.inner;
        if !inner.client_ids.iter().any(|id| id == client_id) {
            return Err(AuthError::internal("apple client id is not configured"));
        }
        let refresh_margin = inner.ttl / 4;
        let mut cache = inner
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = cache.get(client_id)
            && cached.expires_at - now > refresh_margin
        {
            return Ok(cached.jwt.clone());
        }
        let expires_at = now + inner.ttl;
        let jwt = self.sign(client_id, now, expires_at)?;
        cache.insert(
            client_id.to_owned(),
            Cached {
                jwt: jwt.clone(),
                expires_at,
            },
        );
        Ok(jwt)
    }

    fn sign(
        &self,
        client_id: &str,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<SensitiveString, AuthError> {
        let inner = &self.inner;
        let header = serde_json::json!({ "alg": "ES256", "kid": inner.key_id, "typ": "JWT" });
        let claims = serde_json::json!({
            "iss": inner.team_id,
            "iat": now.unix_timestamp(),
            "exp": expires_at.unix_timestamp(),
            "aud": APPLE_AUDIENCE,
            "sub": client_id,
        });
        let signing_input = format!("{}.{}", b64_json(&header)?, b64_json(&claims)?);
        let signature: Signature = inner
            .key
            .try_sign(signing_input.as_bytes())
            .map_err(|_| AuthError::internal("signing the apple client secret"))?;
        let encoded = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(SensitiveString::new(format!("{signing_input}.{encoded}")))
    }
}

/// Envelope context (AAD) of `oidc_client.apple.private_key_ciphertext`:
/// fixed, so the ciphertext cannot be swapped with any other envelope of
/// the system (a stored token, a TOTP secret…) and decrypt.
pub fn private_key_context() -> Result<EnvelopeContext, AuthError> {
    Ok(EnvelopeContext::new(
        "oidc_client",
        "apple_private_key",
        "apple",
    )?)
}

/// Seals a PKCS#8 PEM Apple key for `oidc_client.apple.private_key_ciphertext`
/// (standard base64 of the envelope) with the current `[crypto]` KEK. For
/// operator tooling (authn-server CLI); the key is validated first.
pub async fn seal_private_key(
    envelopes: &EnvelopeCipher,
    pem: &SecretString,
) -> Result<SecretString, AuthError> {
    SigningKey::from_pkcs8_pem(pem.expose_secret().trim())
        .map_err(|_| AuthError::internal("apple private key is not a PKCS#8 P-256 key"))?;
    let sealed = envelopes
        .seal(pem.expose_secret().as_bytes(), &private_key_context()?)
        .await?;
    Ok(SecretString::from(STANDARD.encode(sealed)))
}

/// Replaces `private_key_ciphertext` by the decrypted PEM (K-34). Called
/// once at start-up; a no-op for the other key sources. Failures name the
/// setting, never its content.
pub async fn resolve_private_key(
    config: &mut AppleProvider,
    envelopes: &EnvelopeCipher,
) -> Result<(), AuthError> {
    let Some(ciphertext) = config.private_key_ciphertext.take() else {
        return Ok(());
    };
    if config.private_key_pem.is_some() || config.private_key_file.is_some() {
        return Err(AuthError::internal(
            "exactly one of oidc_client.apple.private_key_pem, private_key_file and \
             private_key_ciphertext must be set",
        ));
    }
    let envelope = Zeroizing::new(STANDARD.decode(ciphertext.expose_secret().trim()).map_err(
        |_| AuthError::internal("oidc_client.apple.private_key_ciphertext is not base64"),
    )?);
    let opened = envelopes
        .open(&envelope, &private_key_context()?)
        .await
        .map_err(|_| {
            AuthError::internal(
                "oidc_client.apple.private_key_ciphertext could not be decrypted with the \
                 configured KEKs",
            )
        })?;
    let pem = std::str::from_utf8(opened.expose())
        .map_err(|_| AuthError::internal("oidc_client.apple.private_key_ciphertext is corrupt"))?;
    config.private_key_pem = Some(SecretString::from(pem.to_owned()));
    Ok(())
}

/// The display name from Apple's first-authorization `user` field, if the
/// field is well-formed. Never fails: a malformed field is ignored.
#[must_use]
pub fn display_name_from_user_field(user: Option<&str>) -> Option<String> {
    let raw = user?;
    if raw.len() > MAX_USER_FIELD_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let name = value.get("name")?;
    let part = |key: &str| {
        name.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let joined = match (part("firstName"), part("lastName")) {
        (Some(first), Some(last)) => format!("{first} {last}"),
        (Some(one), None) | (None, Some(one)) => one.to_owned(),
        (None, None) => return None,
    };
    crate::identity::clean_display_name(&joined)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;

    use super::*;

    const TEST_EC_KEY: &str = include_str!("../tests/fixtures/test_ec_p256.pem");

    fn decode(part: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    fn apple_config(pem: Option<&str>, file: Option<std::path::PathBuf>) -> AppleProvider {
        AppleProvider {
            client_id: "com.example.web".to_owned(),
            team_id: "TEAMID1234".to_owned(),
            key_id: "KEYID12345".to_owned(),
            private_key_pem: pem.map(|p| authn_core::secret::SecretString::from(p.to_owned())),
            private_key_file: file,
            private_key_ciphertext: None,
            native_client_ids: vec!["com.example.app".to_owned()],
            revoke_tokens_on_deletion: true,
        }
    }

    #[test]
    fn soc_07_private_key_is_read_from_a_file_or_inline() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("authn-apple-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("apple.p8");
        std::fs::write(&path, TEST_EC_KEY).unwrap();
        let ttl = Duration::from_secs(3600);
        let from_file = AppleClientSecret::from_config(&apple_config(None, Some(path)), ttl);
        assert!(from_file.is_ok());
        let inline = AppleClientSecret::from_config(&apple_config(Some(TEST_EC_KEY), None), ttl);
        assert!(inline.is_ok());
        // Missing file, neither and both sources fail fast.
        let missing = dir.join("missing.p8");
        assert!(AppleClientSecret::from_config(&apple_config(None, Some(missing)), ttl).is_err());
        assert!(AppleClientSecret::from_config(&apple_config(None, None), ttl).is_err());
        let both = apple_config(Some(TEST_EC_KEY), Some(dir.join("apple.p8")));
        assert!(AppleClientSecret::from_config(&both, ttl).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn soc_07_client_secret_is_es256_signed_with_apple_claims() {
        let secret = AppleClientSecret::new(
            TEST_EC_KEY,
            "TEAMID1234",
            "KEYID12345",
            "com.example.web",
            Duration::from_secs(3600),
        )
        .unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let jwt = secret.current(now).unwrap();
        let parts: Vec<&str> = jwt.expose().split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = decode(parts[0]);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID12345");
        let claims = decode(parts[1]);
        assert_eq!(claims["iss"], "TEAMID1234");
        assert_eq!(claims["sub"], "com.example.web");
        assert_eq!(claims["aud"], APPLE_AUDIENCE);
        assert_eq!(claims["iat"], 1_800_000_000);
        assert_eq!(claims["exp"], 1_800_003_600);

        let key = SigningKey::from_pkcs8_pem(TEST_EC_KEY).unwrap();
        let verifying: &VerifyingKey = key.verifying_key();
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 64, "JWS ES256 signatures are r||s");
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
    }

    #[test]
    fn soc_07_client_secret_is_signed_per_configured_client_id() {
        let secret = AppleClientSecret::from_config(
            &apple_config(Some(TEST_EC_KEY), None),
            Duration::from_secs(3600),
        )
        .unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let web = secret.current(now).unwrap();
        let native = secret.current_for("com.example.app", now).unwrap();
        let sub =
            |jwt: &SensitiveString| decode(jwt.expose().split('.').nth(1).unwrap())["sub"].clone();
        assert_eq!(sub(&web), "com.example.web");
        assert_eq!(sub(&native), "com.example.app");
        assert!(secret.current_for("com.attacker.app", now).is_err());
    }

    async fn cipher() -> EnvelopeCipher {
        let config = authn_testkit::config::TestConfigBuilder::new().build();
        authn_crypto::CryptoServices::from_config(&config.crypto)
            .await
            .unwrap()
            .envelopes
    }

    #[tokio::test]
    async fn soc_07_envelope_encrypted_private_key_round_trip() {
        let envelopes = cipher().await;
        let sealed = seal_private_key(&envelopes, &SecretString::from(TEST_EC_KEY.to_owned()))
            .await
            .unwrap();
        assert!(!sealed.expose_secret().contains("PRIVATE KEY"));
        let mut config = apple_config(None, None);
        config.private_key_ciphertext = Some(sealed.clone());
        // Not decrypted yet: refused (fail fast), without the value.
        let err = AppleClientSecret::from_config(&config, Duration::from_secs(3600)).unwrap_err();
        assert!(!format!("{err:?}").contains(sealed.expose_secret()));
        resolve_private_key(&mut config, &envelopes).await.unwrap();
        assert!(config.private_key_ciphertext.is_none());
        assert!(AppleClientSecret::from_config(&config, Duration::from_secs(3600)).is_ok());
        // Debug output never shows the key material.
        let debug = format!("{config:?}");
        assert!(!debug.contains("PRIVATE KEY"), "{debug}");
    }

    #[tokio::test]
    async fn soc_07_tampered_or_foreign_ciphertext_is_refused_without_detail() {
        let envelopes = cipher().await;
        // Sealed for another context (e.g. a stored token): cannot be
        // swapped in.
        let foreign = envelopes
            .seal(
                TEST_EC_KEY.as_bytes(),
                &EnvelopeContext::new("identities", "refresh_token_ciphertext", "x").unwrap(),
            )
            .await
            .unwrap();
        for value in [
            STANDARD.encode(&foreign),
            "not base64 !!".to_owned(),
            STANDARD.encode(b"garbage"),
        ] {
            let mut config = apple_config(None, None);
            config.private_key_ciphertext = Some(SecretString::from(value.clone()));
            let err = resolve_private_key(&mut config, &envelopes)
                .await
                .unwrap_err();
            let text = format!("{err:?} {err}");
            assert!(!text.contains(&value), "{text}");
            assert!(!text.contains("PRIVATE KEY"), "{text}");
            assert!(config.private_key_pem.is_none());
        }
        // Another source at the same time is refused.
        let mut both = apple_config(Some(TEST_EC_KEY), None);
        both.private_key_ciphertext = Some(SecretString::from("x".to_owned()));
        assert!(resolve_private_key(&mut both, &envelopes).await.is_err());
    }

    #[test]
    fn soc_07_client_secret_is_cached_and_renewed_before_expiry() {
        let secret = AppleClientSecret::new(
            TEST_EC_KEY,
            "TEAMID1234",
            "KEYID12345",
            "com.example.web",
            Duration::from_secs(3600),
        )
        .unwrap();
        let t0 = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let first = secret.current(t0).unwrap();
        // Still more than a quarter left: same JWT.
        let later = secret.current(t0 + time::Duration::minutes(40)).unwrap();
        assert_eq!(first, later);
        // Less than 15 minutes left: renewed.
        let renewed = secret.current(t0 + time::Duration::minutes(50)).unwrap();
        assert_ne!(first, renewed);
    }

    #[test]
    fn soc_07_invalid_key_fails_fast() {
        assert!(
            AppleClientSecret::new("not a key", "T", "K", "C", Duration::from_secs(3600)).is_err()
        );
        assert!(
            AppleClientSecret::new(TEST_EC_KEY, "T", "K", "C", Duration::from_secs(1)).is_err()
        );
    }

    #[test]
    fn soc_07_first_login_name_is_taken_from_the_user_field() {
        assert_eq!(
            display_name_from_user_field(Some(
                r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"x@privaterelay.appleid.com"}"#
            ))
            .as_deref(),
            Some("Ada Lovelace")
        );
        assert_eq!(
            display_name_from_user_field(Some(r#"{"name":{"firstName":"Ada"}}"#)).as_deref(),
            Some("Ada")
        );
        assert_eq!(display_name_from_user_field(Some("{not json")), None);
        assert_eq!(display_name_from_user_field(None), None);
        let huge = format!(r#"{{"name":{{"firstName":"{}"}}}}"#, "a".repeat(5000));
        assert_eq!(display_name_from_user_field(Some(&huge)), None);
    }
}
