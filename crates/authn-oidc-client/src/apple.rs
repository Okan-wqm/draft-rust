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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use authn_core::config::oidc_client::AppleProvider;
use authn_core::error::AuthError;
use authn_core::secret::{ExposeSecret, SensitiveString};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    client_id: String,
    ttl: Duration,
    cache: Mutex<Option<Cached>>,
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
    /// Parses the configured PKCS#8 PEM key (fail fast at start-up).
    pub fn from_config(config: &AppleProvider, ttl: Duration) -> Result<Self, AuthError> {
        let pem = Zeroizing::new(config.private_key_pem.expose_secret().to_owned());
        Self::new(
            &pem,
            &config.team_id,
            &config.key_id,
            &config.client_id,
            ttl,
        )
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
                ttl,
                cache: Mutex::new(None),
            }),
        })
    }

    /// The current client secret; a new one is signed when none is cached
    /// or less than a quarter of the lifetime is left.
    pub fn current(&self, now: OffsetDateTime) -> Result<SensitiveString, AuthError> {
        let inner = &self.inner;
        let refresh_margin = inner.ttl / 4;
        let mut cache = inner
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = cache.as_ref()
            && cached.expires_at - now > refresh_margin
        {
            return Ok(cached.jwt.clone());
        }
        let expires_at = now + inner.ttl;
        let jwt = self.sign(now, expires_at)?;
        *cache = Some(Cached {
            jwt: jwt.clone(),
            expires_at,
        });
        Ok(jwt)
    }

    fn sign(
        &self,
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
            "sub": inner.client_id,
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
