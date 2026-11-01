//! Keyed hashing of identifiers that contain personal data (PRT-02, RSK-02).
//!
//! Rate-limit keys contain e-mail addresses, IPs and phone numbers; device
//! ids are bearer-like identifiers. None of them is ever stored in clear text:
//! they are HMAC-SHA256'd under the `RateLimitKey` purpose key of the
//! [`KeyRing`] (CRY-11). Every use is framed with its own label
//! (`HmacKey::sign_fields`), so a tag computed for one use can never collide
//! with a tag computed for another.

use std::fmt;

use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::RateLimitKey;
use authn_crypto::kdf::{HmacKey, KeyPurpose, KeyRing};

const RATE_LIMIT_LABEL: &[u8] = b"authn/protect/rate-limit-key/v1";
const DEVICE_LABEL: &[u8] = b"authn/protect/known-device/v1";

/// Computes the keyed hashes used by the rate limiters and the risk store.
#[derive(Clone)]
pub struct KeyHasher {
    key: HmacKey,
}

impl KeyHasher {
    /// Uses the `RateLimitKey` purpose key of `ring`.
    pub fn new(ring: &KeyRing) -> Result<Self, AuthError> {
        let key = ring
            .key(KeyPurpose::RateLimitKey)
            .map_err(|_| AuthError::internal("rate-limit purpose key missing"))?
            .clone();
        Ok(Self { key })
    }

    /// Builds a hasher directly from a purpose key (tests, embedding).
    #[must_use]
    pub fn from_key(key: HmacKey) -> Self {
        Self { key }
    }

    /// The 32-byte storage key of a rate-limit key.
    #[must_use]
    pub fn rate_limit_key(&self, key: &RateLimitKey) -> [u8; 32] {
        self.key
            .sign_fields(&[RATE_LIMIT_LABEL, key.canonical().as_bytes()])
    }

    /// The 32-byte storage hash of a client device id, bound to the user so
    /// the same device id yields unrelated hashes for different accounts.
    #[must_use]
    pub fn device(&self, user: UserId, device_id: &str) -> [u8; 32] {
        self.key.sign_fields(&[
            DEVICE_LABEL,
            user.as_uuid().as_bytes(),
            device_id.as_bytes(),
        ])
    }
}

impl fmt::Debug for KeyHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyHasher([REDACTED])")
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use authn_crypto::kdf::KeyRing;

    use super::KeyHasher;

    /// A hasher over a fixed, public test root key.
    pub(crate) fn hasher() -> KeyHasher {
        KeyHasher::new(&KeyRing::derive(&[7_u8; 32]).unwrap()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prt_02_rate_limit_keys_are_keyed_hashes_without_personal_data() {
        let hasher = test_support::hasher();
        let key = RateLimitKey::account("login", "alice@example.com");
        let hash = hasher.rate_limit_key(&key);
        assert_eq!(hash, hasher.rate_limit_key(&key));
        assert_ne!(
            hash,
            hasher.rate_limit_key(&RateLimitKey::account("login", "bob@example.com"))
        );
        // Plain SHA-256 of the canonical form would be guessable from a
        // dictionary of e-mail addresses; the keyed hash is not.
        assert_ne!(hash, authn_crypto::sha256(key.canonical().as_bytes()));
        let other = KeyHasher::new(&KeyRing::derive(&[8_u8; 32]).unwrap()).unwrap();
        assert_ne!(hash, other.rate_limit_key(&key));
        assert_eq!(format!("{hasher:?}"), "KeyHasher([REDACTED])");
    }

    #[test]
    fn rsk_02_device_hashes_are_bound_to_the_user() {
        let hasher = test_support::hasher();
        let (a, b) = (UserId::generate(), UserId::generate());
        assert_ne!(
            hasher.device(a, "device-0123456789"),
            hasher.device(b, "device-0123456789")
        );
        assert_eq!(
            hasher.device(a, "device-0123456789"),
            hasher.device(a, "device-0123456789")
        );
    }
}
