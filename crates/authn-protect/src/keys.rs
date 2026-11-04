//! Keyed hashing of identifiers that contain personal data (PRT-02, RSK-02).
//!
//! Rate-limit keys contain e-mail addresses, IPs and phone numbers; device
//! ids are bearer-like identifiers. None of them is ever stored in clear text:
//! rate-limit keys are HMAC-SHA256'd under the `RateLimitKey` purpose key
//! and device ids under the separate `KnownDevice` purpose key of the
//! [`KeyRing`] (CRY-11: one HKDF `info` label per purpose). Every use is
//! additionally framed with its own label (`HmacKey::sign_fields`).
//!
//! Migration note (K-21): device hashes were computed under the
//! `RateLimitKey` key before. Rows written that way no longer match, so
//! each user's device is "learned" again on the next login: the only effect
//! is a one-time "new device" signal (risk score / `NewDeviceLogin` notice)
//! per remembered device, after which the row is stored under the new key.

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
    device_key: HmacKey,
}

impl KeyHasher {
    /// Uses the `RateLimitKey` and `KnownDevice` purpose keys of `ring`.
    pub fn new(ring: &KeyRing) -> Result<Self, AuthError> {
        let key = ring
            .key(KeyPurpose::RateLimitKey)
            .map_err(|_| AuthError::internal("rate-limit purpose key missing"))?
            .clone();
        let device_key = ring
            .key(KeyPurpose::KnownDevice)
            .map_err(|_| AuthError::internal("known-device purpose key missing"))?
            .clone();
        Ok(Self { key, device_key })
    }

    /// Builds a hasher directly from the two purpose keys (tests,
    /// embedding): `rate_limit` for rate-limit keys, `known_device` for
    /// device hashes.
    #[must_use]
    pub fn from_keys(rate_limit: HmacKey, known_device: HmacKey) -> Self {
        Self {
            key: rate_limit,
            device_key: known_device,
        }
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
        self.device_key.sign_fields(&[
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

    /// K-21 (CRY-11): device hashes use their own HKDF purpose key, not the
    /// rate-limit key (the hash the previous version stored differs).
    #[test]
    fn cry_11_device_hashes_use_the_known_device_purpose_key() {
        let ring = KeyRing::derive(&[7_u8; 32]).unwrap();
        let hasher = KeyHasher::new(&ring).unwrap();
        let user = UserId::generate();
        let expected = ring.key(KeyPurpose::KnownDevice).unwrap().sign_fields(&[
            DEVICE_LABEL,
            user.as_uuid().as_bytes(),
            b"device-0123456789",
        ]);
        assert_eq!(hasher.device(user, "device-0123456789"), expected);
        let legacy = ring.key(KeyPurpose::RateLimitKey).unwrap().sign_fields(&[
            DEVICE_LABEL,
            user.as_uuid().as_bytes(),
            b"device-0123456789",
        ]);
        assert_ne!(hasher.device(user, "device-0123456789"), legacy);
    }
}
