//! Versioned password pepper (CRY-02).
//!
//! Argon2 input = `HMAC-SHA256(pepper[v], canonical password)`. The pepper
//! lives only in configuration, never in the database, so a database dump
//! alone cannot be attacked offline. Several versions can be configured at
//! once; new hashes always use the current version and older versions are
//! upgraded transparently at login (CRY-03).

use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroizing;

use crate::CryptoError;
use crate::kdf::hmac_sha256;
use crate::secret::SecretBytes;

/// Minimum pepper length in bytes.
pub const MIN_PEPPER_BYTES: usize = 32;

/// The configured pepper keys.
#[derive(Clone)]
pub struct Peppers {
    current: u32,
    keys: BTreeMap<u32, SecretBytes>,
}

impl Peppers {
    /// Builds the set. Every key must have ≥ 32 bytes, versions must be ≥ 1
    /// and unique, and `current` must be one of them.
    pub fn new(
        current: u32,
        keys: impl IntoIterator<Item = (u32, SecretBytes)>,
    ) -> Result<Self, CryptoError> {
        let mut map = BTreeMap::new();
        for (version, key) in keys {
            if version == 0 || key.len() < MIN_PEPPER_BYTES {
                return Err(CryptoError::InvalidKey);
            }
            if map.insert(version, key).is_some() {
                return Err(CryptoError::InvalidKey);
            }
        }
        if !map.contains_key(&current) {
            return Err(CryptoError::UnknownKey);
        }
        Ok(Self { current, keys: map })
    }

    /// Loads `crypto.peppers` / `crypto.current_pepper_version`.
    pub fn from_config(
        config: &authn_core::config::crypto::CryptoConfig,
    ) -> Result<Self, CryptoError> {
        let mut keys = Vec::with_capacity(config.peppers.len());
        for pepper in &config.peppers {
            let material = authn_core::config::common::decode_key_material(&pepper.key)
                .ok_or(CryptoError::InvalidKey)?;
            keys.push((pepper.version, SecretBytes::from(material)));
        }
        Self::new(config.current_pepper_version, keys)
    }

    /// Version used for new hashes.
    #[must_use]
    pub const fn current_version(&self) -> u32 {
        self.current
    }

    /// Whether `version` is configured.
    #[must_use]
    pub fn contains(&self, version: u32) -> bool {
        self.keys.contains_key(&version)
    }

    /// `HMAC-SHA256(pepper[version], input)`.
    pub fn apply(&self, version: u32, input: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let key = self.keys.get(&version).ok_or(CryptoError::UnknownKey)?;
        Ok(Zeroizing::new(hmac_sha256(key.expose(), input)?))
    }
}

impl fmt::Debug for Peppers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peppers")
            .field("current", &self.current)
            .field("versions", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peppers() -> Peppers {
        Peppers::new(
            2,
            [
                (1, SecretBytes::new(vec![1; 32])),
                (2, SecretBytes::new(vec![2; 32])),
            ],
        )
        .unwrap()
    }

    #[test]
    fn cry_02_versions_produce_different_outputs() {
        let p = peppers();
        assert_eq!(p.current_version(), 2);
        let a = p.apply(1, b"password").unwrap();
        let b = p.apply(2, b"password").unwrap();
        assert_ne!(*a, *b);
        assert_eq!(*a, hmac_sha256(&[1; 32], b"password").unwrap());
        assert_eq!(
            p.apply(3, b"password").unwrap_err(),
            CryptoError::UnknownKey
        );
    }

    #[test]
    fn cry_02_invalid_sets_are_refused() {
        let short = SecretBytes::new(vec![1; 31]);
        assert!(Peppers::new(1, [(1, short)]).is_err());
        assert!(Peppers::new(2, [(1, SecretBytes::new(vec![1; 32]))]).is_err());
        assert!(Peppers::new(0, [(0, SecretBytes::new(vec![1; 32]))]).is_err());
        assert!(
            Peppers::new(
                1,
                [
                    (1, SecretBytes::new(vec![1; 32])),
                    (1, SecretBytes::new(vec![2; 32]))
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn cry_13_debug_lists_versions_only() {
        let debug = format!("{:?}", peppers());
        assert!(debug.contains("current: 2"));
        assert!(!debug.contains("[1, 1"));
    }

    #[test]
    fn cry_02_loads_from_test_config() {
        let config = authn_testkit::config::test_config();
        let p = Peppers::from_config(&config.crypto).unwrap();
        assert_eq!(p.current_version(), 1);
        assert!(p.contains(1));
    }
}
