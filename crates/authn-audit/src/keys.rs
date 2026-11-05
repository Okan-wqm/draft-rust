//! Keys of the keyed hash chain (AUD-02, K-77).
//!
//! Every event written by a keyed [`crate::PgAuditSink`] is chained with
//! `HMAC-SHA-256(K_v, prev_hash ‖ canonical_json(record))` and stores `v`
//! in `audit_events.chain_key_version`. `K_v` is version `v` of the
//! `KeyPurpose::AuditChain` key family of `authn-crypto`
//! ([`authn_crypto::kdf::AuditChainKeys`]): derived from
//! `crypto.hmac_root_key`, never stored in the database, never logged.
//!
//! [`ChainKeys`] carries that family plus the version for new events and
//! the operator's pinned end of the legacy (unkeyed) prefix.

use std::collections::BTreeMap;

use authn_core::config::audit::AuditChainConfig;
use authn_core::error::AuthError;
use authn_crypto::kdf::{AuditChainKeys, HmacKey, KeyRing};

/// Highest chain key version (`smallint` column).
pub const MAX_KEY_VERSION: u16 = 32_767;

/// The audit chain keys of a writer or verifier.
#[derive(Clone)]
pub struct ChainKeys {
    family: AuditChainKeys,
    current: u16,
    legacy_until_seq: Option<i64>,
}

impl std::fmt::Debug for ChainKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainKeys")
            .field("current_version", &self.current)
            .field("legacy_until_seq", &self.legacy_until_seq)
            .finish_non_exhaustive()
    }
}

impl ChainKeys {
    /// Keys with `current_version` (`1..=32767`) for new events.
    pub fn new(family: AuditChainKeys, current_version: u16) -> Result<Self, AuthError> {
        if !(1..=MAX_KEY_VERSION).contains(&current_version) {
            return Err(AuthError::internal("audit chain key version out of range"));
        }
        Ok(Self {
            family,
            current: current_version,
            legacy_until_seq: None,
        })
    }

    /// The keys of `[audit.chain]` from the key ring (CRY-11).
    pub fn from_config(ring: &KeyRing, config: &AuditChainConfig) -> Result<Self, AuthError> {
        let family = ring.audit_chain_keys().map_err(AuthError::from)?;
        Ok(Self::new(family, config.key_version)?.with_legacy_until_seq(config.legacy_until_seq))
    }

    /// Pins the last sequence number that may be an unkeyed event:
    /// verification rejects every unkeyed event after it.
    #[must_use]
    pub fn with_legacy_until_seq(mut self, seq: Option<i64>) -> Self {
        self.legacy_until_seq = seq;
        self
    }

    /// Version used for new events (unless the chain already uses a newer
    /// one).
    #[must_use]
    pub fn current_version(&self) -> u16 {
        self.current
    }

    /// The pinned end of the unkeyed prefix.
    #[must_use]
    pub fn legacy_until_seq(&self) -> Option<i64> {
        self.legacy_until_seq
    }

    /// The MAC key of `version`.
    pub(crate) fn key(&self, version: u16) -> Result<HmacKey, AuthError> {
        if !(1..=MAX_KEY_VERSION).contains(&version) {
            return Err(AuthError::internal("audit chain key version out of range"));
        }
        self.family.version(version).map_err(AuthError::from)
    }
}

/// Per-verification cache of derived version keys.
#[derive(Default)]
pub(crate) struct KeyCache {
    keys: BTreeMap<u16, HmacKey>,
}

impl KeyCache {
    pub(crate) fn get(&mut self, keys: &ChainKeys, version: u16) -> Result<&HmacKey, AuthError> {
        match self.keys.entry(version) {
            std::collections::btree_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            std::collections::btree_map::Entry::Vacant(entry) => {
                Ok(entry.insert(keys.key(version)?))
            }
        }
    }
}

/// Converts a stored `smallint` version.
pub(crate) fn version_from_db(value: i16) -> Option<u16> {
    u16::try_from(value).ok().filter(|v| *v >= 1)
}

/// Converts a version for storage.
pub(crate) fn version_to_db(version: u16) -> Result<i16, AuthError> {
    i16::try_from(version).map_err(|_| AuthError::internal("audit chain key version out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_77_chain_keys_never_show_key_material() {
        let ring = KeyRing::derive(&[5_u8; 32]).unwrap();
        let keys = ChainKeys::new(ring.audit_chain_keys().unwrap(), 2).unwrap();
        let debug = format!("{keys:?}");
        let k1 = keys.key(1).unwrap();
        let k2 = keys.key(2).unwrap();
        for key in [&k1, &k2] {
            let hex = crate::canonical::hex(key.expose());
            assert!(!debug.contains(&hex), "{debug}");
        }
        assert!(debug.contains("current_version: 2"));
        assert_ne!(k1, k2);
        assert!(ChainKeys::new(ring.audit_chain_keys().unwrap(), 0).is_err());
        assert!(ChainKeys::new(ring.audit_chain_keys().unwrap(), 32_768).is_err());
        assert!(keys.key(0).is_err());
        assert_eq!(version_from_db(0), None);
        assert_eq!(version_from_db(-1), None);
        assert_eq!(version_from_db(3), Some(3));
    }
}
