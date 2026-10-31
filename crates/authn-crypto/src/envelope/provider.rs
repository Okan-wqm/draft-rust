//! Key-encryption-key providers (CRY-08).
//!
//! A [`KeyProvider`] wraps and unwraps per-record data keys (DEKs) with a
//! key-encryption key (KEK) it controls. The default [`EnvKeyProvider`]
//! holds versioned 32-byte KEKs from configuration (`crypto.keks`, which
//! figment also reads from `AUTHN__CRYPTO__KEKS…` environment variables). A
//! KMS-backed provider implements the same trait: the KEK then never leaves
//! the KMS and only the wrapped DEK blob is stored in the envelope.

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::secret::{REDACTED, SecretKey};
use crate::{CryptoError, random};

/// A 32-byte data-encryption key.
pub type DataKey = SecretKey<32>;

/// Maximum length of a KEK id.
pub const MAX_KEK_ID_LEN: usize = 32;

/// Identifier of a key-encryption key (`[A-Za-z0-9_-]{1,32}`), embedded in
/// every envelope.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KekId(String);

impl KekId {
    /// Validates an id.
    pub fn new(id: &str) -> Result<Self, CryptoError> {
        let valid = !id.is_empty()
            && id.len() <= MAX_KEK_ID_LEN
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if valid {
            Ok(Self(id.to_owned()))
        } else {
            Err(CryptoError::Malformed)
        }
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KekId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KekId({})", self.0)
    }
}

impl fmt::Display for KekId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A DEK wrapped by a KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDataKey {
    /// The KEK that wrapped the DEK.
    pub kek_id: KekId,
    /// Provider-specific opaque blob (authenticated; not secret).
    pub blob: Vec<u8>,
}

/// Source of key-encryption keys.
///
/// Implementations must be authenticated-encryption based: unwrapping with
/// the wrong KEK, the wrong `aad` or a modified blob must fail with
/// [`CryptoError::Unauthentic`] (or [`CryptoError::UnknownKey`]).
#[async_trait]
pub trait KeyProvider: Send + Sync + 'static {
    /// KEK used for new envelopes.
    fn current_kek_id(&self) -> &KekId;

    /// Wraps `dek` with the current KEK, binding `aad`.
    async fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<WrappedDataKey, CryptoError>;

    /// Unwraps a DEK previously wrapped by `kek_id` with the same `aad`.
    async fn unwrap(&self, kek_id: &KekId, blob: &[u8], aad: &[u8])
    -> Result<DataKey, CryptoError>;
}

/// Size of an [`EnvKeyProvider`] blob: 24-byte nonce, 32-byte key, 16-byte tag.
pub const ENV_BLOB_LEN: usize = 24 + 32 + 16;

/// KEKs held in process memory, loaded from configuration / environment.
///
/// Wrapping: `XChaCha20-Poly1305(KEK, random 192-bit nonce, DEK,
/// aad = "authn-kek/v1" || len(kek_id) || kek_id || aad)`.
#[derive(Clone)]
pub struct EnvKeyProvider {
    current: KekId,
    keys: BTreeMap<KekId, SecretKey<32>>,
}

impl EnvKeyProvider {
    /// Builds the provider; `current` must be one of `keys`.
    pub fn new(
        current: &str,
        keys: impl IntoIterator<Item = (KekId, SecretKey<32>)>,
    ) -> Result<Self, CryptoError> {
        let mut map = BTreeMap::new();
        for (id, key) in keys {
            if map.insert(id, key).is_some() {
                return Err(CryptoError::InvalidKey);
            }
        }
        let current = KekId::new(current)?;
        if !map.contains_key(&current) {
            return Err(CryptoError::UnknownKey);
        }
        Ok(Self { current, keys: map })
    }

    /// Loads `crypto.keks` / `crypto.current_kek_id` (base64, exactly 32
    /// bytes each).
    pub fn from_config(
        config: &authn_core::config::crypto::CryptoConfig,
    ) -> Result<Self, CryptoError> {
        let mut keys = Vec::with_capacity(config.keks.len());
        for kek in &config.keks {
            let material = authn_core::config::common::decode_key_material(&kek.key)
                .ok_or(CryptoError::InvalidKey)?;
            keys.push((KekId::new(&kek.id)?, SecretKey::from_slice(&material)?));
        }
        Self::new(&config.current_kek_id, keys)
    }

    /// Configured KEK ids.
    pub fn kek_ids(&self) -> impl Iterator<Item = &KekId> {
        self.keys.keys()
    }

    fn cipher(&self, id: &KekId) -> Result<XChaCha20Poly1305, CryptoError> {
        let key = self.keys.get(id).ok_or(CryptoError::UnknownKey)?;
        Ok(XChaCha20Poly1305::new(key.expose().into()))
    }

    fn wrap_aad(id: &KekId, aad: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(16 + id.0.len() + aad.len()));
        out.extend_from_slice(b"authn-kek/v1");
        // KekId is at most 32 bytes, the length fits a byte.
        out.push(u8::try_from(id.0.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(id.0.as_bytes());
        out.extend_from_slice(aad);
        out
    }

    /// Synchronous wrap (the trait method delegates here).
    pub fn wrap_sync(&self, dek: &DataKey, aad: &[u8]) -> Result<WrappedDataKey, CryptoError> {
        let cipher = self.cipher(&self.current)?;
        let nonce = random::bytes::<24>()?;
        let full_aad = Self::wrap_aad(&self.current, aad);
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: dek.expose(),
                    aad: &full_aad,
                },
            )
            .map_err(|_| CryptoError::Internal("kek wrap failed"))?;
        let mut blob = Vec::with_capacity(ENV_BLOB_LEN);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&sealed);
        Ok(WrappedDataKey {
            kek_id: self.current.clone(),
            blob,
        })
    }

    /// Synchronous unwrap (the trait method delegates here).
    pub fn unwrap_sync(
        &self,
        kek_id: &KekId,
        blob: &[u8],
        aad: &[u8],
    ) -> Result<DataKey, CryptoError> {
        if blob.len() != ENV_BLOB_LEN {
            return Err(CryptoError::Malformed);
        }
        let cipher = self.cipher(kek_id)?;
        let (nonce, sealed) = blob.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| CryptoError::Malformed)?;
        let full_aad = Self::wrap_aad(kek_id, aad);
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: sealed,
                        aad: &full_aad,
                    },
                )
                .map_err(|_| CryptoError::Unauthentic)?,
        );
        SecretKey::from_slice(&plain)
    }
}

#[async_trait]
impl KeyProvider for EnvKeyProvider {
    fn current_kek_id(&self) -> &KekId {
        &self.current
    }

    async fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<WrappedDataKey, CryptoError> {
        self.wrap_sync(dek, aad)
    }

    async fn unwrap(
        &self,
        kek_id: &KekId,
        blob: &[u8],
        aad: &[u8],
    ) -> Result<DataKey, CryptoError> {
        self.unwrap_sync(kek_id, blob, aad)
    }
}

impl fmt::Debug for EnvKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvKeyProvider")
            .field("current", &self.current)
            .field("kek_ids", &self.keys.keys().collect::<Vec<_>>())
            .field("keys", &REDACTED)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(current: &str) -> EnvKeyProvider {
        EnvKeyProvider::new(
            current,
            [
                (KekId::new("k1").unwrap(), SecretKey::from_bytes([1; 32])),
                (KekId::new("k2").unwrap(), SecretKey::from_bytes([2; 32])),
            ],
        )
        .unwrap()
    }

    #[test]
    fn cry_08_kek_ids_are_validated() {
        assert!(KekId::new("kek-2026_01").is_ok());
        for bad in ["", "a b", "é", &"a".repeat(33), "a/b"] {
            assert!(KekId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn cry_08_wrap_unwrap_round_trip_and_binding() {
        let p = provider("k1");
        let dek = DataKey::generate().unwrap();
        let wrapped = p.wrap_sync(&dek, b"ctx").unwrap();
        assert_eq!(wrapped.kek_id.as_str(), "k1");
        assert_eq!(wrapped.blob.len(), ENV_BLOB_LEN);
        assert_eq!(
            p.unwrap_sync(&wrapped.kek_id, &wrapped.blob, b"ctx")
                .unwrap(),
            dek
        );
        // Wrong AAD, wrong KEK id, tampered blob, unknown KEK all fail.
        assert_eq!(
            p.unwrap_sync(&wrapped.kek_id, &wrapped.blob, b"other")
                .unwrap_err(),
            CryptoError::Unauthentic
        );
        assert_eq!(
            p.unwrap_sync(&KekId::new("k2").unwrap(), &wrapped.blob, b"ctx")
                .unwrap_err(),
            CryptoError::Unauthentic
        );
        let mut tampered = wrapped.blob.clone();
        tampered[30] ^= 1;
        assert!(p.unwrap_sync(&wrapped.kek_id, &tampered, b"ctx").is_err());
        assert_eq!(
            p.unwrap_sync(&KekId::new("k9").unwrap(), &wrapped.blob, b"ctx")
                .unwrap_err(),
            CryptoError::UnknownKey
        );
        assert!(
            p.unwrap_sync(&wrapped.kek_id, &wrapped.blob[1..], b"ctx")
                .is_err()
        );
    }

    #[test]
    fn cry_08_provider_configuration() {
        assert!(
            EnvKeyProvider::new(
                "k3",
                [(KekId::new("k1").unwrap(), SecretKey::from_bytes([1; 32]))]
            )
            .is_err()
        );
        assert!(
            EnvKeyProvider::new(
                "k1",
                [
                    (KekId::new("k1").unwrap(), SecretKey::from_bytes([1; 32])),
                    (KekId::new("k1").unwrap(), SecretKey::from_bytes([2; 32]))
                ]
            )
            .is_err()
        );
        let config = authn_testkit::config::test_config();
        let p = EnvKeyProvider::from_config(&config.crypto).unwrap();
        assert_eq!(p.current_kek_id().as_str(), "test-kek-1");
        let debug = format!("{p:?}");
        assert!(debug.contains(REDACTED) && debug.contains("test-kek-1"));
    }
}
