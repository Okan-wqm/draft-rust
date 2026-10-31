//! Ed25519 signing-key material and lifecycle states (CRY-10, crypto side).
//!
//! Persistence and state transitions live in
//! `authn_store::signing_keys`; this module provides the key types, the
//! state enum and the envelope binding of private keys
//! (`signing_keys.private_key_ciphertext`, AAD = table/column/key id).

use std::fmt;
use std::str::FromStr;

use authn_core::id::SigningKeyId;
use ed25519_dalek::Signer as _;
use zeroize::Zeroizing;

use crate::envelope::{EnvelopeCipher, EnvelopeContext};
use crate::{CryptoError, ct, random};

/// Lifecycle state of a signing key (`signing_keys.status`).
///
/// `pending` → `active` → `retired` → (dropped from JWKS after
/// `publish_until`); any state → `revoked` (emergency, removed at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningKeyStatus {
    /// Published in the JWKS, not yet used for signing.
    Pending,
    /// The single key used for signing new tokens.
    Active,
    /// No longer signs; still published until `publish_until`.
    Retired,
    /// Compromised or withdrawn: never published, never trusted.
    Revoked,
}

impl SigningKeyStatus {
    /// Every state.
    pub const ALL: &'static [Self] = &[Self::Pending, Self::Active, Self::Retired, Self::Revoked];

    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }
}

impl fmt::Display for SigningKeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SigningKeyStatus {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|v| v.as_str() == s)
            .ok_or(CryptoError::Malformed)
    }
}

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey(ed25519_dalek::VerifyingKey);

impl Ed25519PublicKey {
    /// Parses a 32-byte compressed point; rejects invalid encodings and
    /// small-order ("weak") keys.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(&array).map_err(|_| CryptoError::InvalidKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(key))
    }

    /// The 32 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Strict verification (RFC 8032 with the canonical-`S` and small-order
    /// checks of `verify_strict`).
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        self.0.verify_strict(message, &signature).is_ok()
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ed25519PublicKey({})",
            crate::encoding::b64url_encode(&self.to_bytes())
        )
    }
}

/// An Ed25519 private key. Zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    /// A new key from 32 CSPRNG bytes.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = random::secret_bytes::<32>()?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// From the 32-byte RFC 8032 secret (seed).
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        let array: Zeroizing<[u8; 32]> =
            Zeroizing::new(seed.try_into().map_err(|_| CryptoError::InvalidKey)?);
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&array)))
    }

    /// The 32-byte seed (to seal it with envelope encryption).
    #[must_use]
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verifying_key())
    }

    /// Signs `message` (deterministic RFC 8032 signature).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }

    /// Verifies with the corresponding public key (strict).
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.public_key().verify(message, signature)
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("public", &self.public_key())
            .field("seed", &crate::secret::REDACTED)
            .finish()
    }
}

/// Envelope context of `signing_keys.private_key_ciphertext` for key `id`.
pub fn private_key_context(id: SigningKeyId) -> Result<EnvelopeContext, CryptoError> {
    EnvelopeContext::new("signing_keys", "private_key_ciphertext", id)
}

/// Seals the private key of `id`.
pub async fn seal_private_key(
    cipher: &EnvelopeCipher,
    id: SigningKeyId,
    key: &Ed25519SigningKey,
) -> Result<Vec<u8>, CryptoError> {
    cipher
        .seal(key.seed().as_slice(), &private_key_context(id)?)
        .await
}

/// Opens the private key of `id` and checks that it matches the stored
/// public key (a substituted ciphertext for another key fails here even if
/// it were somehow authentic).
pub async fn open_private_key(
    cipher: &EnvelopeCipher,
    id: SigningKeyId,
    envelope: &[u8],
    stored_public_key: &[u8],
) -> Result<Ed25519SigningKey, CryptoError> {
    let seed = cipher.open(envelope, &private_key_context(id)?).await?;
    let key = Ed25519SigningKey::from_seed(seed.expose())?;
    if !ct::constant_time_eq(&key.public_key().to_bytes(), stored_public_key) {
        return Err(CryptoError::Unauthentic);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::encoding::hex;
    use crate::envelope::{EnvKeyProvider, KekId};
    use crate::secret::SecretKey;

    fn unhex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    /// RFC 8032 §7.1 TEST 1–3.
    #[test]
    fn cry_14_ed25519_rfc8032_vectors() {
        let vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, public, message, signature) in vectors {
            let key = Ed25519SigningKey::from_seed(&unhex(seed)).unwrap();
            assert_eq!(hex(&key.public_key().to_bytes()), public);
            let message = unhex(message);
            let sig = key.sign(&message);
            assert_eq!(hex(&sig), signature);
            let public = Ed25519PublicKey::from_bytes(&unhex(public)).unwrap();
            assert!(public.verify(&message, &sig));
            assert!(key.verify(&message, &sig));
            let mut bad = sig;
            bad[0] ^= 1;
            assert!(!public.verify(&message, &bad));
            assert!(!public.verify(b"other", &sig));
            assert!(!public.verify(&message, &sig[..63]));
        }
    }

    #[test]
    fn cry_10_weak_and_malformed_public_keys_are_rejected() {
        // The identity point (small order).
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        assert!(Ed25519PublicKey::from_bytes(&identity).is_err());
        assert!(Ed25519PublicKey::from_bytes(&[0; 31]).is_err());
    }

    #[test]
    fn cry_10_status_round_trip() {
        for status in SigningKeyStatus::ALL {
            assert_eq!(
                status.as_str().parse::<SigningKeyStatus>().unwrap(),
                *status
            );
            assert_eq!(status.to_string(), status.as_str());
        }
        assert!("Active".parse::<SigningKeyStatus>().is_err());
    }

    #[tokio::test]
    async fn cry_10_private_keys_are_sealed_and_bound_to_their_row() {
        let cipher = EnvelopeCipher::new(Arc::new(
            EnvKeyProvider::new(
                "k",
                [(KekId::new("k").unwrap(), SecretKey::from_bytes([5; 32]))],
            )
            .unwrap(),
        ));
        let key = Ed25519SigningKey::generate().unwrap();
        let id = SigningKeyId::generate();
        let sealed = seal_private_key(&cipher, id, &key).await.unwrap();
        assert!(!sealed.windows(32).any(|w| w == key.seed().as_slice()));
        let public = key.public_key().to_bytes();
        let opened = open_private_key(&cipher, id, &sealed, &public)
            .await
            .unwrap();
        assert_eq!(opened.public_key(), key.public_key());
        // Another row id, or another stored public key, fails.
        assert!(
            open_private_key(&cipher, SigningKeyId::generate(), &sealed, &public)
                .await
                .is_err()
        );
        let other = Ed25519SigningKey::generate()
            .unwrap()
            .public_key()
            .to_bytes();
        assert_eq!(
            open_private_key(&cipher, id, &sealed, &other)
                .await
                .unwrap_err(),
            CryptoError::Unauthentic
        );
        assert!(!format!("{key:?}").contains(&hex(key.seed().as_slice())));
    }
}
