//! Purpose-bound sub-keys (CRY-11) and HMAC-SHA256 helpers.
//!
//! One root secret (`crypto.hmac_root_key`) is expanded with HKDF-SHA256
//! (RFC 5869) into an independent 32-byte key per [`KeyPurpose`]. Every
//! purpose has its own `info` label, so a MAC produced for one purpose (e.g. a
//! CSRF token) can never be replayed as another (e.g. a trusted-device
//! token), and leaking one derived key does not reveal the root or any
//! sibling key.
//!
//! Purposes are an enum, not strings: a typo cannot silently create a new key.

use std::collections::BTreeMap;
use std::fmt;

use hmac::{KeyInit, Mac as _};
use sha2::Sha256;

use crate::secret::SecretKey;
use crate::{CryptoError, ct};

type HmacSha256 = hmac::Hmac<Sha256>;

/// Fixed HKDF salt (domain separation of this system's key hierarchy).
const HKDF_SALT: &[u8] = b"rust-authentication/hkdf-sha256/v1";

/// Minimum length of the root secret in bytes.
pub const MIN_ROOT_KEY_BYTES: usize = 32;

/// What a derived key is used for. Each variant maps to a distinct HKDF
/// `info` label (never change a label: it would invalidate every stored MAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// Storage hash of short OTP codes (CRY-07): e-mail/SMS codes, reset
    /// codes, login codes.
    OtpCode,
    /// Storage hash of recovery codes (MFA-04).
    RecoveryCode,
    /// Synchronizer CSRF tokens bound to a session (SES-04).
    CsrfToken,
    /// Signed trusted-device tokens (MFA-09).
    TrustedDevice,
    /// Magic-link device-binding cookie (SES-18).
    DeviceBinding,
    /// Self-hosted proof-of-work CAPTCHA challenges (PRT-05).
    ProofOfWork,
    /// Pseudonymous identifiers / PII digests in the audit log (AUD-05).
    AuditPseudonym,
    /// Keyed hashing of rate-limit keys that contain personal data (PRT-02).
    RateLimitKey,
    /// Integrity tag of server-side OAuth/OIDC state (SOC-02).
    OAuthState,
    /// Sealing of webhook signing secrets derivation inputs (AUD-07).
    WebhookSecret,
}

impl KeyPurpose {
    /// Every purpose, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::OtpCode,
        Self::RecoveryCode,
        Self::CsrfToken,
        Self::TrustedDevice,
        Self::DeviceBinding,
        Self::ProofOfWork,
        Self::AuditPseudonym,
        Self::RateLimitKey,
        Self::OAuthState,
        Self::WebhookSecret,
    ];

    /// The HKDF `info` label.
    #[must_use]
    pub const fn info(self) -> &'static str {
        match self {
            Self::OtpCode => "authn/v1/otp-code",
            Self::RecoveryCode => "authn/v1/recovery-code",
            Self::CsrfToken => "authn/v1/csrf-token",
            Self::TrustedDevice => "authn/v1/trusted-device",
            Self::DeviceBinding => "authn/v1/device-binding",
            Self::ProofOfWork => "authn/v1/proof-of-work",
            Self::AuditPseudonym => "authn/v1/audit-pseudonym",
            Self::RateLimitKey => "authn/v1/rate-limit-key",
            Self::OAuthState => "authn/v1/oauth-state",
            Self::WebhookSecret => "authn/v1/webhook-secret",
        }
    }
}

/// HMAC-SHA256 (RFC 2104) of `data` under a key of any length.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    hmac_sha256_parts(key, &[data])
}

/// HMAC-SHA256 over the plain concatenation of `parts` (no framing — use
/// [`HmacKey::sign_fields`] when parts are attacker-influenced).
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], CryptoError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| CryptoError::Internal("hmac key length"))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// An HMAC-SHA256 instance keyed with a 32-byte key, without a fallible
/// constructor: a key shorter than the SHA-256 block (64 bytes) is
/// zero-padded by HMAC itself (RFC 2104 §2), so keying with the padded block
/// is exactly HMAC under the 32-byte key.
fn mac_for_key32(key: &[u8; 32]) -> HmacSha256 {
    let mut block = zeroize::Zeroizing::new([0_u8; 64]);
    block[..32].copy_from_slice(key);
    let block_ref: &[u8; 64] = &block;
    <HmacSha256 as KeyInit>::new(block_ref.into())
}

/// A 32-byte HMAC-SHA256 key.
#[derive(Clone, PartialEq, Eq)]
pub struct HmacKey(SecretKey<32>);

impl HmacKey {
    /// Wraps raw key material.
    #[must_use]
    pub fn new(key: SecretKey<32>) -> Self {
        Self(key)
    }

    /// The tag of `data`.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = mac_for_key32(self.0.expose());
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Constant-time check of a tag over `data`. Tags of the wrong length
    /// are rejected.
    #[must_use]
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        ct::constant_time_eq(&self.sign(data), tag)
    }

    /// The tag of an unambiguous encoding of several fields: each field is
    /// preceded by its length as a big-endian `u64`, so `("ab", "c")` and
    /// `("a", "bc")` produce different tags.
    #[must_use]
    pub fn sign_fields(&self, fields: &[&[u8]]) -> [u8; 32] {
        let mut mac = mac_for_key32(self.0.expose());
        for field in fields {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }

    /// Constant-time check of a [`HmacKey::sign_fields`] tag.
    #[must_use]
    pub fn verify_fields(&self, fields: &[&[u8]], tag: &[u8]) -> bool {
        ct::constant_time_eq(&self.sign_fields(fields), tag)
    }

    /// The raw key bytes (for primitives that need the key itself).
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HmacKey({})", crate::secret::REDACTED)
    }
}

/// HKDF-SHA256 expansion of `ikm` into a 32-byte key for `info`.
pub fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
) -> Result<SecretKey<32>, CryptoError> {
    let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = zeroize::Zeroizing::new([0_u8; 32]);
    hk.expand(info, okm.as_mut_slice())
        .map_err(|_| CryptoError::Internal("hkdf output length"))?;
    Ok(SecretKey::from_bytes(*okm))
}

/// Every purpose key derived from the root secret (CRY-11).
///
/// Derivation happens once at start-up; lookups are infallible.
#[derive(Clone)]
pub struct KeyRing {
    keys: BTreeMap<KeyPurpose, HmacKey>,
}

impl KeyRing {
    /// Derives every purpose key from `root` (≥ 32 bytes of CSPRNG output).
    pub fn derive(root: &[u8]) -> Result<Self, CryptoError> {
        if root.len() < MIN_ROOT_KEY_BYTES {
            return Err(CryptoError::InvalidKey);
        }
        let mut keys = BTreeMap::new();
        for purpose in KeyPurpose::ALL {
            let key = hkdf_sha256(Some(HKDF_SALT), root, purpose.info().as_bytes())?;
            keys.insert(*purpose, HmacKey::new(key));
        }
        Ok(Self { keys })
    }

    /// Derives the ring from `crypto.hmac_root_key` (base64).
    pub fn from_config(
        config: &authn_core::config::crypto::CryptoConfig,
    ) -> Result<Self, CryptoError> {
        let root = authn_core::config::common::decode_key_material(&config.hmac_root_key)
            .ok_or(CryptoError::InvalidKey)?;
        Self::derive(&root)
    }

    /// The key for `purpose`.
    pub fn key(&self, purpose: KeyPurpose) -> Result<&HmacKey, CryptoError> {
        // Every variant is inserted by `derive`; the error is unreachable
        // unless a variant is added to the enum but not to `ALL`.
        self.keys
            .get(&purpose)
            .ok_or(CryptoError::Internal("purpose key missing"))
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRing")
            .field("purposes", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::encoding::hex;

    fn unhex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .unwrap()
    }

    /// RFC 4231 §4.2–§4.7 test cases 1–4, 6, 7 (HMAC-SHA-256 column; case 5
    /// is truncated output).
    #[test]
    fn cry_14_hmac_sha256_rfc4231_vectors() {
        let cases: &[(Vec<u8>, Vec<u8>, &str)] = &[
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, data, expected) in cases {
            assert_eq!(hex(&hmac_sha256(key, data).unwrap()), *expected);
        }
    }

    /// RFC 5869 Appendix A.1–A.3 (SHA-256), first 32 bytes of the OKM.
    #[test]
    fn cry_14_hkdf_sha256_rfc5869_vectors() {
        // A.1
        let ikm = vec![0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0_u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        let derived = hkdf_sha256(Some(&salt), &ikm, &info).unwrap();
        assert_eq!(hex(derived.expose()), hex(&okm[..32]));

        // A.3 (no salt, no info)
        let mut okm = [0_u8; 42];
        hkdf::Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut okm)
            .unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn cry_11_purpose_keys_are_distinct_and_deterministic() {
        let root = [7_u8; 32];
        let ring = KeyRing::derive(&root).unwrap();
        let again = KeyRing::derive(&root).unwrap();
        let mut seen = HashSet::new();
        for purpose in KeyPurpose::ALL {
            let key = ring.key(*purpose).unwrap();
            assert_eq!(key, again.key(*purpose).unwrap());
            assert!(seen.insert(*key.expose()), "{purpose:?} collides");
            assert_ne!(key.expose(), &root);
        }
        let labels: HashSet<_> = KeyPurpose::ALL.iter().map(|p| p.info()).collect();
        assert_eq!(labels.len(), KeyPurpose::ALL.len());
        assert!(KeyRing::derive(&[1_u8; 31]).is_err());
        assert!(!format!("{ring:?}").contains("07"));
    }

    #[test]
    fn cry_11_from_test_config() {
        let config = authn_testkit::config::test_config();
        let ring = KeyRing::from_config(&config.crypto).unwrap();
        assert!(ring.key(KeyPurpose::CsrfToken).is_ok());
    }

    #[test]
    fn cry_12_hmac_key_sign_and_verify() {
        let key = HmacKey::new(SecretKey::from_bytes([3; 32]));
        let tag = key.sign(b"data");
        assert!(key.verify(b"data", &tag));
        assert!(!key.verify(b"datA", &tag));
        assert!(!key.verify(b"data", &tag[..31]));
        // Field framing removes concatenation ambiguity.
        assert_ne!(
            key.sign_fields(&[b"ab", b"c"]),
            key.sign_fields(&[b"a", b"bc"])
        );
        let tag = key.sign_fields(&[b"ab", b"c"]);
        assert!(key.verify_fields(&[b"ab", b"c"], &tag));
        assert!(!key.verify_fields(&[b"a", b"bc"], &tag));
        assert!(format!("{key:?}").contains(crate::secret::REDACTED));
        // The infallible 32-byte keying equals generic HMAC.
        assert_eq!(key.sign(b"data"), hmac_sha256(&[3; 32], b"data").unwrap());
    }
}
