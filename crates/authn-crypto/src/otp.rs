//! Short one-time codes (CRY-07): e-mail/SMS OTPs, reset and login codes.
//!
//! * 6 decimal digits drawn uniformly from `000000..=999999` by rejection
//!   sampling over the OS CSPRNG (no modulo bias).
//! * Stored as `HMAC-SHA256(K_otp, len(purpose) || purpose || len(code) || code)`
//!   where `K_otp` is the [`KeyPurpose::OtpCode`] HKDF sub-key. A database
//!   leak alone does not allow brute-forcing the 10^6 code space offline; the
//!   purpose is bound into the MAC so a code hash can never be replayed under
//!   another purpose.
//! * Attempt limiting is enforced where the codes are stored
//!   (`authn_store::one_time_tokens`).

use std::fmt;

use authn_core::secret::SensitiveString;
use zeroize::Zeroizing;

use crate::kdf::{HmacKey, KeyPurpose, KeyRing};
use crate::token::TokenHash;
use crate::{CryptoError, random};

/// Number of digits of a code.
pub const OTP_DIGITS: usize = 6;

const OTP_SPACE: u32 = 1_000_000;

/// A 6-digit one-time code.
#[derive(Clone)]
pub struct OtpCode(Zeroizing<String>);

impl OtpCode {
    /// Generates a uniformly distributed code.
    pub fn generate() -> Result<Self, CryptoError> {
        let value = random::uniform_below(OTP_SPACE)?;
        Ok(Self(Zeroizing::new(format!("{value:06}"))))
    }

    /// Parses user input. ASCII spaces and hyphens are ignored (`"123 456"`,
    /// `"123-456"`); anything else must be exactly six ASCII digits.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        // Bound the work on hostile input before filtering.
        if input.len() > 32 {
            return Err(CryptoError::Malformed);
        }
        let mut digits = Zeroizing::new(String::with_capacity(OTP_DIGITS));
        for c in input.chars() {
            match c {
                '0'..='9' => digits.push(c),
                ' ' | '-' => {}
                _ => return Err(CryptoError::Malformed),
            }
        }
        if digits.len() != OTP_DIGITS {
            return Err(CryptoError::Malformed);
        }
        Ok(Self(digits))
    }

    /// The code text (for the notification only).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Converts into the core type used to carry secrets through ports.
    #[must_use]
    pub fn into_sensitive(self) -> SensitiveString {
        SensitiveString::new(self.0.as_str())
    }
}

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OtpCode({})", crate::secret::REDACTED)
    }
}

/// Computes and checks keyed storage hashes of codes.
#[derive(Clone)]
pub struct OtpHasher {
    key: HmacKey,
}

impl OtpHasher {
    /// A hasher using the [`KeyPurpose::OtpCode`] sub-key.
    pub fn new(ring: &KeyRing) -> Result<Self, CryptoError> {
        Ok(Self {
            key: ring.key(KeyPurpose::OtpCode)?.clone(),
        })
    }

    /// A hasher with an explicit key (tests, other code families).
    #[must_use]
    pub fn with_key(key: HmacKey) -> Self {
        Self { key }
    }

    /// The storage hash of `code` for `purpose` (the `one_time_tokens.purpose`
    /// value, e.g. `"password_reset_code"`).
    #[must_use]
    pub fn hash(&self, purpose: &str, code: &OtpCode) -> TokenHash {
        TokenHash::from_bytes(
            self.key
                .sign_fields(&[purpose.as_bytes(), code.expose().as_bytes()]),
        )
    }

    /// Constant-time check of `code` against a stored hash.
    #[must_use]
    pub fn verify(&self, purpose: &str, code: &OtpCode, stored: &TokenHash) -> bool {
        self.hash(purpose, code) == *stored
    }
}

impl fmt::Debug for OtpHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpHasher").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretKey;

    fn hasher() -> OtpHasher {
        OtpHasher::new(&KeyRing::derive(&[9; 32]).unwrap()).unwrap()
    }

    #[test]
    fn cry_07_codes_are_six_digits() {
        for _ in 0..1_000 {
            let code = OtpCode::generate().unwrap();
            assert_eq!(code.expose().len(), OTP_DIGITS);
            assert!(code.expose().bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn cry_07_parse_accepts_only_six_digits() {
        assert_eq!(OtpCode::parse("012345").unwrap().expose(), "012345");
        assert_eq!(OtpCode::parse("012 345").unwrap().expose(), "012345");
        assert_eq!(OtpCode::parse("012-345").unwrap().expose(), "012345");
        for bad in [
            "",
            "12345",
            "1234567",
            "12345a",
            "١٢٣٤٥٦",
            "123456\n",
            "+12345",
            "000000000000000000000000000000000",
        ] {
            assert!(OtpCode::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn cry_07_hash_is_keyed_and_purpose_bound() {
        let h = hasher();
        let code = OtpCode::parse("123456").unwrap();
        let stored = h.hash("password_reset_code", &code);
        assert!(h.verify("password_reset_code", &code, &stored));
        assert!(!h.verify("login_code", &code, &stored));
        assert!(!h.verify(
            "password_reset_code",
            &OtpCode::parse("123457").unwrap(),
            &stored
        ));
        // Not a plain (unkeyed) hash, and a different key gives another hash.
        assert_ne!(stored, TokenHash::digest(b"123456"));
        let other = OtpHasher::with_key(HmacKey::new(SecretKey::from_bytes([1; 32])));
        assert_ne!(other.hash("password_reset_code", &code), stored);
    }

    #[test]
    fn cry_13_codes_are_redacted() {
        let code = OtpCode::parse("987654").unwrap();
        assert!(!format!("{code:?}").contains("987654"));
        assert!(!format!("{:?}", hasher()).contains("09"));
    }
}
