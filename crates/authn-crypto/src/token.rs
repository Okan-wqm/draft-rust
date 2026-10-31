//! Opaque bearer tokens (CRY-06).
//!
//! * 32 bytes (256 bits) from the OS CSPRNG, encoded as base64url without
//!   padding: always exactly [`TOKEN_LEN`] characters.
//! * Only [`TokenHash`] = SHA-256 of the token text is stored. A database
//!   leak therefore yields nothing usable: the preimage has 256 bits of
//!   entropy, so no salt or slow hash is needed.
//! * Comparisons of hashes are constant-time ([`TokenHash`]'s `==`).
//!   Database lookups by hash are safe against timing attacks because an
//!   attacker cannot choose the bytes of a SHA-256 output.
//! * [`OpaqueToken`] has a redacted `Debug`, no `Display` and no `Serialize`:
//!   it cannot end up in a log line or JSON body by accident. Use
//!   [`OpaqueToken::expose`] at the single place that legitimately needs the
//!   text (building a link, setting a cookie).

use std::fmt;

use authn_core::secret::SensitiveString;
use zeroize::Zeroizing;

use crate::encoding::{b64url_decode_secret, b64url_encode, is_b64url_alphabet};
use crate::{CryptoError, ct, random};

/// Raw entropy of a token in bytes.
pub const TOKEN_BYTES: usize = 32;

/// Length of the textual form (`ceil(32 * 4 / 3)` = 43 characters).
pub const TOKEN_LEN: usize = 43;

/// A freshly generated or presented bearer token.
#[derive(Clone)]
pub struct OpaqueToken(Zeroizing<String>);

impl OpaqueToken {
    /// Generates a new 256-bit token.
    pub fn generate() -> Result<Self, CryptoError> {
        let raw = random::secret_bytes::<TOKEN_BYTES>()?;
        Ok(Self(Zeroizing::new(b64url_encode(raw.as_slice()))))
    }

    /// Validates a presented token: exactly 43 base64url characters in
    /// canonical form. Cheap; call it before any database lookup so garbage
    /// never reaches SQL.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        if input.len() != TOKEN_LEN || !is_b64url_alphabet(input) {
            return Err(CryptoError::Malformed);
        }
        let decoded = b64url_decode_secret(input)?;
        if decoded.len() != TOKEN_BYTES {
            return Err(CryptoError::Malformed);
        }
        Ok(Self(Zeroizing::new(input.to_owned())))
    }

    /// The token text. Call sites should be easy to audit.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The storage hash.
    #[must_use]
    pub fn hash(&self) -> TokenHash {
        TokenHash::digest(self.0.as_bytes())
    }

    /// Constant-time check against a stored hash.
    #[must_use]
    pub fn matches(&self, stored: &TokenHash) -> bool {
        self.hash() == *stored
    }

    /// Converts into the core type used to carry secrets through ports (for
    /// example a notification sealed into the outbox).
    #[must_use]
    pub fn into_sensitive(self) -> SensitiveString {
        SensitiveString::new(self.0.as_str())
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpaqueToken({})", crate::secret::REDACTED)
    }
}

/// The 32-byte storage hash of a token or code. Equality is constant-time.
#[derive(Clone, Copy)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// SHA-256 of `input`.
    #[must_use]
    pub fn digest(input: &[u8]) -> Self {
        Self(crate::sha256(input))
    }

    /// Wraps a stored hash.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Wraps a stored hash read as a byte slice (must be 32 bytes).
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::Malformed)?;
        Ok(Self(array))
    }

    /// The hash bytes (for binding to SQL parameters).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for TokenHash {
    fn eq(&self, other: &Self) -> bool {
        ct::eq_array(&self.0, &other.0)
    }
}

impl Eq for TokenHash {}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenHash({})", crate::secret::REDACTED)
    }
}

#[cfg(test)]
#[allow(clippy::string_slice)] // ASCII fixtures
mod tests {
    use super::*;

    #[test]
    fn cry_06_tokens_have_256_bits_and_canonical_form() {
        let token = OpaqueToken::generate().unwrap();
        assert_eq!(token.expose().len(), TOKEN_LEN);
        assert!(is_b64url_alphabet(token.expose()));
        assert!(!token.expose().contains('='));
        let parsed = OpaqueToken::parse(token.expose()).unwrap();
        assert_eq!(parsed.hash(), token.hash());
        assert_ne!(OpaqueToken::generate().unwrap().hash(), token.hash());
    }

    #[test]
    fn cry_06_parse_rejects_malformed_tokens() {
        let good = OpaqueToken::generate().unwrap();
        let text = good.expose();
        for bad in [
            "",
            &text[..42],
            &format!("{text}A"),
            &format!("{}=", &text[..42]),
            &format!("{}+", &text[..42]),
            &format!("{}é", &text[..41]),
        ] {
            assert!(OpaqueToken::parse(bad).is_err(), "{bad:?}");
        }
        // Non-canonical final character (unused low bits set).
        let canonical = format!("{}A", "A".repeat(42));
        assert!(OpaqueToken::parse(&canonical).is_ok());
        let non_canonical = format!("{}B", "A".repeat(42));
        assert!(OpaqueToken::parse(&non_canonical).is_err());
    }

    #[test]
    fn cry_06_hash_is_sha256_of_text_and_compares_in_constant_time() {
        let token = OpaqueToken::parse(&"A".repeat(43)).unwrap();
        assert_eq!(
            token.hash().as_bytes(),
            &crate::sha256("A".repeat(43).as_bytes())
        );
        assert!(token.matches(&token.hash()));
        assert!(!token.matches(&TokenHash::from_bytes([0; 32])));
        assert!(TokenHash::from_slice(&[0; 31]).is_err());
    }

    #[test]
    fn cry_13_tokens_are_redacted() {
        let token = OpaqueToken::generate().unwrap();
        let debug = format!("{token:?} {:?}", token.hash());
        assert!(!debug.contains(token.expose()));
        assert!(debug.contains(crate::secret::REDACTED));
        assert_eq!(token.clone().into_sensitive().expose(), token.expose());
    }
}
