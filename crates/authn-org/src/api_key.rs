//! The API key format (ORG-08).
//!
//! ```text
//! ak_<env>_<secret>_<checksum>
//!     env       1–8 lowercase ASCII letters (`[org.api_keys] environment`)
//!     secret    32 CSPRNG bytes as 43 base62 digits (fixed width, big endian)
//!     checksum  CRC-32 (IEEE) of "ak_<env>_<secret>" as 6 base62 digits
//! ```
//!
//! * The fixed prefix and the checksum make leaked keys easy to find for
//!   secret scanners and let [`parse_api_key`] reject typos and garbage
//!   without any database work.
//! * The checksum is **not** a security feature (CRC-32 is public): the
//!   security of a key is its 256-bit secret. Only the SHA-256 of the whole
//!   key text is stored ([`TokenHash`]); lookups by that hash are not timing
//!   sensitive (an attacker cannot choose SHA-256 output bytes) and the
//!   stored hash is compared again in constant time after the lookup.
//! * Parsing is total and canonical: every accepted string has exactly one
//!   encoding (fixed-width digits, no overflow beyond 256 bits, exact
//!   length), so two different strings never map to the same key.
//! * Key material lives in `Zeroizing` buffers; `Debug` is redacted.

use std::fmt;

use authn_core::secret::SensitiveString;
use authn_crypto::random;
use authn_crypto::token::TokenHash;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Fixed key prefix.
pub const API_KEY_PREFIX: &str = "ak";
/// Raw entropy of the secret part in bytes.
pub const SECRET_BYTES: usize = 32;
/// Base62 digits of the secret part (`62^43 > 2^256`).
pub const SECRET_DIGITS: usize = 43;
/// Base62 digits of the checksum (`62^6 > 2^32`).
pub const CHECKSUM_DIGITS: usize = 6;
/// Longest accepted environment label.
pub const MAX_ENVIRONMENT_LEN: usize = 8;
/// Longest possible key (`ak_` + 8 + `_` + 43 + `_` + 6).
pub const MAX_API_KEY_LEN: usize =
    3 + MAX_ENVIRONMENT_LEN + 1 + SECRET_DIGITS + 1 + CHECKSUM_DIGITS;
/// Shortest possible key.
pub const MIN_API_KEY_LEN: usize = 3 + 1 + 1 + SECRET_DIGITS + 1 + CHECKSUM_DIGITS;
/// Secret digits shown in listings (`ak_live_AbCd`): ~24 of 256 bits.
const DISPLAY_SECRET_DIGITS: usize = 4;

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Why a presented key was rejected. Never contains the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiKeyFormatError {
    /// Shorter or longer than any valid key.
    #[error("api key has an invalid length")]
    Length,
    /// Not `ak_<env>_<secret>_<checksum>`.
    #[error("api key is malformed")]
    Malformed,
    /// The environment label is invalid.
    #[error("api key environment is invalid")]
    Environment,
    /// The secret part is not 43 base62 digits of a 256-bit value.
    #[error("api key secret is invalid")]
    Secret,
    /// The checksum does not match.
    #[error("api key checksum mismatch")]
    Checksum,
    /// The operating-system RNG failed (generation only).
    #[error("random number generator failure")]
    Rng,
}

/// A freshly generated key: shown to the caller exactly once.
pub struct GeneratedApiKey {
    text: Zeroizing<String>,
    hash: TokenHash,
    display_prefix: String,
}

impl GeneratedApiKey {
    /// Generates a key for `environment` (1–8 lowercase ASCII letters).
    pub fn generate(environment: &str) -> Result<Self, ApiKeyFormatError> {
        if !is_valid_environment(environment) {
            return Err(ApiKeyFormatError::Environment);
        }
        let raw = random::secret_bytes::<SECRET_BYTES>().map_err(|_| ApiKeyFormatError::Rng)?;
        let secret = encode_base62_256(&raw)?;
        let mut text = Zeroizing::new(String::with_capacity(MAX_API_KEY_LEN));
        text.push_str(API_KEY_PREFIX);
        text.push('_');
        text.push_str(environment);
        text.push('_');
        text.push_str(&secret);
        let checksum = encode_base62_u32(crc32fast::hash(text.as_bytes()));
        text.push('_');
        text.push_str(&checksum);
        let display_prefix = display_prefix(environment, &secret);
        let hash = TokenHash::digest(text.as_bytes());
        Ok(Self {
            text,
            hash,
            display_prefix,
        })
    }

    /// The key text. Call sites must be easy to audit: the only legitimate
    /// use is the creation / rotation response.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.text
    }

    /// The storage hash (SHA-256 of the key text).
    #[must_use]
    pub fn hash(&self) -> TokenHash {
        self.hash
    }

    /// The non-secret prefix shown in listings (`ak_live_AbCd`).
    #[must_use]
    pub fn display_prefix(&self) -> &str {
        &self.display_prefix
    }

    /// Moves the key into the redacting core type.
    #[must_use]
    pub fn into_sensitive(self) -> SensitiveString {
        SensitiveString::new(self.text.as_str())
    }
}

impl fmt::Debug for GeneratedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedApiKey")
            .field("display_prefix", &self.display_prefix)
            .finish_non_exhaustive()
    }
}

/// A syntactically valid presented key.
#[derive(Clone)]
pub struct ParsedApiKey {
    environment: String,
    hash: TokenHash,
    display_prefix: String,
}

impl ParsedApiKey {
    /// The environment label (`live`, `test`…).
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// The storage hash to look the key up with.
    #[must_use]
    pub fn hash(&self) -> TokenHash {
        self.hash
    }

    /// The non-secret display prefix.
    #[must_use]
    pub fn display_prefix(&self) -> &str {
        &self.display_prefix
    }
}

impl fmt::Debug for ParsedApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedApiKey")
            .field("display_prefix", &self.display_prefix)
            .finish_non_exhaustive()
    }
}

/// Validates a presented key: length bounds first (no work on oversized
/// input), then the exact structure, the canonical 256-bit secret and the
/// checksum. Cheap; call before any database lookup.
pub fn parse_api_key(input: &str) -> Result<ParsedApiKey, ApiKeyFormatError> {
    if !(MIN_API_KEY_LEN..=MAX_API_KEY_LEN).contains(&input.len()) {
        return Err(ApiKeyFormatError::Length);
    }
    if !input.is_ascii() {
        return Err(ApiKeyFormatError::Malformed);
    }
    let mut parts = input.split('_');
    let (Some(prefix), Some(environment), Some(secret), Some(checksum), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(ApiKeyFormatError::Malformed);
    };
    if prefix != API_KEY_PREFIX {
        return Err(ApiKeyFormatError::Malformed);
    }
    if !is_valid_environment(environment) {
        return Err(ApiKeyFormatError::Environment);
    }
    if secret.len() != SECRET_DIGITS {
        return Err(ApiKeyFormatError::Secret);
    }
    // Canonical 256-bit value (rejects non-base62 digits and overflow).
    let _value = Zeroizing::new(decode_base62_256(secret)?);
    if checksum.len() != CHECKSUM_DIGITS || !checksum.bytes().all(is_base62_digit) {
        return Err(ApiKeyFormatError::Checksum);
    }
    // "ak_<env>_<secret>" is the input without "_<checksum>".
    let body_len = input.len() - CHECKSUM_DIGITS - 1;
    let body = input.get(..body_len).ok_or(ApiKeyFormatError::Malformed)?;
    let expected = encode_base62_u32(crc32fast::hash(body.as_bytes()));
    if !bool::from(expected.as_bytes().ct_eq(checksum.as_bytes())) {
        return Err(ApiKeyFormatError::Checksum);
    }
    Ok(ParsedApiKey {
        environment: environment.to_owned(),
        hash: TokenHash::digest(input.as_bytes()),
        display_prefix: display_prefix(environment, secret),
    })
}

/// Whether `value` looks like it is meant to be an API key (`ak_` prefix).
/// Used by the authentication middleware to route bearer credentials.
#[must_use]
pub fn looks_like_api_key(value: &str) -> bool {
    value.starts_with("ak_")
}

fn is_valid_environment(env: &str) -> bool {
    (1..=MAX_ENVIRONMENT_LEN).contains(&env.len()) && env.bytes().all(|b| b.is_ascii_lowercase())
}

fn is_base62_digit(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn digit_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'Z' => Some(b - b'A' + 10),
        b'a'..=b'z' => Some(b - b'a' + 36),
        _ => None,
    }
}

fn digit_char(value: u32) -> Result<char, ApiKeyFormatError> {
    usize::try_from(value)
        .ok()
        .and_then(|i| BASE62.get(i))
        .map(|b| char::from(*b))
        .ok_or(ApiKeyFormatError::Secret)
}

fn display_prefix(environment: &str, secret: &str) -> String {
    let shown = secret.get(..DISPLAY_SECRET_DIGITS).unwrap_or_default();
    format!("{API_KEY_PREFIX}_{environment}_{shown}")
}

/// Fixed-width (43 digit) big-endian base62 encoding of a 256-bit value.
fn encode_base62_256(bytes: &[u8; SECRET_BYTES]) -> Result<Zeroizing<String>, ApiKeyFormatError> {
    let mut num = Zeroizing::new(*bytes);
    let mut digits = Zeroizing::new([0_u8; SECRET_DIGITS]);
    for slot in digits.iter_mut().rev() {
        let mut rem: u32 = 0;
        for byte in num.iter_mut() {
            let acc = (rem << 8) | u32::from(*byte);
            *byte = u8::try_from(acc / 62).map_err(|_| ApiKeyFormatError::Secret)?;
            rem = acc % 62;
        }
        *slot = u8::try_from(rem).map_err(|_| ApiKeyFormatError::Secret)?;
    }
    if num.iter().any(|b| *b != 0) {
        // Unreachable: 62^43 > 2^256.
        return Err(ApiKeyFormatError::Secret);
    }
    let mut out = Zeroizing::new(String::with_capacity(SECRET_DIGITS));
    for d in digits.iter() {
        out.push(digit_char(u32::from(*d))?);
    }
    Ok(out)
}

/// Decodes 43 base62 digits into a 256-bit big-endian value; values above
/// `2^256 - 1` are rejected so the encoding is canonical.
fn decode_base62_256(digits: &str) -> Result<[u8; SECRET_BYTES], ApiKeyFormatError> {
    let mut num = [0_u8; SECRET_BYTES];
    for c in digits.bytes() {
        let mut carry = u32::from(digit_value(c).ok_or(ApiKeyFormatError::Secret)?);
        for byte in num.iter_mut().rev() {
            let acc = u32::from(*byte) * 62 + carry;
            *byte = u8::try_from(acc & 0xff).map_err(|_| ApiKeyFormatError::Secret)?;
            carry = acc >> 8;
        }
        if carry != 0 {
            return Err(ApiKeyFormatError::Secret);
        }
    }
    Ok(num)
}

/// Fixed-width (6 digit) base62 encoding of a CRC-32.
fn encode_base62_u32(mut value: u32) -> String {
    let mut digits = [b'0'; CHECKSUM_DIGITS];
    for slot in digits.iter_mut().rev() {
        let index = usize::try_from(value % 62).unwrap_or(0);
        *slot = BASE62.get(index).copied().unwrap_or(b'0');
        value /= 62;
    }
    digits.iter().map(|b| char::from(*b)).collect()
}

#[cfg(test)]
#[allow(clippy::string_slice)] // ASCII fixtures
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn org_08_generated_keys_have_the_documented_format() {
        let key = GeneratedApiKey::generate("live").unwrap();
        let text = key.expose();
        assert!(text.starts_with("ak_live_"));
        let parts: Vec<&str> = text.split('_').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[2].len(), SECRET_DIGITS);
        assert_eq!(parts[3].len(), CHECKSUM_DIGITS);
        assert!(text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        let parsed = parse_api_key(text).unwrap();
        assert_eq!(parsed.environment(), "live");
        assert_eq!(parsed.hash(), key.hash());
        assert_eq!(parsed.display_prefix(), key.display_prefix());
        assert_eq!(key.display_prefix().len(), "ak_live_".len() + 4);
        assert!(text.starts_with(key.display_prefix()));
        assert_ne!(
            GeneratedApiKey::generate("live").unwrap().hash(),
            key.hash()
        );
    }

    #[test]
    fn org_08_hash_is_sha256_of_the_full_key() {
        let key = GeneratedApiKey::generate("test").unwrap();
        assert_eq!(
            key.hash().as_bytes(),
            &authn_crypto::sha256(key.expose().as_bytes())
        );
    }

    #[test]
    fn org_08_checksum_rejects_typos_without_database_work() {
        let key = GeneratedApiKey::generate("live").unwrap();
        let text = key.expose().to_owned();
        // Flip one secret digit.
        let mut bytes = text.clone().into_bytes();
        let i = "ak_live_".len() + 10;
        bytes[i] = if bytes[i] == b'a' { b'b' } else { b'a' };
        let typo = String::from_utf8(bytes).unwrap();
        assert_eq!(
            parse_api_key(&typo).unwrap_err(),
            ApiKeyFormatError::Checksum
        );
        // Another environment label with the same secret fails the checksum.
        let other_env = text.replacen("ak_live_", "ak_test_", 1);
        assert_eq!(
            parse_api_key(&other_env).unwrap_err(),
            ApiKeyFormatError::Checksum
        );
    }

    #[test]
    fn org_08_malformed_keys_are_rejected() {
        let key = GeneratedApiKey::generate("live").unwrap();
        let text = key.expose();
        let secret_and_sum = text.strip_prefix("ak_live_").unwrap();
        for bad in [
            String::new(),
            "ak_".to_owned(),
            "x".repeat(MAX_API_KEY_LEN + 1),
            text.replacen("ak_", "AK_", 1),
            text.replacen("ak_", "sk_", 1),
            format!("ak_LIVE_{secret_and_sum}"),
            format!("ak_li-e_{secret_and_sum}"),
            format!("ak_toolonger_{secret_and_sum}"),
            format!("{text}_x"),
            format!(" {text}"),
            text.replacen('_', "-", 1),
            format!("ak_live_{}", secret_and_sum.replacen('_', "", 1)),
            format!("ak_live_é{}", &secret_and_sum[2..]),
        ] {
            assert!(parse_api_key(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn org_08_secret_above_2_pow_256_is_rejected() {
        // "z" * 43 is 62^43 - 1 > 2^256 - 1.
        assert_eq!(
            decode_base62_256(&"z".repeat(43)).unwrap_err(),
            ApiKeyFormatError::Secret
        );
        let max = encode_base62_256(&[0xff; 32]).unwrap();
        assert_eq!(decode_base62_256(&max).unwrap(), [0xff; 32]);
        assert_eq!(
            encode_base62_256(&[0; 32]).unwrap().as_str(),
            "0".repeat(43)
        );
    }

    #[test]
    fn org_08_debug_never_contains_the_key() {
        let key = GeneratedApiKey::generate("live").unwrap();
        let parsed = parse_api_key(key.expose()).unwrap();
        let debug = format!("{key:?} {parsed:?}");
        let secret_part = key.expose().split('_').nth(2).unwrap();
        assert!(!debug.contains(secret_part));
        assert!(debug.contains(key.display_prefix()));
    }

    #[test]
    fn org_08_base62_u32_is_fixed_width() {
        assert_eq!(encode_base62_u32(0), "000000");
        assert_eq!(encode_base62_u32(61), "00000z");
        assert_eq!(encode_base62_u32(62), "000010");
        assert_eq!(encode_base62_u32(u32::MAX).len(), 6);
    }

    proptest! {
        #[test]
        fn org_08_base62_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            let encoded = encode_base62_256(&bytes).unwrap();
            prop_assert_eq!(encoded.len(), SECRET_DIGITS);
            prop_assert_eq!(decode_base62_256(&encoded).unwrap(), bytes);
        }

        #[test]
        fn org_08_parse_never_panics_and_accepts_only_canonical_keys(input in ".{0,80}") {
            if let Ok(parsed) = parse_api_key(&input) {
                prop_assert!(input.starts_with("ak_"));
                prop_assert_eq!(parsed.hash(), TokenHash::digest(input.as_bytes()));
            }
        }
    }
}
