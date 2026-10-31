//! Strict encodings shared by the token, JWT, webhook and envelope code.
//!
//! The base64 engines of the `base64` crate reject padding where none is
//! expected and reject non-canonical trailing bits, so every value has
//! exactly one accepted textual form (no malleability).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Base64url without padding (RFC 4648 §5), canonical.
pub(crate) fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Strict base64url (no padding, canonical trailing bits) decoding.
pub(crate) fn b64url_decode(text: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| CryptoError::Malformed)
}

/// Strict base64url decoding into a zeroizing buffer (secret payloads).
pub(crate) fn b64url_decode_secret(text: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    b64url_decode(text).map(Zeroizing::new)
}

/// Standard base64 with padding (RFC 4648 §4), canonical.
pub(crate) fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Strict standard base64 decoding (padding required, canonical).
pub(crate) fn b64_decode(text: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD.decode(text).map_err(|_| CryptoError::Malformed)
}

/// Whether `text` only contains base64url alphabet characters.
pub(crate) fn is_b64url_alphabet(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Lowercase hexadecimal.
pub(crate) fn hex(data: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(data)
}

/// Percent-encodes `input` for use inside a URI path segment or query value
/// (RFC 3986: everything except unreserved characters is encoded).
pub(crate) fn percent_encode(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            // Writing into a String cannot fail.
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_06_base64url_is_strict() {
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").unwrap(), vec![0xfb, 0xff]);
        // Padding, standard alphabet and non-canonical trailing bits are refused.
        assert!(b64url_decode("-_8=").is_err());
        assert!(b64url_decode("+/8").is_err());
        assert!(b64url_decode("-_9").is_err());
        assert!(is_b64url_alphabet("Az09-_"));
        assert!(!is_b64url_alphabet("a+b"));
    }

    #[test]
    fn standard_base64_is_strict() {
        assert_eq!(b64_encode(b"ab"), "YWI=");
        assert_eq!(b64_decode("YWI=").unwrap(), b"ab");
        assert!(b64_decode("YWI").is_err());
        assert!(b64_decode("YWJ=").is_err());
    }

    #[test]
    fn mfa_01_percent_encoding() {
        assert_eq!(percent_encode("a b:c@d/é~"), "a%20b%3Ac%40d%2F%C3%A9~");
    }
}
