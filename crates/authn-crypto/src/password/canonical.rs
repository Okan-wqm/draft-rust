//! The single canonical form of a password before hashing (PWD-02).
//!
//! Policy (minimum/maximum length, strength, breach checks) belongs to
//! `authn-password`; this module only guarantees that *every* Argon2 input is
//! derived from the same normalization, so a password typed on macOS (NFD
//! input methods) and on Windows (NFC) verifies identically.

use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Hard upper bound on the raw password size accepted by the hashing layer
/// (bytes, before normalization). The policy maximum (PWD-01: 128
/// characters) is far below; this is a denial-of-service guard only.
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// Unicode NFKC normalization of `raw` into a zeroizing buffer.
///
/// The output buffer is sized exactly in a first pass so it is never
/// reallocated (a reallocation would leave an unzeroized copy of the
/// password in freed memory).
pub fn canonicalize_password(raw: &str) -> Result<Zeroizing<String>, CryptoError> {
    if raw.len() > MAX_PASSWORD_BYTES {
        return Err(CryptoError::TooLarge);
    }
    let len: usize = raw.nfkc().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(raw.nfkc());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwd_02_nfkc_normalization_is_applied() {
        // "é" precomposed vs. e + combining acute accent.
        let nfc = canonicalize_password("caf\u{e9}").unwrap();
        let nfd = canonicalize_password("cafe\u{301}").unwrap();
        assert_eq!(*nfc, *nfd);
        // Compatibility forms fold (fullwidth letters, ligatures).
        assert_eq!(&*canonicalize_password("\u{ff21}\u{fb01}").unwrap(), "Afi");
        // Spaces and case are preserved (PWD-01: no other rewriting).
        assert_eq!(&*canonicalize_password(" Pa ss ").unwrap(), " Pa ss ");
    }

    #[test]
    fn pwd_02_capacity_is_exact() {
        let out = canonicalize_password("\u{fdfa}").unwrap();
        assert_eq!(out.capacity(), out.len());
    }

    #[test]
    fn cry_01_oversized_input_is_refused() {
        assert!(canonicalize_password(&"a".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert_eq!(
            canonicalize_password(&"a".repeat(MAX_PASSWORD_BYTES + 1)).unwrap_err(),
            CryptoError::TooLarge
        );
    }
}
