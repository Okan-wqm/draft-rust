//! PKCE (RFC 7636), `S256` only (OAuth 2.1 §4.1.1, OIDP-03).
//!
//! `plain` is refused: it gives no protection against a stolen
//! authorization request. The challenge is `BASE64URL(SHA-256(verifier))`,
//! always 43 characters; the verifier is 43–128 characters of the RFC 7636
//! `unreserved` set. The comparison is constant-time.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Length of an `S256` code challenge.
pub const CHALLENGE_LEN: usize = 43;
/// Shortest code verifier (RFC 7636 §4.1).
pub const MIN_VERIFIER_LEN: usize = 43;
/// Longest code verifier (RFC 7636 §4.1).
pub const MAX_VERIFIER_LEN: usize = 128;
/// The only accepted `code_challenge_method`.
pub const METHOD_S256: &str = "S256";

fn is_b64url(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `challenge` has the shape of an `S256` challenge (43 base64url
/// characters encoding 32 bytes).
#[must_use]
pub fn is_valid_challenge(challenge: &str) -> bool {
    challenge.len() == CHALLENGE_LEN
        && is_b64url(challenge)
        && URL_SAFE_NO_PAD
            .decode(challenge)
            .is_ok_and(|bytes| bytes.len() == 32)
}

/// Whether `verifier` is a syntactically valid code verifier.
#[must_use]
pub fn is_valid_verifier(verifier: &str) -> bool {
    (MIN_VERIFIER_LEN..=MAX_VERIFIER_LEN).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// `BASE64URL(SHA-256(verifier))`.
#[must_use]
pub fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(authn_crypto::sha256(verifier.as_bytes()))
}

/// Whether `verifier` matches the stored `challenge` (constant-time).
#[must_use]
pub fn verify(verifier: &str, challenge: &str) -> bool {
    if !is_valid_verifier(verifier) || !is_valid_challenge(challenge) {
        return false;
    }
    authn_core::secret::constant_time_eq(s256_challenge(verifier).as_bytes(), challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidp_03_rfc_7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), challenge);
        assert!(verify(verifier, challenge));
        assert!(!verify(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl",
            challenge
        ));
    }

    #[test]
    fn oidp_03_plain_style_challenges_and_bad_verifiers_fail() {
        let verifier = "a".repeat(43);
        // `plain` would compare the verifier itself.
        assert!(!verify(&verifier, &verifier));
        assert!(!is_valid_verifier(&"a".repeat(42)));
        assert!(!is_valid_verifier(&"a".repeat(129)));
        assert!(!is_valid_verifier(&format!("{}!", "a".repeat(42))));
        assert!(!is_valid_challenge("short"));
        assert!(!is_valid_challenge(&"=".repeat(43)));
    }
}
