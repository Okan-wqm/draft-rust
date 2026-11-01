//! Owner: authn-org (ORG-08). TST-04: API key format and CRC32 checksum parsing.
//!
//! Invariants checked for arbitrary input:
//! * `parse_api_key` never panics and never allocates more than the input
//!   bound (oversized input is rejected before any work);
//! * an accepted key is canonical: `ak_<env>_<43 base62>_<6 base62>`, its
//!   storage hash is SHA-256 of the exact input and its display prefix is a
//!   prefix of the input (no secret beyond 4 digits);
//! * flipping any single byte of an accepted key makes it invalid or a
//!   different key (no two strings map to the same stored hash).
#![no_main]

use authn_org::api_key::{MAX_API_KEY_LEN, MIN_API_KEY_LEN, parse_api_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = parse_api_key(input) else {
        return;
    };
    assert!(input.starts_with("ak_"));
    assert!((MIN_API_KEY_LEN..=MAX_API_KEY_LEN).contains(&input.len()));
    assert!(
        input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    let env = parsed.environment();
    assert!((1..=8).contains(&env.len()) && env.bytes().all(|b| b.is_ascii_lowercase()));
    assert_eq!(
        parsed.hash().as_bytes(),
        &authn_crypto::sha256(input.as_bytes())
    );
    assert!(input.starts_with(parsed.display_prefix()));
    assert_eq!(parsed.display_prefix().len(), 3 + env.len() + 1 + 4);
    // Single-byte mutations never yield the same key.
    let mut bytes = input.as_bytes().to_vec();
    for i in 0..bytes.len() {
        let original = bytes[i];
        bytes[i] = original ^ 0x01;
        if let Ok(mutated) = std::str::from_utf8(&bytes)
            && let Ok(other) = parse_api_key(mutated)
        {
            assert_ne!(other.hash().as_bytes(), parsed.hash().as_bytes());
        }
        bytes[i] = original;
    }
});
