//! Owner: authn-crypto (CRY-01, CRY-04). TST-04: stored password-hash
//! parsers (Argon2id PHC, PBKDF2-SHA256 in PHC / passlib / Django form,
//! bcrypt with bounded cost).
//!
//! Invariants: no panic; accepted Argon2 parameters stay inside the
//! verification bounds (a planted hash cannot turn a login into a DoS).
#![no_main]

use authn_crypto::password::argon::{
    Argon2Phc, MAX_ITERATIONS, MAX_MEMORY_KIB, MAX_PARALLELISM, MIN_MEMORY_KIB,
};
use authn_crypto::password::legacy::{LegacyDigest, MAX_PBKDF2_ITERATIONS, Pbkdf2Hash, verify_bcrypt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(parsed) = Argon2Phc::parse(text) {
        let s = parsed.settings();
        assert!((MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&s.memory_kib));
        assert!((1..=MAX_ITERATIONS).contains(&s.iterations));
        assert!((1..=MAX_PARALLELISM).contains(&s.parallelism));
    }
    if let Ok(parsed) = Pbkdf2Hash::parse(text) {
        assert!((1..=MAX_PBKDF2_ITERATIONS).contains(&parsed.iterations()));
        // Verification cost is bounded by the iteration limit; only run the
        // cheap ones to keep the fuzzer fast.
        if parsed.iterations() <= 16 {
            let _ = parsed.verify(b"password");
        }
    }
    // Only the cheapest bcrypt costs are executed (cost is bounded anyway).
    if text.len() == 60 && (text.get(3..7) == Some("$04$") || text.get(3..7) == Some("$05$")) {
        let _ = verify_bcrypt(b"password", text);
    }
    for digest in [LegacyDigest::Md5, LegacyDigest::Sha1] {
        if let Ok(hex) = digest.normalize_hex(text) {
            assert!(hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        }
    }
});
