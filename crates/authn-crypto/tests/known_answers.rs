#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! TST-05: known-answer vectors for the primitives of the crate that the
//! unit tests (`cry_14_*`: SHA-256, HMAC, HKDF, HOTP/TOTP, Ed25519,
//! Argon2id; `aud_07_standard_webhooks_reference_vector`) do not cover yet:
//! the XChaCha20-Poly1305 AEAD of the envelope encryption (CRY-08).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap(), 16).unwrap())
        .collect()
}

/// draft-irtf-cfrg-xchacha-03, appendix A.3.1 (AEAD_XChaCha20_Poly1305).
const KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const NONCE: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
const AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
const CIPHERTEXT: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
21f9664c97637da9768812f615c68b13b52e";
const TAG: &str = "c0875924c1c7987947deafd8780acf49";

#[test]
fn tst_05_cry_08_xchacha20poly1305_reference_vector() {
    let cipher = XChaCha20Poly1305::new_from_slice(&unhex(KEY)).unwrap();
    let nonce_bytes = unhex(NONCE);
    let nonce = &XNonce::try_from(nonce_bytes.as_slice()).unwrap();
    let aad = unhex(AAD);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: PLAINTEXT,
                aad: &aad,
            },
        )
        .unwrap();
    let mut expected = unhex(CIPHERTEXT);
    expected.extend(unhex(TAG));
    assert_eq!(sealed, expected);

    let opened = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &expected,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(opened, PLAINTEXT);
}

/// The vector's ciphertext does not open under another AAD or with a
/// flipped tag bit: the AAD binds an envelope to its record (CRY-08).
#[test]
fn tst_05_cry_08_xchacha20poly1305_rejects_wrong_aad_and_tag() {
    let cipher = XChaCha20Poly1305::new_from_slice(&unhex(KEY)).unwrap();
    let nonce_bytes = unhex(NONCE);
    let nonce = &XNonce::try_from(nonce_bytes.as_slice()).unwrap();
    let mut sealed = unhex(CIPHERTEXT);
    sealed.extend(unhex(TAG));
    let wrong_aad = cipher.decrypt(
        nonce,
        Payload {
            msg: &sealed,
            aad: b"another record",
        },
    );
    assert!(wrong_aad.is_err());
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    let tampered = cipher.decrypt(
        nonce,
        Payload {
            msg: &sealed,
            aad: &unhex(AAD),
        },
    );
    assert!(tampered.is_err());
}
