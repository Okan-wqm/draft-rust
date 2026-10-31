//! # authn-crypto
//!
//! Cryptographic building blocks of `rust-authentication`. Nothing in here
//! invents an algorithm: every primitive comes from an audited crate
//! (RustCrypto, dalek-cryptography); this crate only *composes* them with
//! safe defaults, typed secrets and fail-closed parsing.
//!
//! | Module | Requirement | What |
//! |--------|-------------|------|
//! | [`password`] | CRY-01…05, ARC-12 | Argon2id + versioned HMAC pepper, rehash detection, legacy hashes, dummy verification, blocking pool + semaphore |
//! | [`token`] | CRY-06 | 256-bit URL-safe tokens, SHA-256 storage hash |
//! | [`otp`] | CRY-07 | Uniform 6-digit codes, keyed storage hash |
//! | [`envelope`] | CRY-08 | `KeyProvider`, per-record DEK, XChaCha20-Poly1305 envelopes with mandatory AAD, KEK rotation |
//! | [`jwt`] | CRY-09 | Fixed-algorithm EdDSA compact JWS / JWT, claim validation, JWKS |
//! | [`signing`] | CRY-10 | Ed25519 signing-key material and lifecycle states |
//! | [`kdf`] | CRY-11 | HKDF-SHA256 purpose sub-keys and HMAC helpers |
//! | [`ct`] | CRY-12 | Constant-time comparison helpers |
//! | [`secret`] | CRY-13 | Zeroizing, redacted secret containers |
//! | [`totp`] | MFA-01 core | RFC 6238 / RFC 4226 TOTP with replay-step reporting |
//! | [`webhook`] | AUD-07 core | Standard Webhooks HMAC signing and verification |
//! | [`services`] | ARC-07 | [`CryptoServices`]: every service built from `[crypto]` |
//!
//! Known-answer tests (CRY-14, TST-05) live next to each module (RFC 4231,
//! RFC 5869, RFC 4226, RFC 6238, RFC 8032, RFC 9106 / reference Argon2id,
//! RFC 7914 PBKDF2, Standard Webhooks); property tests (TST-03) are in
//! `tests/properties.rs`; fuzz targets (TST-04) in `fuzz/fuzz_targets/`.
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * Secrets live in [`secret`] / `Zeroizing` containers, never in plain
//!   `String`/`Vec`, and their `Debug` output is redacted.
//! * Errors are [`CryptoError`] (no secret material in messages); they convert
//!   into `authn_core::AuthError` with the generic `internal_error` code.
//! * Randomness comes only from the operating-system CSPRNG ([`random`]).

#![forbid(unsafe_code)]

mod encoding;

pub mod ct;
pub mod envelope;
pub mod error;
pub mod jwt;
pub mod kdf;
pub mod otp;
pub mod password;
pub mod random;
pub mod secret;
pub mod services;
pub mod signing;
pub mod token;
pub mod totp;
pub mod webhook;

pub use error::CryptoError;
pub use services::CryptoServices;

/// SHA-256 of `data` (non-secret helper used for token storage hashes,
/// audit chains and API-key fingerprints).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_14_sha256_known_answer() {
        // FIPS 180-2 example "abc".
        assert_eq!(
            data_encoding::HEXLOWER.encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
