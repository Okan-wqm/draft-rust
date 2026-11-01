//! Owner: authn-mfa (MFA-04, MFA-06, MFA-09). TST-04: parsing of
//! user-supplied MFA inputs — recovery codes, E.164 phone numbers and
//! trusted-device tokens.
//!
//! Registration in `fuzz/Cargo.toml` (`[[bin]] mfa_input_parse` and the
//! `authn-mfa` path dependency) is requested in
//! `docs/architecture/contract-change-requests.md` (authn-mfa).
//!
//! Invariants checked for every input:
//! * no parser panics, whatever the bytes;
//! * an accepted recovery code is exactly 10 characters of the 32-symbol
//!   alphabet and re-parses to itself from its display form;
//! * an accepted phone number is `+` and 8–15 ASCII digits;
//! * no token that was not issued by the signer verifies (the MAC key is
//!   random per process, so a fuzzer cannot learn it).
#![no_main]

use std::sync::OnceLock;

use authn_core::id::UserId;
use authn_crypto::kdf::KeyRing;
use authn_mfa::DeviceTokenSigner;
use authn_mfa::phone::parse_phone;
use authn_mfa::recovery::{ALPHABET, CODE_CHARS, RecoveryCode};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

fn signer() -> &'static (DeviceTokenSigner, UserId) {
    static SIGNER: OnceLock<(DeviceTokenSigner, UserId)> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let mut root = [0_u8; 32];
        authn_crypto::random::fill(&mut root).expect("os rng");
        let signer =
            DeviceTokenSigner::new(&KeyRing::derive(&root).expect("ring")).expect("signer");
        (signer, UserId::generate())
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(code) = RecoveryCode::parse(text) {
        assert_eq!(code.canonical().len(), CODE_CHARS);
        assert!(code.canonical().bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(RecoveryCode::parse(&code.display()).as_ref(), Some(&code));
    }
    if let Ok(phone) = parse_phone(text) {
        let digits = phone.as_str().strip_prefix('+').expect("plus");
        assert!((8..=15).contains(&digits.len()));
        assert!(digits.bytes().all(|b| b.is_ascii_digit()));
    }
    let (signer, user) = signer();
    assert!(
        signer
            .verify(*user, text, OffsetDateTime::UNIX_EPOCH)
            .is_none()
    );
});
