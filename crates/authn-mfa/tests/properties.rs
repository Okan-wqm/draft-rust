#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Property tests (TST-03) of the MFA input parsers — the same invariants as
//! the `mfa_input_parse` fuzz target (TST-04), run on every `cargo test`.

use authn_core::id::{TrustedDeviceId, UserId};
use authn_crypto::kdf::KeyRing;
use authn_mfa::DeviceTokenSigner;
use authn_mfa::phone::parse_phone;
use authn_mfa::recovery::{ALPHABET, CODE_CHARS, RecoveryCode};
use proptest::prelude::*;
use time::OffsetDateTime;

fn signer() -> DeviceTokenSigner {
    DeviceTokenSigner::new(&KeyRing::derive(&[42; 32]).unwrap()).unwrap()
}

proptest! {
    #[test]
    fn mfa_04_recovery_code_parser_is_total_and_canonical(input in ".{0,40}") {
        if let Some(code) = RecoveryCode::parse(&input) {
            prop_assert_eq!(code.canonical().len(), CODE_CHARS);
            prop_assert!(code.canonical().bytes().all(|b| ALPHABET.contains(&b)));
            prop_assert_eq!(RecoveryCode::parse(&code.display()), Some(code));
        }
    }

    #[test]
    fn mfa_04_every_generated_code_round_trips(_seed in 0_u8..50) {
        let code = RecoveryCode::generate().unwrap();
        let shown = code.display();
        prop_assert_eq!(RecoveryCode::parse(&shown.to_lowercase()), Some(code.clone()));
        prop_assert_eq!(RecoveryCode::parse(&shown.replace('-', " ")), Some(code));
    }

    #[test]
    fn mfa_06_phone_parser_accepts_only_e164(input in "\\PC{0,20}") {
        if let Ok(phone) = parse_phone(&input) {
            let digits = phone.as_str().strip_prefix('+').unwrap();
            prop_assert!((8..=15).contains(&digits.len()));
            prop_assert!(digits.bytes().all(|b| b.is_ascii_digit()));
            prop_assert!(!digits.starts_with('0'));
            prop_assert_eq!(phone.as_str(), input.as_str());
        }
    }

    #[test]
    fn mfa_09_arbitrary_strings_never_verify_as_device_tokens(input in "\\PC{0,200}") {
        prop_assert!(signer().verify(UserId::generate(), &input, OffsetDateTime::UNIX_EPOCH).is_none());
    }

    #[test]
    fn mfa_09_any_single_byte_change_breaks_a_token(index in 0_usize..160, byte in 0x21_u8..0x7f) {
        let signer = signer();
        let user = UserId::generate();
        let now = OffsetDateTime::UNIX_EPOCH;
        let token = signer
            .issue(user, TrustedDeviceId::generate(), now + time::Duration::days(1))
            .unwrap();
        let mut bytes = token.expose().as_bytes().to_vec();
        let i = index % bytes.len();
        prop_assume!(bytes[i] != byte);
        bytes[i] = byte;
        let forged = String::from_utf8(bytes).unwrap();
        prop_assert!(signer.verify(user, &forged, now).is_none());
    }
}
