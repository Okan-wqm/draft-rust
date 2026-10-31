#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Property-based tests (TST-03) of token and code formats and a uniformity
//! sanity check of OTP generation (CRY-06, CRY-07).

use authn_crypto::kdf::KeyRing;
use authn_crypto::otp::{OTP_DIGITS, OtpCode, OtpHasher};
use authn_crypto::token::{OpaqueToken, TOKEN_LEN, TokenHash};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every 256-bit value has exactly one accepted textual form, and it
    /// hashes to SHA-256 of that text.
    #[test]
    fn cry_06_prop_every_256_bit_value_is_a_canonical_token(bytes in proptest::array::uniform32(any::<u8>())) {
        let text = URL_SAFE_NO_PAD.encode(bytes);
        prop_assert_eq!(text.len(), TOKEN_LEN);
        let token = OpaqueToken::parse(&text).unwrap();
        prop_assert_eq!(token.hash(), TokenHash::digest(text.as_bytes()));
        prop_assert!(token.matches(&TokenHash::digest(text.as_bytes())));
    }

    /// Arbitrary strings are only accepted when they are canonical tokens.
    #[test]
    fn cry_06_prop_parse_accepts_only_canonical_tokens(input in "\\PC{0,64}") {
        if let Ok(token) = OpaqueToken::parse(&input) {
            prop_assert_eq!(input.len(), TOKEN_LEN);
            let decoded = URL_SAFE_NO_PAD.decode(token.expose()).unwrap();
            prop_assert_eq!(URL_SAFE_NO_PAD.encode(decoded), input);
        }
    }

    /// Every 6-digit value parses, keeps leading zeros and hashes stably.
    #[test]
    fn cry_07_prop_codes_round_trip(value in 0_u32..1_000_000, purpose in "[a-z][a-z0-9_]{0,20}") {
        let text = format!("{value:06}");
        let code = OtpCode::parse(&text).unwrap();
        prop_assert_eq!(code.expose(), text.as_str());
        let hasher = OtpHasher::new(&KeyRing::derive(&[1; 32]).unwrap()).unwrap();
        let hash = hasher.hash(&purpose, &code);
        prop_assert!(hasher.verify(&purpose, &OtpCode::parse(&text).unwrap(), &hash));
        let other = OtpCode::parse(&format!("{:06}", (value + 1) % 1_000_000)).unwrap();
        prop_assert!(!hasher.verify(&purpose, &other, &hash));
    }

    /// Codes with anything but six digits (ignoring spaces/hyphens) fail.
    #[test]
    fn cry_07_prop_non_codes_are_rejected(input in "\\PC{0,12}") {
        let digits = input.chars().filter(char::is_ascii_digit).count();
        let only_allowed = input.chars().all(|c| c.is_ascii_digit() || c == ' ' || c == '-');
        let accepted = OtpCode::parse(&input).is_ok();
        prop_assert_eq!(accepted, only_allowed && digits == OTP_DIGITS);
    }
}

/// Uniformity sanity check (CRY-07, no modulo bias): 60 000 codes, every
/// digit position must have a roughly flat distribution. Expected count per
/// cell is 6 000 (σ ≈ 73); the ±600 band is > 8σ, so the test is not flaky,
/// while a biased generator (e.g. `byte % 10`, which over-represents 0–5 by
/// ~2.4 %, i.e. ±140 per cell, or anything grosser) is visible in the χ²
/// statistic below.
#[test]
fn cry_07_generated_codes_are_uniform() {
    const SAMPLES: usize = 60_000;
    let mut counts = [[0_u32; 10]; OTP_DIGITS];
    for _ in 0..SAMPLES {
        let code = OtpCode::generate().unwrap();
        for (position, digit) in code.expose().bytes().enumerate() {
            counts[position][usize::from(digit - b'0')] += 1;
        }
    }
    let expected = (SAMPLES / 10) as f64;
    for (position, row) in counts.iter().enumerate() {
        for count in row {
            assert!(
                (f64::from(*count) - expected).abs() < 600.0,
                "position {position}: {row:?}"
            );
        }
        // χ² with 9 degrees of freedom: p = 1e-9 critical value ≈ 63.5
        // (Wilson–Hilferty). With 6 positions the false-failure rate per run
        // is ~6e-9, so the test is effectively deterministic while still
        // catching any gross bias (a broken generator lands far above this).
        let chi2: f64 = row
            .iter()
            .map(|c| (f64::from(*c) - expected).powi(2) / expected)
            .sum();
        assert!(
            chi2 < 63.5,
            "position {position}: chi2 = {chi2:.1}, {row:?}"
        );
    }
}

#[test]
fn cry_06_generated_tokens_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(OpaqueToken::generate().unwrap().expose().to_owned()));
    }
}
