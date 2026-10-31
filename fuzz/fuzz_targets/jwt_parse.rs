//! Owner: authn-crypto (CRY-09). TST-04: JWT / JWS parsing and verification
//! (alg confusion, malformed segments, hostile JSON).
//!
//! Two modes, chosen by the first input byte:
//! * even: the rest is a raw compact token, verified against a fixed key
//!   set. A forged token can never verify.
//! * odd: the rest is `header_json \0 payload_json`; the harness signs it
//!   with the trusted key so the fuzzer reaches header validation, claim
//!   parsing and claim validation behind the signature check.
#![no_main]

use std::sync::OnceLock;

use authn_crypto::jwt::{JwtValidation, JwtVerifier, VerifiedJwt};
use authn_crypto::signing::Ed25519SigningKey;
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

const ISS: &str = "https://auth.fuzz.example";
const AUD: &str = "https://api.fuzz.example";

struct Fixture {
    key: Ed25519SigningKey,
    verifier: JwtVerifier,
    validation: JwtValidation,
    now: OffsetDateTime,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let key = Ed25519SigningKey::from_seed(&[7; 32]).expect("seed");
        let verifier = JwtVerifier::new([("kid-1".to_owned(), key.public_key())]);
        Fixture {
            key,
            verifier,
            validation: JwtValidation::access_token(ISS, AUD),
            now: OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time"),
        }
    })
}

fn b64url(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn check(result: Result<VerifiedJwt<serde_json::Value>, authn_crypto::jwt::JwtError>) {
    if let Ok(verified) = result {
        // Anything accepted must satisfy the validation contract.
        assert_eq!(verified.kid, "kid-1");
        assert_eq!(verified.registered.iss, ISS);
        assert!(verified.registered.aud.iter().any(|a| a == AUD));
        assert!(verified.registered.iat <= verified.registered.exp);
        assert!(verified.claims.is_object());
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else { return };
    let f = fixture();
    if mode % 2 == 0 {
        let Ok(token) = std::str::from_utf8(rest) else { return };
        let result = f.verifier.verify::<serde_json::Value>(token, &f.validation, f.now);
        // A token not produced by the trusted key never verifies.
        assert!(result.is_err());
    } else {
        let mut parts = rest.splitn(2, |b| *b == 0);
        let (Some(header), Some(payload)) = (parts.next(), parts.next()) else { return };
        let input = format!("{}.{}", b64url(header), b64url(payload));
        let signature = f.key.sign(input.as_bytes());
        let token = format!("{input}.{}", b64url(&signature));
        check(f.verifier.verify::<serde_json::Value>(&token, &f.validation, f.now));
    }
});
