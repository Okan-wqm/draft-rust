//! Owner: authn-webauthn (PKY-01, PKY-04, PKY-06). TST-04: everything an
//! attacker can send to the passkey endpoints before or around
//! `webauthn-rs` verification.
//!
//! Registration in `fuzz/Cargo.toml` (`[[bin]] webauthn_response_parse`,
//! the `authn-webauthn` path dependency and `webauthn-rs`) and the MPL-2.0
//! exception in `fuzz/deny.toml` are requested in
//! `docs/architecture/contract-change-requests.md` (authn-webauthn).
//!
//! Invariants checked for every input:
//! * no parser panics, whatever the bytes: client `RegisterPublicKeyCredential`
//!   / `PublicKeyCredential` JSON, the CBOR attestation object and
//!   authenticator data inside them (through `webauthn-rs` verification
//!   against a live registration state), the user handle of a discoverable
//!   assertion, passkey names and relying-party configuration values;
//! * no random response ever verifies against the fixed ceremony (its
//!   challenge is random per process);
//! * an accepted passkey name is trimmed, 1–64 characters and free of
//!   control / bidi / invisible characters;
//! * an accepted RP id is lowercase ASCII and an accepted web origin host
//!   matches `rp_id` only on a label boundary.
#![no_main]

use std::sync::OnceLock;

use authn_core::config::webauthn::{host_matches_rp_id, is_valid_rp_id, web_origin_host};
use authn_webauthn::name::{MAX_NAME_CHARS, normalize_name};
use libfuzzer_sys::fuzz_target;
use webauthn_rs::prelude::{
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Url, Uuid, Webauthn,
    WebauthnBuilder,
};

struct Fixture {
    rp: Webauthn,
    registration: PasskeyRegistration,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let origin = Url::parse("https://auth.example.com").expect("origin");
        let rp = WebauthnBuilder::new("example.com", &origin)
            .expect("rp")
            .build()
            .expect("rp");
        let (_, registration) = rp
            .start_passkey_registration(Uuid::from_u128(1), "user", "user", None)
            .expect("registration");
        Fixture { rp, registration }
    })
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();

    if let Ok(response) = serde_json::from_slice::<RegisterPublicKeyCredential>(data) {
        assert!(
            fixture
                .rp
                .finish_passkey_registration(&response, &fixture.registration)
                .is_err(),
            "a random registration response verified"
        );
    }
    if let Ok(assertion) = serde_json::from_slice::<PublicKeyCredential>(data) {
        let _ = fixture.rp.identify_discoverable_authentication(&assertion);
    }

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(name) = normalize_name(text) {
        assert_eq!(name.trim(), name);
        let chars = name.chars().count();
        assert!((1..=MAX_NAME_CHARS).contains(&chars));
        assert!(!name.chars().any(char::is_control));
        assert!(!name.contains('\u{202E}') && !name.contains('\u{200B}'));
    }
    if is_valid_rp_id(text) {
        assert!(text.bytes().all(|b| b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'-'
            || b == b'.'));
        if let Some(host) = web_origin_host(&format!("https://{text}")) {
            assert!(host_matches_rp_id(&host, text));
        }
    }
    if let Some((left, right)) = text.split_once('\n')
        && host_matches_rp_id(left, right)
    {
        assert!(left == right || left.ends_with(&format!(".{right}")));
    }
});
