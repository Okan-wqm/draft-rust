//! Owner: authn-crypto (AUD-07 core). TST-04: Standard Webhooks header
//! parsing and signature verification of `authn_crypto::webhook` (the
//! `webhook_signature` target belongs to authn-audit and covers its own
//! delivery code on top of this).
//!
//! Input: `id \n timestamp \n signature-header \n body`. Invariants: no
//! panic; an attacker-built header never verifies.
#![no_main]

use std::sync::OnceLock;

use authn_crypto::webhook::{SignedHeaders, WebhookSecret, parse_signature_header, verify};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

fn secret() -> &'static WebhookSecret {
    static SECRET: OnceLock<WebhookSecret> = OnceLock::new();
    SECRET.get_or_init(|| WebhookSecret::parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").expect("secret"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut parts = text.splitn(4, '\n');
    let (Some(id), Some(timestamp), Some(signature), Some(body)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    if let Ok(tags) = parse_signature_header(signature) {
        assert!(!tags.is_empty() && tags.len() <= 16);
    }
    let headers = SignedHeaders {
        id: id.to_owned(),
        timestamp: timestamp.to_owned(),
        signature: signature.to_owned(),
    };
    let now = OffsetDateTime::from_unix_timestamp(1_614_265_330).expect("time");
    let result = verify(std::slice::from_ref(secret()), &headers, body.as_bytes(), now, 300);
    // The only known valid signature is the reference vector; anything else
    // is a forgery and must fail.
    let reference = id == "msg_p5jXN8AQM9LWM0D4loKWxJek"
        && timestamp == "1614265330"
        && body == r#"{"test": 2432232314}"#;
    if !reference {
        assert!(result.is_err());
    }
});
