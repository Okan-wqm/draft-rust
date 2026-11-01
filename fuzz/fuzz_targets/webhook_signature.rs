//! Owner: authn-audit (AUD-07). TST-04: the webhook delivery signing path of
//! authn-audit on top of `authn_crypto::webhook` (whose parser has its own
//! `webhook_verify` target).
//!
//! Input: `selector byte ‖ webhook-id \n unix-timestamp \n stored payload`.
//! Invariants:
//! * nothing panics (canonical JSON, header construction, signing);
//! * the canonical body is a fixed point (re-parsing and re-encoding the
//!   delivered bytes reproduces them — what receivers and the audit chain
//!   rely on);
//! * every header set that is produced carries the input id and timestamp,
//!   one `v1` signature per secret, verifies with each secret, and does not
//!   verify for a modified body, another id or an unknown secret;
//! * ids that could make the signed content ambiguous (`.`) are refused.
#![no_main]

use std::sync::OnceLock;

use authn_audit::canonical::to_canonical_vec;
use authn_audit::webhooks::signed_delivery_headers;
use authn_crypto::webhook::{SignedHeaders, WebhookSecret, parse_signature_header, verify};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

fn secrets() -> &'static [WebhookSecret; 3] {
    static SECRETS: OnceLock<[WebhookSecret; 3]> = OnceLock::new();
    SECRETS.get_or_init(|| {
        [
            WebhookSecret::parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").expect("secret"),
            WebhookSecret::parse("whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
                .expect("secret"),
            WebhookSecret::parse("whsec_ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=")
                .expect("secret"),
        ]
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let mut parts = text.splitn(3, '\n');
    let (Some(id), Some(timestamp), Some(payload)) = (parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    let Ok(seconds) = timestamp.parse::<i64>() else {
        return;
    };
    let Ok(at) = OffsetDateTime::from_unix_timestamp(seconds) else {
        return;
    };

    // Stored payload → delivered body (canonical JSON).
    let body = match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(value) => match to_canonical_vec(&value) {
            Ok(body) => {
                let reparsed: serde_json::Value =
                    serde_json::from_slice(&body).expect("canonical output is JSON");
                assert_eq!(to_canonical_vec(&reparsed).expect("fixed point"), body);
                body
            }
            Err(_) => payload.as_bytes().to_vec(),
        },
        Err(_) => payload.as_bytes().to_vec(),
    };

    let all = secrets();
    let count = usize::from(selector % 2) + 1;
    let signing = &all[..count];
    let Ok(headers) = signed_delivery_headers(signing, id, at, &body) else {
        return;
    };
    assert!(
        !id.is_empty() && !id.contains('.'),
        "ambiguous id accepted: {id:?}"
    );
    let get = |name: &str| {
        headers
            .get(name)
            .expect("header present")
            .to_str()
            .expect("ascii header")
            .to_owned()
    };
    let signed = SignedHeaders {
        id: get("webhook-id"),
        timestamp: get("webhook-timestamp"),
        signature: get("webhook-signature"),
    };
    assert_eq!(signed.id, id);
    assert_eq!(signed.timestamp, seconds.to_string());
    let tags = parse_signature_header(&signed.signature).expect("own header parses");
    assert_eq!(tags.len(), count);

    if seconds < 0 {
        // Receivers refuse pre-1970 timestamps; nothing more to check.
        return;
    }
    for secret in signing {
        assert!(verify(std::slice::from_ref(secret), &signed, &body, at, 300).is_ok());
    }
    assert!(
        verify(&all[2..], &signed, &body, at, 300).is_err(),
        "unknown secret verified"
    );
    let mut tampered = body.clone();
    tampered.push(b' ');
    assert!(
        verify(signing, &signed, &tampered, at, 300).is_err(),
        "modified body verified"
    );
    let mut other_id = signed.clone();
    other_id.id.push('x');
    assert!(
        verify(signing, &other_id, &body, at, 300).is_err(),
        "other id verified"
    );
});
