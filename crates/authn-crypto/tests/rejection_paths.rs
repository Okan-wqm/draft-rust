//! Rejection paths of the authn-crypto parsers and verifiers that the
//! coverage report (docs/operations/coverage.md) showed as never exercised
//! by a unit test. The fuzz targets reach them too, but fuzzing is not part
//! of `cargo test`; these keep them under regression.

use authn_crypto::CryptoError;
use authn_crypto::envelope::{ENVELOPE_VERSION, Envelope, EnvelopeContext, NONCE_LEN, TAG_LEN};
use authn_crypto::totp::{Totp, TotpParams, TotpSecret};
use authn_crypto::webhook::{self, SignedHeaders, WebhookError, WebhookSecret};
use time::macros::datetime;

const NOW: time::OffsetDateTime = datetime!(2026-05-01 12:00:00 UTC);

#[test]
fn cry_08_envelope_context_rejects_non_identifier_table_and_column_names() {
    assert!(EnvelopeContext::new("mfa_factors", "secret", "row-1").is_ok());
    for (table, column) in [
        ("", "secret"),
        ("Mfa", "secret"),
        ("1mfa", "secret"),
        ("mfa-factors", "secret"),
        ("mfa", "se cret"),
        ("mfa", ""),
    ] {
        assert_eq!(
            EnvelopeContext::new(table, column, "row-1").unwrap_err(),
            CryptoError::Malformed,
            "{table}.{column}"
        );
    }
    let long: &'static str = Box::leak("a".repeat(64).into_boxed_str());
    assert_eq!(
        EnvelopeContext::new(long, "secret", "row-1").unwrap_err(),
        CryptoError::Malformed
    );
}

#[test]
fn cry_08_envelope_without_a_full_tag_is_rejected() {
    // Version, kek id "k1", a 1-byte wrapped key, the nonce and then fewer
    // ciphertext bytes than one Poly1305 tag.
    let mut bytes = vec![ENVELOPE_VERSION, 2, b'k', b'1', 0, 1, 0xAA];
    bytes.extend_from_slice(&[0; NONCE_LEN]);
    for ciphertext_len in [0, 1, TAG_LEN - 1] {
        let mut envelope = bytes.clone();
        envelope.extend(std::iter::repeat_n(0, ciphertext_len));
        assert_eq!(
            Envelope::parse(&envelope).unwrap_err(),
            CryptoError::Malformed,
            "{ciphertext_len} ciphertext bytes"
        );
    }
    let mut envelope = bytes;
    envelope.extend_from_slice(&[0; TAG_LEN]);
    assert_eq!(Envelope::parse(&envelope).unwrap().plaintext_len(), 0);
}

#[test]
fn aud_07_webhook_secret_rejects_oversized_text_before_decoding() {
    let oversized = format!("{}{}", webhook::SECRET_PREFIX, "A".repeat(129));
    assert_eq!(
        WebhookSecret::parse(&oversized).unwrap_err(),
        CryptoError::TooLarge
    );
}

#[test]
fn aud_07_webhook_id_must_be_a_short_token() {
    let secret = WebhookSecret::generate().unwrap();
    let secrets = [secret];
    for id in [String::new(), "a".repeat(257), "msg 1".to_owned()] {
        assert_eq!(
            webhook::sign(&secrets, &id, NOW, b"{}").unwrap_err(),
            WebhookError::InvalidId,
            "{id:?}"
        );
        let headers = SignedHeaders {
            id: id.clone(),
            timestamp: NOW.unix_timestamp().to_string(),
            signature: "v1,AAAA".to_owned(),
        };
        assert_eq!(
            webhook::verify(&secrets, &headers, b"{}", NOW, 300).unwrap_err(),
            WebhookError::InvalidId
        );
    }
}

#[test]
fn aud_07_webhook_signing_needs_one_to_max_secrets() {
    assert_eq!(
        webhook::sign(&[], "msg_1", NOW, b"{}").unwrap_err(),
        WebhookError::Signing
    );
    let many: Vec<WebhookSecret> = (0..64)
        .map(|_| WebhookSecret::generate().unwrap())
        .collect();
    assert_eq!(
        webhook::sign(&many, "msg_1", NOW, b"{}").unwrap_err(),
        WebhookError::Signing
    );
}

#[test]
fn aud_07_webhook_timestamp_must_be_canonical_decimal() {
    let secrets = [WebhookSecret::generate().unwrap()];
    let signed = webhook::sign(&secrets, "msg_1", NOW, b"{}").unwrap();
    assert!(webhook::verify(&secrets, &signed, b"{}", NOW, 300).is_ok());
    // The same instant written with a leading zero, a sign or spaces is not
    // the signed text: refused before any HMAC is computed.
    for timestamp in [
        format!("0{}", signed.timestamp),
        format!("+{}", signed.timestamp),
        format!("-{}", signed.timestamp),
        format!(" {}", signed.timestamp),
        String::new(),
        "1".repeat(13),
    ] {
        let headers = SignedHeaders {
            timestamp: timestamp.clone(),
            ..signed.clone()
        };
        assert_eq!(
            webhook::verify(&secrets, &headers, b"{}", NOW, 300).unwrap_err(),
            WebhookError::InvalidTimestamp,
            "{timestamp:?}"
        );
    }
}

#[test]
fn mfa_01_totp_provisioning_uri_rejects_ambiguous_issuer_and_account() {
    let totp = Totp::new(TotpParams::default()).unwrap();
    let secret = TotpSecret::generate().unwrap();
    assert!(
        totp.provisioning_uri(&secret, "Example", "user@example.com")
            .is_ok()
    );
    for (issuer, account) in [
        ("Exa:mple", "user@example.com"),
        ("", "user@example.com"),
        ("Example", ""),
        ("Example", "user\n@example.com"),
    ] {
        assert_eq!(
            totp.provisioning_uri(&secret, issuer, account).unwrap_err(),
            CryptoError::Malformed,
            "{issuer:?} / {account:?}"
        );
    }
    let long = "a".repeat(257);
    assert!(totp.provisioning_uri(&secret, &long, "user").is_err());
}
