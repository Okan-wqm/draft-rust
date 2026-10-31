//! Standard Webhooks signatures (AUD-07 core; <https://www.standardwebhooks.com>).
//!
//! * Secret: `whsec_` + base64 of 32 CSPRNG bytes (24..=64 bytes accepted).
//! * Signed content: `{webhook-id}.{webhook-timestamp}.{body}`.
//! * `webhook-signature`: space-separated `v1,<base64(HMAC-SHA256)>` entries
//!   (several during secret rotation).
//!
//! Hardening beyond the spec text:
//! * `webhook-id` is restricted to `[A-Za-z0-9_-]{1,256}`: a `.` in the id
//!   would make the signed content ambiguous (`id="a.1", ts=2` vs.
//!   `id="a", ts=1, body="2.…"`), allowing a signature to be transplanted
//!   onto a different body.
//! * The timestamp must be a canonical decimal and within the tolerance in
//!   *both* directions (replay window).
//! * Header size and entry count are bounded; every candidate signature is
//!   compared in constant time against every secret without early exit.

use std::fmt;

use time::OffsetDateTime;

use crate::encoding::{b64_decode, b64_encode};
use crate::kdf::hmac_sha256_parts;
use crate::secret::SecretBytes;
use crate::{CryptoError, ct, random};

/// Prefix of serialized secrets.
pub const SECRET_PREFIX: &str = "whsec_";
/// Default timestamp tolerance (5 minutes).
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;
const MAX_HEADER_LEN: usize = 4096;
const MAX_SIGNATURES: usize = 16;
const MAX_ID_LEN: usize = 256;

/// A webhook signing secret.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret(SecretBytes);

impl WebhookSecret {
    /// A new 256-bit secret.
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = random::secret_bytes::<32>()?;
        Ok(Self(SecretBytes::new(bytes.to_vec())))
    }

    /// Parses `whsec_<base64>` (24..=64 key bytes).
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let encoded = text
            .strip_prefix(SECRET_PREFIX)
            .ok_or(CryptoError::Malformed)?;
        if encoded.len() > 128 {
            return Err(CryptoError::TooLarge);
        }
        let bytes = SecretBytes::new(b64_decode(encoded)?);
        if !(24..=64).contains(&bytes.len()) {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(bytes))
    }

    /// The `whsec_…` form (shown once to the endpoint owner; store it
    /// envelope-encrypted).
    #[must_use]
    pub fn to_text(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(format!("{SECRET_PREFIX}{}", b64_encode(self.0.expose())))
    }

    fn tag(&self, id: &str, timestamp: i64, body: &[u8]) -> Result<[u8; 32], CryptoError> {
        let ts = timestamp.to_string();
        hmac_sha256_parts(
            self.0.expose(),
            &[id.as_bytes(), b".", ts.as_bytes(), b".", body],
        )
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebhookSecret({})", crate::secret::REDACTED)
    }
}

/// Why a delivery was rejected (for logs; receivers answer 4xx uniformly).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebhookError {
    /// Missing or malformed `webhook-id`.
    #[error("invalid webhook-id")]
    InvalidId,
    /// Missing or malformed `webhook-timestamp`.
    #[error("invalid webhook-timestamp")]
    InvalidTimestamp,
    /// Timestamp outside the tolerance.
    #[error("webhook timestamp outside tolerance")]
    TimestampOutOfTolerance,
    /// Missing or malformed `webhook-signature`.
    #[error("invalid webhook-signature header")]
    InvalidSignatureHeader,
    /// No signature matched any secret.
    #[error("no matching webhook signature")]
    NoMatchingSignature,
    /// Signing failed (invalid id, internal error).
    #[error("webhook signing failed")]
    Signing,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The three headers of a signed delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `webhook-id`.
    pub id: String,
    /// `webhook-timestamp` (Unix seconds).
    pub timestamp: String,
    /// `webhook-signature`.
    pub signature: String,
}

/// Signs a delivery with every given secret (one `v1,` entry per secret, so
/// receivers keep working during secret rotation).
pub fn sign(
    secrets: &[WebhookSecret],
    id: &str,
    at: OffsetDateTime,
    body: &[u8],
) -> Result<SignedHeaders, WebhookError> {
    if !valid_id(id) {
        return Err(WebhookError::InvalidId);
    }
    if secrets.is_empty() || secrets.len() > MAX_SIGNATURES {
        return Err(WebhookError::Signing);
    }
    let timestamp = at.unix_timestamp();
    let mut entries = Vec::with_capacity(secrets.len());
    for secret in secrets {
        let tag = secret
            .tag(id, timestamp, body)
            .map_err(|_| WebhookError::Signing)?;
        entries.push(format!("v1,{}", b64_encode(&tag)));
    }
    Ok(SignedHeaders {
        id: id.to_owned(),
        timestamp: timestamp.to_string(),
        signature: entries.join(" "),
    })
}

/// Verifies a delivery against any of `secrets` with a timestamp tolerance
/// (seconds, applied in both directions).
pub fn verify(
    secrets: &[WebhookSecret],
    headers: &SignedHeaders,
    body: &[u8],
    now: OffsetDateTime,
    tolerance_secs: i64,
) -> Result<(), WebhookError> {
    if !valid_id(&headers.id) {
        return Err(WebhookError::InvalidId);
    }
    let timestamp = parse_timestamp(&headers.timestamp).ok_or(WebhookError::InvalidTimestamp)?;
    let age = now.unix_timestamp().saturating_sub(timestamp);
    if age.saturating_abs() > tolerance_secs.max(0) {
        return Err(WebhookError::TimestampOutOfTolerance);
    }
    let candidates = parse_signature_header(&headers.signature)?;
    let mut matched = false;
    for secret in secrets {
        let expected = secret
            .tag(&headers.id, timestamp, body)
            .map_err(|_| WebhookError::NoMatchingSignature)?;
        for candidate in &candidates {
            // No early exit: every pair is compared.
            matched |= ct::constant_time_eq(&expected, candidate);
        }
    }
    if matched {
        Ok(())
    } else {
        Err(WebhookError::NoMatchingSignature)
    }
}

/// Canonical decimal Unix timestamp (optional leading '-' is refused: no
/// legitimate delivery predates 1970).
fn parse_timestamp(text: &str) -> Option<i64> {
    let canonical = !text.is_empty()
        && text.len() <= 12
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

/// Extracts the `v1` signatures (32 bytes each) of a `webhook-signature`
/// header. Entries of unknown versions are skipped; malformed `v1` entries
/// make the whole header invalid.
pub fn parse_signature_header(header: &str) -> Result<Vec<[u8; 32]>, WebhookError> {
    if header.is_empty() || header.len() > MAX_HEADER_LEN {
        return Err(WebhookError::InvalidSignatureHeader);
    }
    let mut out = Vec::new();
    for (index, entry) in header.split(' ').filter(|e| !e.is_empty()).enumerate() {
        if index >= MAX_SIGNATURES {
            return Err(WebhookError::InvalidSignatureHeader);
        }
        let (version, value) = entry
            .split_once(',')
            .ok_or(WebhookError::InvalidSignatureHeader)?;
        if version != "v1" {
            continue;
        }
        let bytes = b64_decode(value).map_err(|_| WebhookError::InvalidSignatureHeader)?;
        let tag: [u8; 32] = bytes
            .try_into()
            .map_err(|_| WebhookError::InvalidSignatureHeader)?;
        out.push(tag);
    }
    if out.is_empty() {
        return Err(WebhookError::InvalidSignatureHeader);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::string_slice)] // ASCII fixtures
mod tests {
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-02-01 10:00:00 UTC);

    /// Example from the Standard Webhooks reference libraries.
    #[test]
    fn aud_07_standard_webhooks_reference_vector() {
        let secret = WebhookSecret::parse("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
        let headers = SignedHeaders {
            id: "msg_p5jXN8AQM9LWM0D4loKWxJek".to_owned(),
            timestamp: "1614265330".to_owned(),
            signature: "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=".to_owned(),
        };
        let body = br#"{"test": 2432232314}"#;
        let at = OffsetDateTime::from_unix_timestamp(1_614_265_330).unwrap();
        assert_eq!(
            verify(
                std::slice::from_ref(&secret),
                &headers,
                body,
                at,
                DEFAULT_TOLERANCE_SECS
            ),
            Ok(())
        );
        let signed = sign(&[secret], &headers.id, at, body).unwrap();
        assert_eq!(signed, headers);
    }

    #[test]
    fn aud_07_sign_verify_rotation_and_tampering() {
        let old = WebhookSecret::generate().unwrap();
        let new = WebhookSecret::generate().unwrap();
        let signed = sign(&[new.clone(), old.clone()], "msg_1", NOW, b"{}").unwrap();
        assert_eq!(signed.signature.split(' ').count(), 2);
        // Receivers with either secret accept.
        assert!(verify(std::slice::from_ref(&old), &signed, b"{}", NOW, 300).is_ok());
        assert!(verify(std::slice::from_ref(&new), &signed, b"{}", NOW, 300).is_ok());
        // Tampering with body, id or timestamp fails.
        assert_eq!(
            verify(std::slice::from_ref(&old), &signed, b"{ }", NOW, 300),
            Err(WebhookError::NoMatchingSignature)
        );
        let mut other_id = signed.clone();
        other_id.id = "msg_2".to_owned();
        assert!(verify(std::slice::from_ref(&old), &other_id, b"{}", NOW, 300).is_err());
        let mut other_ts = signed.clone();
        other_ts.timestamp = (NOW.unix_timestamp() + 1).to_string();
        assert!(verify(std::slice::from_ref(&old), &other_ts, b"{}", NOW, 300).is_err());
        let stranger = WebhookSecret::generate().unwrap();
        assert!(verify(&[stranger], &signed, b"{}", NOW, 300).is_err());
    }

    #[test]
    fn aud_07_timestamp_tolerance_both_directions() {
        let secret = WebhookSecret::generate().unwrap();
        let signed = sign(std::slice::from_ref(&secret), "msg", NOW, b"x").unwrap();
        let later = NOW + time::Duration::seconds(301);
        let earlier = NOW - time::Duration::seconds(301);
        assert_eq!(
            verify(std::slice::from_ref(&secret), &signed, b"x", later, 300),
            Err(WebhookError::TimestampOutOfTolerance)
        );
        assert_eq!(
            verify(std::slice::from_ref(&secret), &signed, b"x", earlier, 300),
            Err(WebhookError::TimestampOutOfTolerance)
        );
        assert!(
            verify(
                std::slice::from_ref(&secret),
                &signed,
                b"x",
                NOW + time::Duration::seconds(300),
                300
            )
            .is_ok()
        );
        for bad in ["", "-1", "01", "1.5", "１２", "9999999999999"] {
            let mut h = signed.clone();
            h.timestamp = bad.to_owned();
            assert_eq!(
                verify(std::slice::from_ref(&secret), &h, b"x", NOW, 300),
                Err(WebhookError::InvalidTimestamp),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn aud_07_ids_with_dots_are_refused() {
        let secret = WebhookSecret::generate().unwrap();
        assert_eq!(
            sign(std::slice::from_ref(&secret), "a.1", NOW, b"x").unwrap_err(),
            WebhookError::InvalidId
        );
        let mut signed = sign(std::slice::from_ref(&secret), "a", NOW, b"x").unwrap();
        signed.id = "a.b".to_owned();
        assert_eq!(
            verify(&[secret], &signed, b"x", NOW, 300),
            Err(WebhookError::InvalidId)
        );
    }

    #[test]
    fn aud_07_signature_header_parsing() {
        let tag = b64_encode(&[7; 32]);
        assert_eq!(
            parse_signature_header(&format!("v1,{tag}")).unwrap(),
            vec![[7; 32]]
        );
        assert_eq!(
            parse_signature_header(&format!("v1a,xyz v1,{tag}")).unwrap(),
            vec![[7; 32]]
        );
        for bad in [
            String::new(),
            "v1".to_owned(),
            "v1,".to_owned(),
            "v1,AAAA".to_owned(),
            format!("v2,{tag}"),
            format!("v1,{}", &tag[..tag.len() - 1]),
            vec![format!("v1,{tag}"); 17].join(" "),
            "x".repeat(5000),
        ] {
            assert!(parse_signature_header(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn aud_07_secret_format() {
        let secret = WebhookSecret::generate().unwrap();
        let text = secret.to_text();
        assert!(text.starts_with(SECRET_PREFIX));
        assert_eq!(WebhookSecret::parse(&text).unwrap(), secret);
        assert!(WebhookSecret::parse("whsec_AAAA").is_err());
        assert!(WebhookSecret::parse("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").is_err());
        assert!(!format!("{secret:?}").contains(&text[6..12]));
    }
}
