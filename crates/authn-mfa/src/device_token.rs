//! Signed trusted-device tokens (MFA-09).
//!
//! Wire format (ASCII, ≤ 160 bytes):
//!
//! ```text
//! td1.<device id: 32 lowercase hex>.<expiry: unix seconds>.<nonce: 43 b64url>.<tag: 43 b64url>
//! ```
//!
//! * `nonce` — 256 bits from the OS CSPRNG; the token is a bearer secret.
//! * `tag` — `HMAC-SHA256(K_trusted_device, len‖"td1"‖len‖user‖len‖id‖len‖exp‖len‖nonce)`
//!   with the [`KeyPurpose::TrustedDevice`] HKDF sub-key (CRY-11). The user
//!   id is *not* in the token but in the MAC input, so a token can only ever
//!   vouch for the user it was issued to.
//! * The database stores only `SHA-256(token)` (`trusted_devices.token_hash`);
//!   revocation and expiry are enforced there. The MAC lets forged or
//!   tampered tokens be rejected without touching the database.
//!
//! Parsing is strict (canonical base64url, canonical decimal, exact field
//! count and lengths) and never panics on hostile input.

use std::fmt;

use authn_core::id::{TrustedDeviceId, UserId};
use authn_crypto::CryptoError;
use authn_crypto::kdf::{HmacKey, KeyPurpose, KeyRing};
use authn_crypto::random;
use authn_crypto::token::TokenHash;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Version prefix of the format.
const PREFIX: &str = "td1";
/// Longest accepted token.
pub const MAX_TOKEN_LEN: usize = 160;
const B64_32_LEN: usize = 43;

/// A trusted-device token (bearer secret). Redacted `Debug`, no `Display`,
/// zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedDeviceToken(Zeroizing<String>);

impl TrustedDeviceToken {
    /// The token text (for the cookie / response only).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The storage hash (`SHA-256` of the text).
    #[must_use]
    pub fn hash(&self) -> TokenHash {
        TokenHash::digest(self.0.as_bytes())
    }
}

impl fmt::Debug for TrustedDeviceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrustedDeviceToken({})", authn_core::secret::REDACTED)
    }
}

/// What a valid token vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceToken {
    /// The `trusted_devices` row.
    pub device_id: TrustedDeviceId,
    /// Expiry embedded in (and authenticated by) the token.
    pub expires_at: OffsetDateTime,
    /// Storage hash to look the row up with.
    pub token_hash: TokenHash,
}

/// Issues and verifies trusted-device tokens.
#[derive(Clone)]
pub struct DeviceTokenSigner {
    key: HmacKey,
}

impl fmt::Debug for DeviceTokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceTokenSigner").finish_non_exhaustive()
    }
}

impl DeviceTokenSigner {
    /// A signer with the [`KeyPurpose::TrustedDevice`] sub-key.
    pub fn new(ring: &KeyRing) -> Result<Self, CryptoError> {
        Ok(Self {
            key: ring.key(KeyPurpose::TrustedDevice)?.clone(),
        })
    }

    /// Issues a token for `user` / `device` valid until `expires_at`.
    pub fn issue(
        &self,
        user: UserId,
        device: TrustedDeviceId,
        expires_at: OffsetDateTime,
    ) -> Result<TrustedDeviceToken, CryptoError> {
        let nonce = random::secret_bytes::<32>()?;
        let id_hex = HEXLOWER.encode(device.as_uuid().as_bytes());
        let exp = expires_at.unix_timestamp().to_string();
        let nonce_b64 = Zeroizing::new(BASE64URL_NOPAD.encode(nonce.as_slice()));
        let tag = self.tag(user, &id_hex, &exp, nonce_b64.as_bytes());
        Ok(TrustedDeviceToken(Zeroizing::new(format!(
            "{PREFIX}.{id_hex}.{exp}.{}.{}",
            nonce_b64.as_str(),
            BASE64URL_NOPAD.encode(&tag)
        ))))
    }

    /// Verifies the format, the MAC for `user` and the embedded expiry.
    /// `None` for anything invalid (callers treat that as "not trusted").
    #[must_use]
    pub fn verify(
        &self,
        user: UserId,
        token: &str,
        now: OffsetDateTime,
    ) -> Option<VerifiedDeviceToken> {
        if token.len() > MAX_TOKEN_LEN || !token.is_ascii() {
            return None;
        }
        let mut parts = token.split('.');
        let (Some(prefix), Some(id_hex), Some(exp), Some(nonce), Some(tag), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        if prefix != PREFIX
            || id_hex.len() != 32
            || nonce.len() != B64_32_LEN
            || tag.len() != B64_32_LEN
        {
            return None;
        }
        let id_bytes = HEXLOWER.decode(id_hex.as_bytes()).ok()?;
        let device = TrustedDeviceId::from_uuid(Uuid::from_slice(&id_bytes).ok()?);
        let exp_secs = parse_canonical_decimal(exp)?;
        let nonce_bytes = Zeroizing::new(decode_canonical_b64(nonce)?);
        let tag_bytes = decode_canonical_b64(tag)?;
        if nonce_bytes.len() != 32 || tag_bytes.len() != 32 {
            return None;
        }
        let expected = self.tag(user, id_hex, exp, nonce.as_bytes());
        if !authn_crypto::ct::constant_time_eq(&expected, &tag_bytes) {
            return None;
        }
        let expires_at = OffsetDateTime::from_unix_timestamp(exp_secs).ok()?;
        if expires_at <= now {
            return None;
        }
        Some(VerifiedDeviceToken {
            device_id: device,
            expires_at,
            token_hash: TokenHash::digest(token.as_bytes()),
        })
    }

    fn tag(&self, user: UserId, id_hex: &str, exp: &str, nonce_b64: &[u8]) -> [u8; 32] {
        self.key.sign_fields(&[
            PREFIX.as_bytes(),
            user.as_uuid().as_bytes().as_slice(),
            id_hex.as_bytes(),
            exp.as_bytes(),
            nonce_b64,
        ])
    }
}

/// Canonical decimal (no sign, no leading zero, ≤ 12 digits).
fn parse_canonical_decimal(text: &str) -> Option<i64> {
    if text.is_empty()
        || text.len() > 12
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

/// Canonical unpadded base64url (re-encoding must give the same text).
fn decode_canonical_b64(text: &str) -> Option<Vec<u8>> {
    let bytes = BASE64URL_NOPAD.decode(text.as_bytes()).ok()?;
    (BASE64URL_NOPAD.encode(&bytes) == text).then_some(bytes)
}

#[cfg(test)]
#[allow(clippy::string_slice)] // ASCII fixtures
mod tests {
    use std::time::Duration;

    use time::macros::datetime;

    use super::*;

    fn signer() -> DeviceTokenSigner {
        DeviceTokenSigner::new(&KeyRing::derive(&[3; 32]).unwrap()).unwrap()
    }

    const NOW: OffsetDateTime = datetime!(2026-01-01 00:00:00 UTC);

    #[test]
    fn mfa_09_round_trip_and_binding() {
        let s = signer();
        let user = UserId::generate();
        let device = TrustedDeviceId::generate();
        let exp = NOW + Duration::from_secs(30 * 86_400);
        let token = s.issue(user, device, exp).unwrap();
        assert!(token.expose().len() <= MAX_TOKEN_LEN);
        let ok = s.verify(user, token.expose(), NOW).unwrap();
        assert_eq!(ok.device_id, device);
        assert_eq!(ok.expires_at, exp);
        assert_eq!(ok.token_hash, token.hash());
        // Another user, another key, after expiry: rejected.
        assert!(s.verify(UserId::generate(), token.expose(), NOW).is_none());
        let other = DeviceTokenSigner::new(&KeyRing::derive(&[4; 32]).unwrap()).unwrap();
        assert!(other.verify(user, token.expose(), NOW).is_none());
        assert!(s.verify(user, token.expose(), exp).is_none());
        // Two tokens for the same device differ (random nonce).
        assert_ne!(s.issue(user, device, exp).unwrap(), token);
    }

    #[test]
    fn mfa_09_tampering_is_rejected() {
        let s = signer();
        let user = UserId::generate();
        let exp = NOW + Duration::from_secs(86_400);
        let token = s.issue(user, TrustedDeviceId::generate(), exp).unwrap();
        let text = token.expose().to_owned();
        let parts: Vec<&str> = text.split('.').collect();
        // Extended expiry with the old tag.
        let later = (exp + Duration::from_secs(86_400))
            .unix_timestamp()
            .to_string();
        let forged = format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], later, parts[3], parts[4]
        );
        assert!(s.verify(user, &forged, NOW).is_none());
        // Other device id with the old tag.
        let other_id = HEXLOWER.encode(TrustedDeviceId::generate().as_uuid().as_bytes());
        let forged = format!(
            "{}.{}.{}.{}.{}",
            parts[0], other_id, parts[2], parts[3], parts[4]
        );
        assert!(s.verify(user, &forged, NOW).is_none());
        // Every single-character change of the tag fails.
        for i in 0..parts[4].len() {
            let mut tag = parts[4].as_bytes().to_vec();
            tag[i] = if tag[i] == b'A' { b'B' } else { b'A' };
            let forged = format!(
                "{}.{}.{}.{}.{}",
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                String::from_utf8(tag).unwrap()
            );
            assert!(s.verify(user, &forged, NOW).is_none());
        }
    }

    #[test]
    fn mfa_09_malformed_tokens_are_rejected_without_panic() {
        let s = signer();
        let user = UserId::generate();
        let token = s
            .issue(
                user,
                TrustedDeviceId::generate(),
                NOW + Duration::from_secs(60),
            )
            .unwrap();
        let text = token.expose();
        for bad in [
            String::new(),
            "td1".to_owned(),
            "td1.....".to_owned(),
            text.replacen("td1", "td2", 1),
            format!("{text}."),
            format!("{text}A"),
            text[..text.len() - 1].to_owned(),
            text.to_uppercase(),
            "ü".repeat(10),
            "A".repeat(10_000),
            text.replace('.', ".0"),
        ] {
            assert!(s.verify(user, &bad, NOW).is_none(), "{bad:?}");
        }
        assert_eq!(parse_canonical_decimal("0"), Some(0));
        assert_eq!(parse_canonical_decimal("01"), None);
        assert_eq!(parse_canonical_decimal("-1"), None);
        assert_eq!(parse_canonical_decimal("+1"), None);
        assert_eq!(parse_canonical_decimal("9999999999999"), None);
    }

    #[test]
    fn cry_13_device_tokens_are_redacted() {
        let token = signer()
            .issue(UserId::generate(), TrustedDeviceId::generate(), NOW)
            .unwrap();
        assert!(!format!("{token:?}").contains(&token.expose()[4..20]));
    }
}
