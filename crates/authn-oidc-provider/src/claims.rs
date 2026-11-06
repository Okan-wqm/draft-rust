//! Token claim sets (OIDP-08) and the `acr` model.
//!
//! * **Access tokens** follow RFC 9068 (`typ: at+jwt`). They deliberately
//!   carry no `sid` and their `aud` never contains an audience of the
//!   native (first-party) access tokens: the native verifier of
//!   authn-session requires `sid` and its own audience, so a provider
//!   token can never be used as a native token, and the provider looks up
//!   every presented access token by `jti` in its own table, so a native
//!   token is never accepted by the provider either (token-type confusion,
//!   OIDP-08).
//! * **ID tokens** (`typ: JWT`) follow OIDC Core §2 / §3.1.3.6: `at_hash`,
//!   `nonce`, `auth_time`, `amr`, `acr`, `azp`, `sid`. They carry no
//!   personal data besides the opaque `sub`; profile and e-mail claims are
//!   served by `userinfo`.
//!
//! **`acr` values** (OIDP-04) are derived from the session's RFC 8176
//! `amr`, never from client input:
//!
//! | Value | Meaning | Rule |
//! |-------|---------|------|
//! | [`ACR_PHR`] | phishing-resistant multi-factor | a passkey (`hwk`/`swk`) with user verification or a second factor (`mfa`, `pin`, `fpt`, `face`) |
//! | [`ACR_AAL2`] | multi-factor | `mfa`, or [`ACR_PHR`] |
//! | [`ACR_AAL1`] | single factor | any session |
//!
//! A higher level satisfies a lower one.

use authn_core::domain::AuthMethodRef;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

/// Single-factor authentication.
pub const ACR_AAL1: &str = "urn:rust-authentication:acr:aal1";
/// Multi-factor authentication.
pub const ACR_AAL2: &str = "urn:rust-authentication:acr:aal2";
/// Phishing-resistant multi-factor authentication (passkey).
pub const ACR_PHR: &str = "urn:rust-authentication:acr:phr";
/// Every supported `acr` value, weakest first.
pub const ACR_VALUES: &[&str] = &[ACR_AAL1, ACR_AAL2, ACR_PHR];

/// `typ` header of ID tokens.
pub const TYP_ID_TOKEN: &str = "JWT";

fn rank(acr: &str) -> Option<u8> {
    ACR_VALUES
        .iter()
        .position(|v| *v == acr)
        .and_then(|p| u8::try_from(p).ok())
}

/// The `acr` level a session with `amr` reached.
#[must_use]
pub fn acr_for(amr: &[AuthMethodRef]) -> &'static str {
    let key = amr
        .iter()
        .any(|a| matches!(a, AuthMethodRef::Hwk | AuthMethodRef::Swk));
    let verified = amr.iter().any(|a| {
        matches!(
            a,
            AuthMethodRef::Mfa | AuthMethodRef::Pin | AuthMethodRef::Fpt | AuthMethodRef::Face
        )
    });
    if key && verified {
        ACR_PHR
    } else if amr.contains(&AuthMethodRef::Mfa) {
        ACR_AAL2
    } else {
        ACR_AAL1
    }
}

/// Whether a session with `amr` satisfies at least one of the requested
/// `acr_values` (an empty request is always satisfied; unknown values were
/// dropped while parsing).
#[must_use]
pub fn satisfies(amr: &[AuthMethodRef], requested: &[String]) -> bool {
    if requested.is_empty() {
        return true;
    }
    let have = rank(acr_for(amr)).unwrap_or(0);
    requested
        .iter()
        .filter_map(|r| rank(r))
        .any(|want| have >= want)
}

/// The claim set of a provider access token (RFC 9068 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAccessTokenClaims {
    /// Issuer.
    pub iss: String,
    /// Subject: the opaque user id.
    pub sub: String,
    /// Audiences: the requested resources (RFC 8707), else the client;
    /// plus the `userinfo` endpoint when `openid` was granted.
    pub aud: Vec<String>,
    /// Expiry.
    pub exp: i64,
    /// Issue time.
    pub iat: i64,
    /// Token id (the `oidc_access_tokens` row).
    pub jti: String,
    /// The client the token was issued to.
    pub client_id: String,
    /// Space-separated granted scopes.
    pub scope: String,
    /// Time of the user's authentication.
    pub auth_time: i64,
    /// Authentication context class.
    pub acr: String,
}

/// The claim set of an ID token (OIDC Core §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer.
    pub iss: String,
    /// Subject.
    pub sub: String,
    /// Audience: the client id.
    pub aud: Vec<String>,
    /// Authorized party: the client id.
    pub azp: String,
    /// Expiry.
    pub exp: i64,
    /// Issue time.
    pub iat: i64,
    /// Time of the user's authentication.
    pub auth_time: i64,
    /// The `nonce` of the authorization request (absent on refresh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Authentication methods (RFC 8176).
    pub amr: Vec<AuthMethodRef>,
    /// Authentication context class.
    pub acr: String,
    /// Left half of SHA-256 of the access token, base64url (OIDC Core
    /// §3.1.3.6).
    pub at_hash: String,
    /// The provider session (the user's session at this server).
    pub sid: String,
}

/// `at_hash` of `access_token` (OIDC Core §3.1.3.6): the left half of the
/// hash of its ASCII octets, base64url without padding. The hash is the
/// one of the ID token's `alg`; for `EdDSA` over Ed25519 (the only
/// algorithm of this server, ADR 0001) that is SHA-512, as in other
/// OpenID-certified providers (Ed25519 itself is defined over SHA-512).
#[must_use]
pub fn at_hash(access_token: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha512::digest(access_token.as_bytes());
    let half = digest.get(..32).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(half)
}

#[cfg(test)]
mod tests {
    use super::*;
    use AuthMethodRef::{Face, Hwk, Mfa, Otp, Pwd, Swk, User};

    #[test]
    fn oidp_04_acr_levels_follow_amr() {
        assert_eq!(acr_for(&[Pwd]), ACR_AAL1);
        assert_eq!(acr_for(&[Pwd, Otp, Mfa]), ACR_AAL2);
        assert_eq!(acr_for(&[Hwk, User]), ACR_AAL1);
        assert_eq!(acr_for(&[Swk, Face]), ACR_PHR);
        assert_eq!(acr_for(&[Pwd, Hwk, Mfa]), ACR_PHR);
    }

    #[test]
    fn oidp_04_higher_levels_satisfy_lower_requests() {
        let aal2 = [Pwd, Otp, Mfa];
        assert!(satisfies(&aal2, &[]));
        assert!(satisfies(&aal2, &[ACR_AAL1.to_owned()]));
        assert!(satisfies(&aal2, &[ACR_AAL2.to_owned()]));
        assert!(!satisfies(&aal2, &[ACR_PHR.to_owned()]));
        assert!(satisfies(&aal2, &[ACR_PHR.to_owned(), ACR_AAL2.to_owned()]));
        assert!(!satisfies(&[Pwd], &[ACR_AAL2.to_owned()]));
    }
}
