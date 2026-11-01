//! Access-token claims (SES-08, RFC 9068).
//!
//! No personal data: the subject is the opaque user id; e-mail address and
//! name are never included.

use authn_core::domain::AuthMethodRef;
use authn_core::id::OrgId;
use serde::{Deserialize, Serialize};

/// `client_id` of tokens issued to the first-party clients of Phase 1
/// (RFC 9068 §2.2 requires the claim; Phase 2 adds registered clients).
pub const FIRST_PARTY_CLIENT_ID: &str = "first-party";

/// The actor of an impersonation token (RFC 8693 §4.1 `act`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorClaim {
    /// The acting platform admin's user id.
    pub sub: String,
}

/// The claim set of an access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Issuer.
    pub iss: String,
    /// Subject: the user id.
    pub sub: String,
    /// Audiences.
    pub aud: Vec<String>,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// Issue time.
    pub iat: i64,
    /// Not before.
    pub nbf: i64,
    /// Token id (UUIDv7).
    pub jti: String,
    /// Session id (the refresh-token family).
    pub sid: String,
    /// Time of the last (re-)authentication.
    pub auth_time: i64,
    /// Authentication methods (RFC 8176).
    pub amr: Vec<AuthMethodRef>,
    /// Authentication context class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Active organization (SES-17).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<OrgId>,
    /// Space-separated scopes.
    pub scope: String,
    /// Client the token was issued to.
    pub client_id: String,
    /// Impersonation: the real actor (ADM-04, RFC 8693).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    /// Impersonation is read-only (`true`) — resource servers must refuse
    /// state changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}
