//! Fixed-algorithm EdDSA (Ed25519) compact JWS / JWT (CRY-09).
//!
//! Hand-written on top of `ed25519-dalek` instead of a general JOSE library
//! (ADR 0001): there is exactly one algorithm, so algorithm confusion is
//! impossible by construction.
//!
//! Verification order (each step fails closed, nothing of the payload is
//! interpreted before the signature is checked):
//!
//! 1. Size (≤ [`MAX_TOKEN_LEN`]), ASCII, exactly three non-empty segments
//!    (JWE / unsecured JWS shapes are rejected).
//! 2. Strict base64url (no padding, canonical bits) header; JSON object with
//!    **only** `alg`, `typ`, `kid` (unknown parameters such as `crit`,
//!    `jku`, `jwk`, `x5u`, `x5c`, `b64` and duplicate names are rejected).
//! 3. `alg` must be exactly `EdDSA` — the header is checked against the
//!    pinned algorithm, never used to select one (`none`, `HS*`, `RS*`,
//!    `ES*`, case variants… all fail).
//! 4. `typ` must equal the expected type (`at+jwt`, RFC 9068; the
//!    `application/` prefix is accepted per RFC 7515 §4.1.9).
//! 5. `kid` must name a key of the verifier's key set.
//! 6. 64-byte signature, `verify_strict` over the received signing input.
//! 7. Payload: strict base64url, JSON object without duplicate member
//!    names; `iss` (exact), `aud` (string or array containing the expected
//!    audience), `exp`, `iat` (required integers), `nbf` (optional integer)
//!    with a configurable leeway (default 30 s), `iat <= exp`, optional
//!    maximum lifetime.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::CryptoError;
use crate::encoding::{b64url_decode, b64url_encode, is_b64url_alphabet};
use crate::signing::{Ed25519PublicKey, Ed25519SigningKey};

/// The only accepted `alg`.
pub const ALG: &str = "EdDSA";
/// `typ` of OAuth 2.0 access tokens (RFC 9068).
pub const TYP_ACCESS_TOKEN: &str = "at+jwt";
/// Maximum accepted token length.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
/// Maximum `kid` length.
pub const MAX_KID_LEN: usize = 128;
const MAX_HEADER_LEN: usize = 512;
const MAX_AUDIENCES: usize = 16;

/// Why a token was rejected. Logged for diagnostics; clients always get a
/// uniform `unauthenticated` (see the `AuthError` conversion).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwtError {
    /// Not a well-formed compact JWS.
    #[error("malformed token")]
    Malformed,
    /// `alg` is not `EdDSA`.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    /// `typ` is not the expected type.
    #[error("unexpected token type")]
    WrongType,
    /// `kid` is missing or unknown.
    #[error("unknown key id")]
    UnknownKey,
    /// The signature does not verify.
    #[error("invalid signature")]
    BadSignature,
    /// A required claim is missing or has the wrong JSON type.
    #[error("missing or invalid claim `{0}`")]
    InvalidClaim(&'static str),
    /// `iss` mismatch.
    #[error("wrong issuer")]
    WrongIssuer,
    /// `aud` does not contain the expected audience.
    #[error("wrong audience")]
    WrongAudience,
    /// `exp` has passed.
    #[error("token expired")]
    Expired,
    /// `nbf` is in the future.
    #[error("token not yet valid")]
    NotYetValid,
    /// `iat` is in the future or after `exp`, or the lifetime is too long.
    #[error("invalid issue time")]
    InvalidIssuedAt,
    /// Signing failed (invalid kid, claims not a JSON object…).
    #[error("token signing failed")]
    Signing,
}

impl From<JwtError> for authn_core::AuthError {
    fn from(err: JwtError) -> Self {
        let code = if err == JwtError::Signing {
            authn_core::error::codes::common::INTERNAL_ERROR
        } else {
            authn_core::error::codes::common::UNAUTHENTICATED
        };
        Self::new(code).with_source(err)
    }
}

#[derive(Serialize)]
struct HeaderOut<'a> {
    alg: &'static str,
    typ: &'a str,
    kid: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderIn {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty() && kid.len() <= MAX_KID_LEN && kid.bytes().all(|b| b.is_ascii_graphic())
}

/// Signs JWTs with one Ed25519 key.
#[derive(Clone)]
pub struct JwtSigner {
    kid: String,
    key: Ed25519SigningKey,
}

impl fmt::Debug for JwtSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtSigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl JwtSigner {
    /// A signer; `kid` must be 1..=128 printable ASCII characters.
    pub fn new(kid: impl Into<String>, key: Ed25519SigningKey) -> Result<Self, CryptoError> {
        let kid = kid.into();
        if !valid_kid(&kid) {
            return Err(CryptoError::Malformed);
        }
        Ok(Self { kid, key })
    }

    /// Key id written into every header.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Public key of the signer.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.key.public_key()
    }

    /// Signs `claims` (must serialize to a JSON object) with header
    /// `{"alg":"EdDSA","typ":typ,"kid":kid}`.
    pub fn sign<C: Serialize>(&self, typ: &str, claims: &C) -> Result<String, JwtError> {
        if typ.is_empty() || typ.len() > 64 || !typ.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(JwtError::Signing);
        }
        let payload = serde_json::to_value(claims).map_err(|_| JwtError::Signing)?;
        if !payload.is_object() {
            return Err(JwtError::Signing);
        }
        let header = serde_json::to_vec(&HeaderOut {
            alg: ALG,
            typ,
            kid: &self.kid,
        })
        .map_err(|_| JwtError::Signing)?;
        let payload = serde_json::to_vec(&payload).map_err(|_| JwtError::Signing)?;
        let mut token = b64url_encode(&header);
        token.push('.');
        token.push_str(&b64url_encode(&payload));
        let signature = self.key.sign(token.as_bytes());
        token.push('.');
        token.push_str(&b64url_encode(&signature));
        if token.len() > MAX_TOKEN_LEN {
            return Err(JwtError::Signing);
        }
        Ok(token)
    }
}

/// What a verifier expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtValidation {
    /// Exact `iss`.
    pub issuer: String,
    /// Audience that `aud` must contain.
    pub audience: String,
    /// Expected `typ` (default [`TYP_ACCESS_TOKEN`]).
    pub typ: String,
    /// Clock-skew tolerance (CRY-09 default 30 s, `crypto.jwt_leeway`).
    pub leeway: Duration,
    /// Optional upper bound on `exp - iat`.
    pub max_lifetime: Option<Duration>,
}

impl JwtValidation {
    /// Access-token validation for `issuer` / `audience` with a 30 s leeway.
    #[must_use]
    pub fn access_token(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            typ: TYP_ACCESS_TOKEN.to_owned(),
            leeway: Duration::from_secs(30),
            max_lifetime: None,
        }
    }

    /// Replaces the leeway.
    #[must_use]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Sets a maximum lifetime.
    #[must_use]
    pub fn with_max_lifetime(mut self, max: Duration) -> Self {
        self.max_lifetime = Some(max);
        self
    }

    fn typ_matches(&self, typ: &str) -> bool {
        let typ = typ.to_ascii_lowercase();
        let expected = self.typ.to_ascii_lowercase();
        typ == expected || typ.strip_prefix("application/") == Some(expected.as_str())
    }
}

/// Registered claims extracted during validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredClaims {
    /// `iss`.
    pub iss: String,
    /// `sub`, if present.
    pub sub: Option<String>,
    /// `aud` (normalized to a list).
    pub aud: Vec<String>,
    /// `exp` (Unix seconds).
    pub exp: i64,
    /// `nbf`, if present.
    pub nbf: Option<i64>,
    /// `iat`.
    pub iat: i64,
    /// `jti`, if present.
    pub jti: Option<String>,
}

/// A verified token.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedJwt<C> {
    /// Key that signed the token.
    pub kid: String,
    /// The validated registered claims.
    pub registered: RegisteredClaims,
    /// The full claim set deserialized into the caller's type.
    pub claims: C,
}

/// Verifies JWTs against a set of trusted public keys (by `kid`).
#[derive(Clone, Default)]
pub struct JwtVerifier {
    keys: HashMap<String, Ed25519PublicKey>,
}

impl fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut kids: Vec<&String> = self.keys.keys().collect();
        kids.sort();
        f.debug_struct("JwtVerifier").field("kids", &kids).finish()
    }
}

impl JwtVerifier {
    /// A verifier trusting exactly `keys`.
    pub fn new(keys: impl IntoIterator<Item = (String, Ed25519PublicKey)>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    /// Whether `kid` is trusted.
    #[must_use]
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.contains_key(kid)
    }

    /// Verifies `token` and deserializes its claims into `C`.
    pub fn verify<C: DeserializeOwned>(
        &self,
        token: &str,
        validation: &JwtValidation,
        now: OffsetDateTime,
    ) -> Result<VerifiedJwt<C>, JwtError> {
        let (kid, claims) = self.verify_signature(token, validation)?;
        let registered = validate_claims(&claims, validation, now)?;
        let claims = serde_json::from_value(Value::Object(claims))
            .map_err(|_| JwtError::InvalidClaim("claims"))?;
        Ok(VerifiedJwt {
            kid,
            registered,
            claims,
        })
    }

    /// Steps 1–6 plus payload decoding: returns the `kid` and the claim
    /// object of a token whose signature is valid.
    fn verify_signature(
        &self,
        token: &str,
        validation: &JwtValidation,
    ) -> Result<(String, Map<String, Value>), JwtError> {
        if token.len() > MAX_TOKEN_LEN || !token.is_ascii() {
            return Err(JwtError::Malformed);
        }
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwtError::Malformed);
        };
        for part in [header_b64, payload_b64, signature_b64] {
            if part.is_empty() || !is_b64url_alphabet(part) {
                return Err(JwtError::Malformed);
            }
        }
        if header_b64.len() > MAX_HEADER_LEN {
            return Err(JwtError::Malformed);
        }
        let header_json = b64url_decode(header_b64).map_err(|_| JwtError::Malformed)?;
        // Two steps on purpose: `StrictObject` guarantees a JSON *object*
        // without duplicate names (serde's derive would also accept a JSON
        // array such as `["EdDSA"]`), then the typed view rejects unknown
        // parameters.
        let StrictObject(header) =
            serde_json::from_slice(&header_json).map_err(|_| JwtError::Malformed)?;
        let header: HeaderIn =
            serde_json::from_value(Value::Object(header)).map_err(|_| JwtError::Malformed)?;
        if header.alg != ALG {
            return Err(JwtError::UnsupportedAlgorithm);
        }
        match &header.typ {
            Some(typ) if validation.typ_matches(typ) => {}
            _ => return Err(JwtError::WrongType),
        }
        let kid = header.kid.ok_or(JwtError::UnknownKey)?;
        let key = self.keys.get(&kid).ok_or(JwtError::UnknownKey)?;

        let signature = b64url_decode(signature_b64).map_err(|_| JwtError::Malformed)?;
        if signature.len() != 64 {
            return Err(JwtError::Malformed);
        }
        // The signing input is the received ASCII, byte for byte.
        let signing_input_len = header_b64.len() + 1 + payload_b64.len();
        let signing_input = token
            .as_bytes()
            .get(..signing_input_len)
            .ok_or(JwtError::Malformed)?;
        if !key.verify(signing_input, &signature) {
            return Err(JwtError::BadSignature);
        }

        let payload = b64url_decode(payload_b64).map_err(|_| JwtError::Malformed)?;
        let StrictObject(claims) =
            serde_json::from_slice(&payload).map_err(|_| JwtError::Malformed)?;
        Ok((kid, claims))
    }
}

fn int_claim(claims: &Map<String, Value>, name: &'static str) -> Result<Option<i64>, JwtError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or(JwtError::InvalidClaim(name)),
    }
}

fn string_claim(
    claims: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<String>, JwtError> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(JwtError::InvalidClaim(name)),
    }
}

fn validate_claims(
    claims: &Map<String, Value>,
    validation: &JwtValidation,
    now: OffsetDateTime,
) -> Result<RegisteredClaims, JwtError> {
    let leeway = i64::try_from(validation.leeway.as_secs()).unwrap_or(i64::MAX);
    let now = now.unix_timestamp();

    let iss = string_claim(claims, "iss")?.ok_or(JwtError::InvalidClaim("iss"))?;
    if iss != validation.issuer {
        return Err(JwtError::WrongIssuer);
    }

    let aud = match claims.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_AUDIENCES => items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or(JwtError::InvalidClaim("aud"))?,
        _ => return Err(JwtError::InvalidClaim("aud")),
    };
    if !aud.contains(&validation.audience) {
        return Err(JwtError::WrongAudience);
    }

    let exp = int_claim(claims, "exp")?.ok_or(JwtError::InvalidClaim("exp"))?;
    let iat = int_claim(claims, "iat")?.ok_or(JwtError::InvalidClaim("iat"))?;
    let nbf = int_claim(claims, "nbf")?;

    if now >= exp.saturating_add(leeway) {
        return Err(JwtError::Expired);
    }
    if let Some(nbf) = nbf
        && nbf > now.saturating_add(leeway)
    {
        return Err(JwtError::NotYetValid);
    }
    if iat > now.saturating_add(leeway) || iat > exp {
        return Err(JwtError::InvalidIssuedAt);
    }
    if let Some(max) = validation.max_lifetime {
        let max = i64::try_from(max.as_secs()).unwrap_or(i64::MAX);
        if exp.saturating_sub(iat) > max {
            return Err(JwtError::InvalidIssuedAt);
        }
    }

    Ok(RegisteredClaims {
        iss,
        sub: string_claim(claims, "sub")?,
        aud,
        exp,
        nbf,
        iat,
        jti: string_claim(claims, "jti")?,
    })
}

/// A JSON object whose top-level member names are unique (RFC 7519 §4:
/// duplicate claim names must be rejected or the last one used; we reject).
struct StrictObject(Map<String, Value>);

impl<'de> Deserialize<'de> for StrictObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictObject;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object with unique member names")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = Map::new();
                while let Some((key, value)) = access.next_entry::<String, Value>()? {
                    if map.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate member name"));
                    }
                    map.insert(key, value);
                }
                Ok(StrictObject(map))
            }
        }

        deserializer.deserialize_map(StrictVisitor)
    }
}

/// One public key in a JWKS (RFC 8037 OKP / Ed25519).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// `OKP`.
    pub kty: String,
    /// `Ed25519`.
    pub crv: String,
    /// Base64url public key.
    pub x: String,
    /// Key id.
    pub kid: String,
    /// `EdDSA`.
    pub alg: String,
    /// `sig`.
    #[serde(rename = "use")]
    pub use_: String,
}

impl Jwk {
    /// The JWK of an Ed25519 public key.
    #[must_use]
    pub fn ed25519(kid: &str, key: &Ed25519PublicKey) -> Self {
        Self {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: b64url_encode(&key.to_bytes()),
            kid: kid.to_owned(),
            alg: ALG.to_owned(),
            use_: "sig".to_owned(),
        }
    }
}

/// A JSON Web Key Set (`/.well-known/jwks.json`, SES-09): public keys only.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct JwkSet {
    /// The keys.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Builds the set from `(kid, public key)` pairs.
    pub fn from_keys<'a>(keys: impl IntoIterator<Item = (&'a str, &'a Ed25519PublicKey)>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .map(|(kid, key)| Jwk::ed25519(kid, key))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
