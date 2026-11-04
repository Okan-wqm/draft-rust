//! ID token verification (SOC-03, SOC-04).
//!
//! The JWS is parsed here and its signature is checked with
//! `openidconnect`'s audited JWK implementation
//! (`CoreJsonWebKey::verify_signature`, public keys only); every claim rule
//! is applied here, explicitly:
//!
//! * **algorithm allow-list:** RS256/384/512, PS256/384/512, ES256, ES384.
//!   `none`, every `HS*` (a provider's public key must never become an HMAC
//!   secret — algorithm confusion) and anything unknown are refused before
//!   a key is even looked up; a JWK that names an algorithm must name the
//!   header's; `crit` headers are refused; `jku` / `x5u` / `jwk` are never
//!   followed (keys come only from the provider's configured JWKS);
//! * **`kid`** is mandatory and resolved in the provider JWKS
//!   ([`crate::jwks`], rate-limited refresh on unknown `kid`);
//! * **`iss`**: exact match ([`IssuerRule::Exact`]) or the Microsoft
//!   tenant rule `https://login.microsoftonline.com/{tid}/v2.0` with the
//!   token's own `tid` (a GUID) admitted by the tenant policy;
//! * **`aud`**: every audience must be an accepted client id (web:
//!   `client_id`; native: the configured native client ids) — a token that
//!   also names an untrusted party is refused; with several audiences `azp`
//!   is mandatory; a present `azp` must be an accepted client id;
//! * **`exp`** (mandatory) must not be past, **`iat`** (mandatory) and
//!   `nbf` must not be in the future — each with `crypto.jwt_leeway`;
//! * **`nonce`** is compared by the caller (hash of the stored nonce,
//!   constant time).
//!
//! Every failure is the generic `oauth_token_invalid`; the reason is only
//! logged.

use std::time::Duration;

use authn_core::error::AuthError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm};
use openidconnect::{JsonWebKey as _, JsonWebKeyAlgorithm};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::codes;
use crate::provider::{IssuerRule, is_guid};

/// Longest accepted ID token (bytes).
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Generic rejection; `reason` is logged, never returned.
pub(crate) fn invalid(reason: &'static str) -> AuthError {
    tracing::info!(reason, "id token rejected");
    AuthError::new(codes::OAUTH_TOKEN_INVALID).with_context(reason)
}

/// The accepted signature algorithms.
fn algorithm(name: &str) -> Option<CoreJwsSigningAlgorithm> {
    Some(match name {
        "RS256" => CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        "RS384" => CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
        "RS512" => CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
        "PS256" => CoreJwsSigningAlgorithm::RsaSsaPssSha256,
        "PS384" => CoreJwsSigningAlgorithm::RsaSsaPssSha384,
        "PS512" => CoreJwsSigningAlgorithm::RsaSsaPssSha512,
        "ES256" => CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        "ES384" => CoreJwsSigningAlgorithm::EcdsaP384Sha384,
        _ => return None,
    })
}

/// A compact JWS whose signature has not been checked yet. Its `Debug`
/// output shows only the header facts (the token is a bearer credential and
/// its claims are personal data).
pub struct UnverifiedToken {
    /// Signature algorithm (from the allow-list).
    pub alg: CoreJwsSigningAlgorithm,
    /// Key id.
    pub kid: String,
    signing_input: String,
    signature: Vec<u8>,
    claims: Map<String, Value>,
}

impl std::fmt::Debug for UnverifiedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnverifiedToken")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

fn decode_json(part: &str) -> Result<Map<String, Value>, AuthError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| invalid("segment is not base64url"))?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(invalid("segment is not a JSON object")),
    }
}

/// Parses a compact JWS and checks its header (algorithm allow-list,
/// `kid`, no `crit`). The signature is checked by [`UnverifiedToken::verify`].
pub fn parse(token: &str) -> Result<UnverifiedToken, AuthError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
        return Err(invalid("token size or charset"));
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("not a compact JWS"));
    };
    let header_map = decode_json(header)?;
    let alg_name = header_map
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing alg"))?;
    if alg_name.eq_ignore_ascii_case("none") || alg_name.to_ascii_uppercase().starts_with("HS") {
        return Err(invalid("forbidden alg (none / HMAC)"));
    }
    let alg = algorithm(alg_name).ok_or_else(|| invalid("unsupported alg"))?;
    if header_map.contains_key("crit") {
        return Err(invalid("crit header"));
    }
    if let Some(typ) = header_map.get("typ") {
        let ok = typ.as_str().is_some_and(|t| t.eq_ignore_ascii_case("JWT"));
        if !ok {
            return Err(invalid("unexpected typ"));
        }
    }
    let kid = header_map
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty() && k.len() <= 256)
        .ok_or_else(|| invalid("missing kid"))?
        .to_owned();
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| invalid("signature is not base64url"))?;
    if signature.is_empty() {
        return Err(invalid("empty signature"));
    }
    let claims = decode_json(payload)?;
    Ok(UnverifiedToken {
        alg,
        kid,
        signing_input: format!("{header}.{payload}"),
        signature,
        claims,
    })
}

impl UnverifiedToken {
    /// The unverified `nonce` claim (used to find the native nonce row
    /// *after* verification; never trusted before).
    #[must_use]
    pub fn nonce_unverified(&self) -> Option<&str> {
        self.claims.get("nonce").and_then(Value::as_str)
    }

    /// Checks the signature with `key` and returns the claims.
    pub fn verify(self, key: &CoreJsonWebKey) -> Result<Map<String, Value>, AuthError> {
        match key.signing_alg() {
            JsonWebKeyAlgorithm::Unspecified => {}
            JsonWebKeyAlgorithm::Algorithm(a) if *a == self.alg => {}
            _ => return Err(invalid("JWK algorithm does not match the header")),
        }
        key.verify_signature(&self.alg, self.signing_input.as_bytes(), &self.signature)
            .map_err(|_| invalid("bad signature"))?;
        Ok(self.claims)
    }
}

/// What the claims must satisfy.
#[derive(Debug, Clone)]
pub struct Expectations<'a> {
    /// Issuer rule of the provider.
    pub issuer: &'a IssuerRule,
    /// Accepted `aud` / `azp` values.
    pub audiences: &'a [String],
    /// Current time.
    pub now: OffsetDateTime,
    /// Clock-skew tolerance.
    pub leeway: Duration,
}

/// The validated claims this system uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdClaims {
    /// `iss`.
    pub issuer: String,
    /// `sub`.
    pub subject: String,
    /// `nonce`.
    pub nonce: Option<String>,
    /// `email`.
    pub email: Option<String>,
    /// `email_verified` (boolean or `"true"`).
    pub email_verified: bool,
    /// `name`.
    pub name: Option<String>,
    /// Microsoft `tid`.
    pub tenant_id: Option<String>,
    /// Microsoft `oid`.
    pub object_id: Option<String>,
    /// Microsoft optional claim `xms_edov` (e-mail domain owner verified).
    pub email_domain_verified: bool,
    /// Apple `is_private_email`.
    pub is_private_email: bool,
    /// `amr`.
    pub amr: Vec<String>,
}

fn string_claim(claims: &Map<String, Value>, name: &str) -> Option<String> {
    claims.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn bool_claim(claims: &Map<String, Value>, name: &str) -> bool {
    match claims.get(name) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

fn time_claim(claims: &Map<String, Value>, name: &str) -> Option<i64> {
    let value = claims.get(name)?;
    if let Some(i) = value.as_i64() {
        return Some(i);
    }
    let f = value.as_f64()?;
    if f.is_finite() && f.abs() < 1e15 {
        #[allow(clippy::cast_possible_truncation)]
        Some(f.floor() as i64)
    } else {
        None
    }
}

fn leeway_secs(leeway: Duration) -> i64 {
    i64::try_from(leeway.as_secs()).unwrap_or(i64::MAX)
}

fn check_issuer(
    rule: &IssuerRule,
    iss: &str,
    claims: &Map<String, Value>,
) -> Result<(), AuthError> {
    match rule {
        IssuerRule::Exact(accepted) => {
            if accepted.iter().any(|a| a == iss) {
                Ok(())
            } else {
                Err(invalid("issuer mismatch"))
            }
        }
        IssuerRule::MicrosoftTenant {
            prefix,
            suffix,
            policy,
        } => {
            let tid = claims
                .get("tid")
                .and_then(Value::as_str)
                .filter(|t| is_guid(t))
                .ok_or_else(|| invalid("missing or malformed tid"))?;
            if iss != format!("{prefix}{tid}{suffix}") {
                return Err(invalid("issuer does not match the token tenant"));
            }
            if !policy.admits(tid) {
                return Err(invalid("tenant not admitted"));
            }
            Ok(())
        }
    }
}

/// Validates the claims of a signature-verified token.
pub fn validate(
    claims: &Map<String, Value>,
    expect: &Expectations<'_>,
) -> Result<IdClaims, AuthError> {
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing iss"))?;
    check_issuer(expect.issuer, iss, claims)?;

    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(list)) => {
            let names: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
            if names.len() != list.len() {
                return Err(invalid("malformed aud"));
            }
            names
        }
        _ => return Err(invalid("missing aud")),
    };
    if audiences.is_empty() {
        return Err(invalid("empty aud"));
    }
    let accepted = |v: &str| expect.audiences.iter().any(|a| a == v);
    // OIDC Core 3.1.3.7 rule 3: every audience must be one of ours — a token
    // also issued to a party we do not trust is refused.
    if !audiences.iter().all(|a| accepted(a)) {
        return Err(invalid("audience mismatch"));
    }
    match claims.get("azp") {
        Some(Value::String(azp)) => {
            if !accepted(azp) {
                return Err(invalid("azp mismatch"));
            }
        }
        Some(_) => return Err(invalid("malformed azp")),
        None if audiences.len() > 1 => return Err(invalid("azp required with several audiences")),
        None => {}
    }

    let now = expect.now.unix_timestamp();
    let leeway = leeway_secs(expect.leeway);
    let exp = time_claim(claims, "exp").ok_or_else(|| invalid("missing exp"))?;
    if now >= exp.saturating_add(leeway) {
        return Err(invalid("expired"));
    }
    let iat = time_claim(claims, "iat").ok_or_else(|| invalid("missing iat"))?;
    if iat > now.saturating_add(leeway) {
        return Err(invalid("issued in the future"));
    }
    if let Some(nbf) = time_claim(claims, "nbf")
        && nbf > now.saturating_add(leeway)
    {
        return Err(invalid("not yet valid"));
    }

    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.chars().count() <= 255 && !s.chars().any(char::is_control))
        .ok_or_else(|| invalid("missing or malformed sub"))?
        .to_owned();
    let nonce = match claims.get("nonce") {
        None => None,
        Some(Value::String(n)) => Some(n.clone()),
        Some(_) => return Err(invalid("malformed nonce")),
    };
    let amr = claims
        .get("amr")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .take(16)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(IdClaims {
        issuer: iss.to_owned(),
        subject,
        nonce,
        email: string_claim(claims, "email"),
        email_verified: bool_claim(claims, "email_verified"),
        name: string_claim(claims, "name"),
        tenant_id: string_claim(claims, "tid"),
        object_id: string_claim(claims, "oid"),
        email_domain_verified: bool_claim(claims, "xms_edov"),
        is_private_email: bool_claim(claims, "is_private_email"),
        amr,
    })
}

#[cfg(test)]
mod tests {
    use openidconnect::JsonWebKeyId;
    use openidconnect::PrivateSigningKey as _;
    use openidconnect::core::CoreRsaPrivateSigningKey;
    use serde_json::json;

    use super::*;
    use crate::provider::TenantPolicy;

    const KEY_A: &str = include_str!("../tests/fixtures/test_rsa_a.pem");
    const KEY_B: &str = include_str!("../tests/fixtures/test_rsa_b.pem");
    const NOW: i64 = 1_800_000_000;

    fn b64(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    fn sign(pem: &str, kid: &str, header: &Value, claims: &Value) -> String {
        let key = CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(kid.to_owned())))
            .unwrap();
        let input = format!("{}.{}", b64(header), b64(claims));
        let sig = key
            .sign(
                &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                input.as_bytes(),
            )
            .unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn public(pem: &str, kid: &str) -> CoreJsonWebKey {
        CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(kid.to_owned())))
            .unwrap()
            .as_verification_key()
    }

    fn claims() -> Value {
        json!({
            "iss": "https://issuer.example",
            "sub": "subject-1",
            "aud": "client-1",
            "exp": NOW + 300,
            "iat": NOW - 10,
            "nonce": "n-1",
            "email": "a@example.com",
            "email_verified": true,
        })
    }

    fn exact() -> IssuerRule {
        IssuerRule::Exact(vec!["https://issuer.example".to_owned()])
    }

    fn check(c: &Value, issuer: &IssuerRule, audiences: &[String]) -> Result<IdClaims, AuthError> {
        let map = c.as_object().unwrap().clone();
        validate(
            &map,
            &Expectations {
                issuer,
                audiences,
                now: OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
                leeway: Duration::from_secs(60),
            },
        )
    }

    fn client() -> Vec<String> {
        vec!["client-1".to_owned()]
    }

    fn rejected(r: Result<IdClaims, AuthError>) {
        let err = r.unwrap_err();
        assert!(err.is(codes::OAUTH_TOKEN_INVALID), "{err:?}");
    }

    #[test]
    fn soc_03_valid_token_round_trip() {
        let token = sign(
            KEY_A,
            "key-a",
            &json!({"alg":"RS256","kid":"key-a","typ":"JWT"}),
            &claims(),
        );
        let parsed = parse(&token).unwrap();
        assert_eq!(parsed.kid, "key-a");
        let verified = parsed.verify(&public(KEY_A, "key-a")).unwrap();
        let c = check(&Value::Object(verified), &exact(), &client()).unwrap();
        assert_eq!(c.subject, "subject-1");
        assert!(c.email_verified);
        assert_eq!(c.nonce.as_deref(), Some("n-1"));
    }

    #[test]
    fn soc_03_signature_with_another_key_is_rejected() {
        let token = sign(
            KEY_B,
            "key-a",
            &json!({"alg":"RS256","kid":"key-a"}),
            &claims(),
        );
        let err = parse(&token)
            .unwrap()
            .verify(&public(KEY_A, "key-a"))
            .unwrap_err();
        assert!(err.is(codes::OAUTH_TOKEN_INVALID));
    }

    #[test]
    fn soc_03_tampered_payload_is_rejected() {
        let token = sign(
            KEY_A,
            "key-a",
            &json!({"alg":"RS256","kid":"key-a"}),
            &claims(),
        );
        let parts: Vec<&str> = token.split('.').collect();
        let mut evil = claims();
        evil["sub"] = json!("admin");
        let forged = format!("{}.{}.{}", parts[0], b64(&evil), parts[2]);
        assert!(
            parse(&forged)
                .unwrap()
                .verify(&public(KEY_A, "key-a"))
                .is_err()
        );
    }

    #[test]
    fn soc_03_alg_none_and_hmac_are_rejected_before_key_lookup() {
        for alg in [
            "none", "None", "HS256", "HS384", "HS512", "hs256", "XS256", "",
        ] {
            let header = json!({ "alg": alg, "kid": "key-a" });
            let token = format!("{}.{}.{}", b64(&header), b64(&claims()), "c2ln");
            let err = parse(&token).unwrap_err();
            assert!(err.is(codes::OAUTH_TOKEN_INVALID), "{alg}");
        }
        // Unsigned token with an empty signature.
        let token = format!(
            "{}.{}.",
            b64(&json!({"alg":"RS256","kid":"key-a"})),
            b64(&claims())
        );
        assert!(parse(&token).is_err());
    }

    #[test]
    fn soc_03_alg_confusion_jwk_algorithm_must_match_header() {
        // A key published for ES256 must not verify an RS256 signature.
        let mut jwk = serde_json::to_value(public(KEY_A, "key-a")).unwrap();
        jwk["alg"] = json!("PS256");
        let key: CoreJsonWebKey = serde_json::from_value(jwk).unwrap();
        let token = sign(
            KEY_A,
            "key-a",
            &json!({"alg":"RS256","kid":"key-a"}),
            &claims(),
        );
        assert!(parse(&token).unwrap().verify(&key).is_err());
        // An RSA key cannot verify an ES256 header.
        let header = json!({"alg":"ES256","kid":"key-a"});
        let token = format!("{}.{}.{}", b64(&header), b64(&claims()), "c2lnbmF0dXJl");
        assert!(
            parse(&token)
                .unwrap()
                .verify(&public(KEY_A, "key-a"))
                .is_err()
        );
    }

    #[test]
    fn soc_03_header_rules() {
        let no_kid = format!("{}.{}.c2ln", b64(&json!({"alg":"RS256"})), b64(&claims()));
        assert!(parse(&no_kid).is_err());
        let crit = format!(
            "{}.{}.c2ln",
            b64(&json!({"alg":"RS256","kid":"k","crit":["exp"]})),
            b64(&claims())
        );
        assert!(parse(&crit).is_err());
        let typ = format!(
            "{}.{}.c2ln",
            b64(&json!({"alg":"RS256","kid":"k","typ":"at+jwt"})),
            b64(&claims())
        );
        assert!(parse(&typ).is_err());
        assert!(parse("a.b").is_err());
        assert!(parse("a.b.c.d").is_err());
        assert!(parse(&"a".repeat(MAX_TOKEN_BYTES + 1)).is_err());
    }

    #[test]
    fn soc_03_wrong_issuer_is_rejected() {
        let mut c = claims();
        c["iss"] = json!("https://issuer.example/");
        rejected(check(&c, &exact(), &client()));
        c["iss"] = json!("https://evil.example");
        rejected(check(&c, &exact(), &client()));
    }

    #[test]
    fn soc_03_wrong_audience_is_rejected() {
        let mut c = claims();
        c["aud"] = json!("someone-else");
        rejected(check(&c, &exact(), &client()));
        c["aud"] = json!([]);
        rejected(check(&c, &exact(), &client()));
    }

    #[test]
    fn soc_03_azp_rules() {
        let mut c = claims();
        c["aud"] = json!(["client-1", "other"]);
        rejected(check(&c, &exact(), &client()));
        c["azp"] = json!("other");
        rejected(check(&c, &exact(), &client()));
        // Review finding 2: `azp` is ours, but `aud` also names a party we do
        // not trust (OIDC Core 3.1.3.7 rule 3) — refused.
        c["azp"] = json!("client-1");
        rejected(check(&c, &exact(), &client()));
        let two = vec!["client-1".to_owned(), "client-2".to_owned()];
        c["aud"] = json!(["client-1", "client-2"]);
        check(&c, &exact(), &two).unwrap();
        let mut single = claims();
        single["azp"] = json!("attacker-app");
        rejected(check(&single, &exact(), &client()));
    }

    #[test]
    fn soc_03_expired_and_future_tokens_are_rejected() {
        let mut c = claims();
        c["exp"] = json!(NOW - 61);
        rejected(check(&c, &exact(), &client()));
        c["exp"] = json!(NOW - 30); // within leeway
        check(&c, &exact(), &client()).unwrap();
        let mut f = claims();
        f["iat"] = json!(NOW + 120);
        rejected(check(&f, &exact(), &client()));
        let mut n = claims();
        n["nbf"] = json!(NOW + 120);
        rejected(check(&n, &exact(), &client()));
        let mut missing = claims();
        missing.as_object_mut().unwrap().remove("iat");
        rejected(check(&missing, &exact(), &client()));
        let mut missing = claims();
        missing.as_object_mut().unwrap().remove("exp");
        rejected(check(&missing, &exact(), &client()));
    }

    #[test]
    fn soc_03_microsoft_tenant_spoofing_is_rejected() {
        let rule = IssuerRule::MicrosoftTenant {
            prefix: "https://login.microsoftonline.com/".to_owned(),
            suffix: "/v2.0".to_owned(),
            policy: TenantPolicy {
                configured: "common".to_owned(),
                allowed: vec!["11111111-1111-1111-1111-111111111111".to_owned()],
            },
        };
        let good = "11111111-1111-1111-1111-111111111111";
        let evil = "22222222-2222-2222-2222-222222222222";
        let mut c = claims();
        c["tid"] = json!(good);
        c["iss"] = json!(format!("https://login.microsoftonline.com/{good}/v2.0"));
        check(&c, &rule, &client()).unwrap();
        // Issuer of the allowed tenant, token of another tenant.
        c["tid"] = json!(evil);
        rejected(check(&c, &rule, &client()));
        // A consistent token of a tenant that is not on the allow-list.
        c["iss"] = json!(format!("https://login.microsoftonline.com/{evil}/v2.0"));
        rejected(check(&c, &rule, &client()));
        // `tid` that is not a GUID cannot splice the issuer.
        c["tid"] = json!("x/v2.0#");
        c["iss"] = json!("https://login.microsoftonline.com/x/v2.0#/v2.0");
        rejected(check(&c, &rule, &client()));
        // The literal `{tenantid}` template issuer is never accepted.
        c["tid"] = json!(good);
        c["iss"] = json!("https://login.microsoftonline.com/{tenantid}/v2.0");
        rejected(check(&c, &rule, &client()));
    }

    #[test]
    fn soc_03_untrusted_extra_audiences_are_rejected() {
        let mut c = claims();
        c["aud"] = json!(["client-1", "attacker-client"]);
        c["azp"] = json!("client-1");
        rejected(check(&c, &exact(), &client()));
        c["aud"] = json!(["client-1", 7]);
        rejected(check(&c, &exact(), &client()));
    }

    #[test]
    fn soc_03_unverified_token_debug_redacts_the_token() {
        let token = sign(
            KEY_A,
            "key-a",
            &json!({"alg":"RS256","kid":"key-a"}),
            &claims(),
        );
        let parsed = parse(&token).unwrap();
        let debug = format!("{parsed:?}");
        let payload = token.split('.').nth(1).unwrap();
        assert!(!debug.contains(payload), "{debug}");
        assert!(!debug.contains("a@example.com"), "{debug}");
        assert!(!debug.contains("signature: ["), "{debug}");
    }

    #[test]
    fn soc_03_claim_type_tolerance() {
        let mut c = claims();
        c["email_verified"] = json!("true");
        c["exp"] = json!((NOW + 300) as f64 + 0.5);
        assert!(check(&c, &exact(), &client()).unwrap().email_verified);
        c["email_verified"] = json!("false");
        assert!(!check(&c, &exact(), &client()).unwrap().email_verified);
        c["nonce"] = json!(5);
        rejected(check(&c, &exact(), &client()));
    }
}
