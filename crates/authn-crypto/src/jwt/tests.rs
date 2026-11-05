#![allow(clippy::string_slice)] // ASCII fixtures

use serde_json::json;
use time::macros::datetime;

use super::*;
use crate::kdf::hmac_sha256;

const NOW: OffsetDateTime = datetime!(2026-05-01 12:00:00 UTC);
const ISS: &str = "https://auth.test.example";
const AUD: &str = "https://api.test.example";

fn signer(kid: &str) -> JwtSigner {
    JwtSigner::new(kid, Ed25519SigningKey::generate().unwrap()).unwrap()
}

fn verifier(signers: &[&JwtSigner]) -> JwtVerifier {
    JwtVerifier::new(signers.iter().map(|s| (s.kid().to_owned(), s.public_key())))
}

fn validation() -> JwtValidation {
    JwtValidation::access_token(ISS, AUD)
}

fn claims() -> Value {
    let now = NOW.unix_timestamp();
    json!({
        "iss": ISS,
        "sub": "user-1",
        "aud": AUD,
        "exp": now + 600,
        "iat": now,
        "nbf": now,
        "jti": "jti-1",
        "scope": "openid"
    })
}

/// Builds a token with arbitrary header/payload JSON and a signature from
/// `key` (or a garbage signature).
fn forge(header: &str, payload: &str, key: Option<&Ed25519SigningKey>) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let signature = key.map_or_else(|| vec![0_u8; 64], |k| k.sign(input.as_bytes()).to_vec());
    format!("{input}.{}", b64url_encode(&signature))
}

#[derive(Debug, Deserialize, PartialEq)]
struct Custom {
    sub: String,
    scope: String,
}

#[test]
fn cry_09_sign_and_verify_round_trip() {
    let s = signer("kid-1");
    let token = s.sign(TYP_ACCESS_TOKEN, &claims()).unwrap();
    let header: Value =
        serde_json::from_slice(&b64url_decode(token.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(
        header,
        json!({"alg": "EdDSA", "typ": "at+jwt", "kid": "kid-1"})
    );

    let verified: VerifiedJwt<Custom> = verifier(&[&s]).verify(&token, &validation(), NOW).unwrap();
    assert_eq!(verified.kid, "kid-1");
    assert_eq!(verified.registered.iss, ISS);
    assert_eq!(verified.registered.aud, vec![AUD.to_owned()]);
    assert_eq!(verified.registered.sub.as_deref(), Some("user-1"));
    assert_eq!(verified.registered.jti.as_deref(), Some("jti-1"));
    assert_eq!(
        verified.claims,
        Custom {
            sub: "user-1".into(),
            scope: "openid".into()
        }
    );
}

#[test]
fn cry_09_alg_none_and_symmetric_algorithms_are_rejected() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let payload = claims().to_string();
    let public = s.public_key().to_bytes();
    for alg in [
        "none", "None", "HS256", "HS384", "HS512", "RS256", "PS256", "ES256", "eddsa", "Ed25519",
        "",
    ] {
        let header = format!(r#"{{"alg":"{alg}","typ":"at+jwt","kid":"kid-1"}}"#);
        // Classic confusion: HMAC keyed with the public key.
        let input = format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(payload.as_bytes())
        );
        let hmac = hmac_sha256(&public, input.as_bytes()).unwrap();
        for token in [
            format!("{input}.{}", b64url_encode(&hmac)),
            format!("{input}."),
            forge(
                &header,
                &payload,
                Some(&Ed25519SigningKey::generate().unwrap()),
            ),
        ] {
            let err = v.verify::<Value>(&token, &validation(), NOW).unwrap_err();
            assert!(
                matches!(err, JwtError::UnsupportedAlgorithm | JwtError::Malformed),
                "{alg}: {err:?}"
            );
        }
    }
    // A missing alg is malformed.
    let token = forge(r#"{"typ":"at+jwt","kid":"kid-1"}"#, &payload, None);
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::Malformed
    );
}

#[test]
fn cry_09_unknown_header_parameters_and_duplicates_are_rejected() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let payload = claims().to_string();
    let key = Ed25519SigningKey::generate().unwrap();
    for header in [
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1","crit":["exp"]}"#,
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1","jku":"https://evil.example/jwks"}"#,
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1","jwk":{"kty":"OKP"}}"#,
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1","x5u":"https://evil.example"}"#,
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1","b64":false}"#,
        r#"{"alg":"EdDSA","alg":"none","typ":"at+jwt","kid":"kid-1"}"#,
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1","kid":"kid-2"}"#,
        r#"["EdDSA"]"#,
        r#"["EdDSA","at+jwt","kid-1"]"#,
        "not json",
    ] {
        let token = forge(header, &payload, Some(&key));
        assert_eq!(
            v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
            JwtError::Malformed,
            "{header}"
        );
    }
}

#[test]
fn cry_09_kid_and_typ_are_enforced() {
    let s1 = signer("kid-1");
    let s2 = signer("kid-2");
    let v = verifier(&[&s1]);
    // Unknown kid (e.g. a revoked key no longer in the set).
    let token = s2.sign(TYP_ACCESS_TOKEN, &claims()).unwrap();
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::UnknownKey
    );
    // A kid that exists but a signature by another key.
    let other = JwtSigner::new("kid-1", Ed25519SigningKey::generate().unwrap()).unwrap();
    let token = other.sign(TYP_ACCESS_TOKEN, &claims()).unwrap();
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::BadSignature
    );
    // Missing kid.
    let token = forge(
        r#"{"alg":"EdDSA","typ":"at+jwt"}"#,
        &claims().to_string(),
        None,
    );
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::UnknownKey
    );
    // typ: wrong, missing, and the accepted media-type form.
    let token = s1.sign("JWT", &claims()).unwrap();
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::WrongType
    );
    let token = forge(
        r#"{"alg":"EdDSA","kid":"kid-1"}"#,
        &claims().to_string(),
        None,
    );
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::WrongType
    );
    let token = s1.sign("application/AT+JWT", &claims()).unwrap();
    assert!(v.verify::<Value>(&token, &validation(), NOW).is_ok());
}

#[test]
fn cry_09_any_modification_breaks_the_signature() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let token = s.sign(TYP_ACCESS_TOKEN, &claims()).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let mut evil = claims();
    evil["sub"] = json!("admin");
    let swapped = format!(
        "{}.{}.{}",
        parts[0],
        b64url_encode(evil.to_string().as_bytes()),
        parts[2]
    );
    assert_eq!(
        v.verify::<Value>(&swapped, &validation(), NOW).unwrap_err(),
        JwtError::BadSignature
    );
    // Flip a character in every position of the signature segment.
    let sig_start = parts[0].len() + parts[1].len() + 2;
    for i in sig_start..token.len() {
        let mut bytes = token.clone().into_bytes();
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(v.verify::<Value>(&tampered, &validation(), NOW).is_err());
    }
}

#[test]
fn cry_09_structural_attacks_are_rejected() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let token = s.sign(TYP_ACCESS_TOKEN, &claims()).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let cases = [
        String::new(),
        "a.b".to_owned(),
        format!("{}.{}", parts[0], parts[1]),
        format!("{token}.extra"),
        format!("{token}.extra.extra"),
        format!("{}..{}", parts[0], parts[2]),
        format!("{}={}", &token[..parts[0].len()], &token[parts[0].len()..]),
        format!("{token}="),
        format!(" {token}"),
        format!("{}+", &token[..token.len() - 1]),
        format!("{}/", &token[..token.len() - 1]),
        format!("{token}é"),
        "a".repeat(MAX_TOKEN_LEN + 1),
        format!("{}.{}.{}", parts[0], parts[1], b64url_encode(&[0; 63])),
    ];
    for case in &cases {
        assert!(
            v.verify::<Value>(case, &validation(), NOW).is_err(),
            "{case}"
        );
    }
}

#[test]
fn cry_09_registered_claims_are_validated() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let now = NOW.unix_timestamp();
    let check = |mutate: &dyn Fn(&mut Value)| {
        let mut c = claims();
        mutate(&mut c);
        let token = s.sign(TYP_ACCESS_TOKEN, &c).unwrap();
        v.verify::<Value>(&token, &validation(), NOW).map(|_| ())
    };
    assert_eq!(check(&|_| {}), Ok(()));
    assert_eq!(
        check(&|c| c["iss"] = json!("https://evil.example")),
        Err(JwtError::WrongIssuer)
    );
    assert_eq!(
        check(&|c| c["aud"] = json!("other")),
        Err(JwtError::WrongAudience)
    );
    assert_eq!(check(&|c| c["aud"] = json!(["other", AUD])), Ok(()));
    assert_eq!(
        check(&|c| c["aud"] = json!([])),
        Err(JwtError::InvalidClaim("aud"))
    );
    assert_eq!(
        check(&|c| c["aud"] = json!([1])),
        Err(JwtError::InvalidClaim("aud"))
    );
    assert_eq!(
        check(&|c| {
            c.as_object_mut().unwrap().remove("aud");
        }),
        Err(JwtError::InvalidClaim("aud"))
    );
    assert_eq!(
        check(&|c| {
            c.as_object_mut().unwrap().remove("iss");
        }),
        Err(JwtError::InvalidClaim("iss"))
    );
    assert_eq!(
        check(&|c| {
            c.as_object_mut().unwrap().remove("exp");
        }),
        Err(JwtError::InvalidClaim("exp"))
    );
    assert_eq!(
        check(&|c| {
            c.as_object_mut().unwrap().remove("iat");
        }),
        Err(JwtError::InvalidClaim("iat"))
    );
    assert_eq!(
        check(&|c| {
            c.as_object_mut().unwrap().remove("nbf");
        }),
        Ok(())
    );
    assert_eq!(
        check(&|c| c["exp"] = json!((now + 600) as f64 + 0.5)),
        Err(JwtError::InvalidClaim("exp"))
    );
    assert_eq!(
        check(&|c| c["exp"] = json!("9999999999")),
        Err(JwtError::InvalidClaim("exp"))
    );
    assert_eq!(
        check(&|c| c["iss"] = json!(1)),
        Err(JwtError::InvalidClaim("iss"))
    );
    // Expiry with the 30 s leeway.
    assert_eq!(
        check(&|c| {
            c["exp"] = json!(now - 29);
            c["iat"] = json!(now - 600);
            c["nbf"] = json!(now - 600);
        }),
        Ok(())
    );
    assert_eq!(
        check(&|c| {
            c["exp"] = json!(now - 30);
            c["iat"] = json!(now - 600);
            c["nbf"] = json!(now - 600);
        }),
        Err(JwtError::Expired)
    );
    // nbf / iat in the future beyond the leeway.
    assert_eq!(check(&|c| c["nbf"] = json!(now + 30)), Ok(()));
    assert_eq!(
        check(&|c| c["nbf"] = json!(now + 31)),
        Err(JwtError::NotYetValid)
    );
    assert_eq!(
        check(&|c| c["iat"] = json!(now + 31)),
        Err(JwtError::InvalidIssuedAt)
    );
    assert_eq!(
        check(&|c| c["iat"] = json!(now + 700)),
        Err(JwtError::InvalidIssuedAt)
    );
}

#[test]
fn cry_09_leeway_and_max_lifetime_are_configurable() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let now = NOW.unix_timestamp();
    let mut c = claims();
    c["exp"] = json!(now - 5);
    c["iat"] = json!(now - 60);
    let token = s.sign(TYP_ACCESS_TOKEN, &c).unwrap();
    assert!(v.verify::<Value>(&token, &validation(), NOW).is_ok());
    assert_eq!(
        v.verify::<Value>(&token, &validation().with_leeway(Duration::ZERO), NOW)
            .unwrap_err(),
        JwtError::Expired
    );
    let long = s.sign(TYP_ACCESS_TOKEN, &claims()).unwrap();
    assert_eq!(
        v.verify::<Value>(
            &long,
            &validation().with_max_lifetime(Duration::from_secs(300)),
            NOW
        )
        .unwrap_err(),
        JwtError::InvalidIssuedAt
    );
}

#[test]
fn cry_09_duplicate_claims_are_rejected() {
    let key = Ed25519SigningKey::generate().unwrap();
    let s = JwtSigner::new("kid-1", key.clone()).unwrap();
    let v = verifier(&[&s]);
    let now = NOW.unix_timestamp();
    let payload = format!(
        r#"{{"iss":"{ISS}","aud":"{AUD}","exp":{},"iat":{now},"sub":"user","sub":"admin"}}"#,
        now + 60
    );
    let token = forge(
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1"}"#,
        &payload,
        Some(&key),
    );
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::Malformed
    );
    // Claims must be an object.
    let token = forge(
        r#"{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1"}"#,
        "[1,2]",
        Some(&key),
    );
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::Malformed
    );
}

#[test]
fn cry_09_signer_input_validation() {
    assert!(JwtSigner::new("", Ed25519SigningKey::generate().unwrap()).is_err());
    assert!(JwtSigner::new("a b", Ed25519SigningKey::generate().unwrap()).is_err());
    assert!(JwtSigner::new("k".repeat(129), Ed25519SigningKey::generate().unwrap()).is_err());
    let s = signer("kid");
    assert_eq!(
        s.sign(TYP_ACCESS_TOKEN, &json!([1])).unwrap_err(),
        JwtError::Signing
    );
    assert_eq!(s.sign("", &claims()).unwrap_err(), JwtError::Signing);
    assert!(!format!("{s:?}").contains("seed"));
    assert_eq!(
        authn_core::AuthError::from(JwtError::Expired).code(),
        authn_core::error::codes::common::UNAUTHENTICATED
    );
}

#[test]
fn ses_09_jwks_contains_only_public_okp_keys() {
    let s1 = signer("kid-1");
    let s2 = signer("kid-2");
    let p1 = s1.public_key();
    let p2 = s2.public_key();
    let set = JwkSet::from_keys([("kid-1", &p1), ("kid-2", &p2)]);
    let json = serde_json::to_value(&set).unwrap();
    assert_eq!(
        json["keys"][0],
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(&p1.to_bytes()),
            "kid": "kid-1",
            "alg": "EdDSA",
            "use": "sig"
        })
    );
    assert_eq!(json["keys"].as_array().unwrap().len(), 2);
    for key in json["keys"].as_array().unwrap() {
        assert!(
            key.get("d").is_none(),
            "private part must never be published"
        );
    }
    let back: JwkSet = serde_json::from_value(json).unwrap();
    assert_eq!(back, set);
}

#[test]
fn cry_09_oversized_header_is_rejected_before_decoding() {
    let key = Ed25519SigningKey::generate().unwrap();
    let s = JwtSigner::new("kid-1", key.clone()).unwrap();
    let v = verifier(&[&s]);
    let padding = "x".repeat(MAX_HEADER_LEN);
    let header = format!(r#"{{"alg":"EdDSA","typ":"at+jwt","kid":"kid-1","p":"{padding}"}}"#);
    let token = forge(&header, &claims().to_string(), Some(&key));
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::Malformed
    );
}

#[test]
fn cry_09_audience_arrays_must_be_non_empty_and_bounded() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let mut c = claims();
    c["aud"] = json!([]);
    let token = s.sign(TYP_ACCESS_TOKEN, &c).unwrap();
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::InvalidClaim("aud")
    );
    let mut many: Vec<String> = (0..MAX_AUDIENCES).map(|i| format!("aud-{i}")).collect();
    many.push(AUD.to_owned());
    c["aud"] = json!(many);
    let token = s.sign(TYP_ACCESS_TOKEN, &c).unwrap();
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::InvalidClaim("aud")
    );
    // Exactly MAX_AUDIENCES entries including ours is accepted.
    many.remove(0);
    c["aud"] = json!(many);
    let token = s.sign(TYP_ACCESS_TOKEN, &c).unwrap();
    assert!(v.verify::<Value>(&token, &validation(), NOW).is_ok());
}

#[test]
fn cry_09_issued_at_in_the_future_or_after_expiry_is_rejected() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let now = NOW.unix_timestamp();
    let mut c = claims();
    // Beyond the 30 s leeway.
    c["iat"] = json!(now + 31);
    c["nbf"] = json!(now);
    let token = s.sign(TYP_ACCESS_TOKEN, &c).unwrap();
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::InvalidIssuedAt
    );
    // Within the leeway but after `exp`.
    c["iat"] = json!(now + 20);
    c["exp"] = json!(now + 10);
    let token = s.sign(TYP_ACCESS_TOKEN, &c).unwrap();
    assert_eq!(
        v.verify::<Value>(&token, &validation(), NOW).unwrap_err(),
        JwtError::InvalidIssuedAt
    );
}

#[test]
fn cry_09_lifetime_within_the_maximum_is_accepted() {
    let s = signer("kid-1");
    let v = verifier(&[&s]);
    let token = s.sign(TYP_ACCESS_TOKEN, &claims()).unwrap();
    // `claims()` lives exactly 600 s: the bound is inclusive.
    assert!(
        v.verify::<Value>(
            &token,
            &validation().with_max_lifetime(Duration::from_secs(600)),
            NOW
        )
        .is_ok()
    );
}

#[test]
fn cry_09_signer_refuses_bad_typ_and_oversized_tokens() {
    let s = signer("kid-1");
    for typ in ["", "at jwt", &"t".repeat(65)] {
        assert_eq!(
            s.sign(typ, &claims()).unwrap_err(),
            JwtError::Signing,
            "{typ:?}"
        );
    }
    let mut c = claims();
    c["big"] = json!("x".repeat(MAX_TOKEN_LEN));
    assert_eq!(s.sign(TYP_ACCESS_TOKEN, &c).unwrap_err(), JwtError::Signing);
    // Signing failures are internal errors, verification failures a
    // uniform `unauthenticated`.
    let signing: authn_core::AuthError = JwtError::Signing.into();
    assert_eq!(
        signing.code(),
        authn_core::error::codes::common::INTERNAL_ERROR
    );
    let rejected: authn_core::AuthError = JwtError::BadSignature.into();
    assert_eq!(
        rejected.code(),
        authn_core::error::codes::common::UNAUTHENTICATED
    );
}
