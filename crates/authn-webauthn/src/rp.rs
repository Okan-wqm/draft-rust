//! Relying-party configuration (PKY-06): the `webauthn-rs` instance built
//! from `[webauthn]`.
//!
//! * `rp_id` is the registrable domain every passkey is scoped to.
//! * Allowed origins are matched **exactly** (no subdomain wildcard, no
//!   port wildcard): web origins of the RP and its subdomains, related
//!   origins (`/.well-known/webauthn`) and Android app origins
//!   (`android:apk-key-hash:<base64url SHA-256 of the signing cert>`, which
//!   Credential Manager reports for native apps). iOS apps use the web
//!   origin of their associated domain (`webcredentials`).
//! * The authenticator timeout sent to clients equals the server-side
//!   ceremony lifetime.

use authn_core::config::ConfigProblems;
use authn_core::config::webauthn::{
    ANDROID_ORIGIN_PREFIX, WebauthnConfig, host_matches_rp_id, web_origin_host,
};
use authn_core::error::AuthError;
use url::Url;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

/// Builds the relying party. Fails (start-up, fail-fast) when the section is
/// invalid or `webauthn-rs` rejects it; the error lists the offending keys.
pub(crate) fn build(config: &WebauthnConfig) -> Result<Webauthn, AuthError> {
    let mut problems = ConfigProblems::default();
    config.validate(&mut problems);
    if !problems.is_empty() {
        return Err(AuthError::internal(format!(
            "invalid [webauthn] configuration: {}",
            problems.problems().join("; ")
        )));
    }
    let origins = parse_origins(config)?;
    let primary = origins
        .iter()
        .find(|origin| {
            origin
                .host_str()
                .is_some_and(|host| host_matches_rp_id(host, &config.rp_id))
        })
        .ok_or_else(|| {
            AuthError::internal("webauthn.allowed_origins has no origin of webauthn.rp_id")
        })?;
    let mut builder = WebauthnBuilder::new(&config.rp_id, primary)
        .map_err(|_| AuthError::internal("webauthn-rs rejected webauthn.rp_id / origin"))?
        .rp_name(&config.rp_name)
        .timeout(config.ceremony_ttl)
        .allow_subdomains(false)
        .allow_any_port(false);
    for origin in origins.iter().filter(|origin| *origin != primary) {
        builder = builder.append_allowed_origin(origin);
    }
    builder
        .build()
        .map_err(|_| AuthError::internal("webauthn-rs rejected the [webauthn] configuration"))
}

/// Parses every allowed origin (web and Android) into the form `webauthn-rs`
/// compares against the client data (`Url` equality).
fn parse_origins(config: &WebauthnConfig) -> Result<Vec<Url>, AuthError> {
    config
        .allowed_origins
        .iter()
        .enumerate()
        .map(|(i, origin)| {
            let valid =
                origin.starts_with(ANDROID_ORIGIN_PREFIX) || web_origin_host(origin).is_some();
            let parsed = Url::parse(origin).ok().filter(|_| valid);
            parsed.ok_or_else(|| {
                AuthError::internal(format!(
                    "webauthn.allowed_origins[{i}] is not a valid origin"
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pky_06_relying_party_accepts_web_and_android_origins() {
        let config = WebauthnConfig {
            rp_id: "example.com".to_owned(),
            allowed_origins: vec![
                "https://app.example.com".to_owned(),
                "https://example.com".to_owned(),
                "android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_owned(),
            ],
            ..WebauthnConfig::default()
        };
        let rp = build(&config).unwrap();
        let allowed: Vec<String> = rp
            .get_allowed_origins()
            .iter()
            .map(Url::to_string)
            .collect();
        assert_eq!(allowed.len(), 3, "{allowed:?}");
        assert!(
            allowed
                .iter()
                .any(|o| o.starts_with("android:apk-key-hash:"))
        );
    }

    #[test]
    fn pky_06_invalid_relying_party_fails_fast_without_echoing_values() {
        let config = WebauthnConfig {
            rp_id: "example.com".to_owned(),
            allowed_origins: vec!["https://evil.test".to_owned()],
            ..WebauthnConfig::default()
        };
        let err = build(&config).unwrap_err();
        let context = err.context().unwrap();
        assert!(context.contains("webauthn.allowed_origins"), "{context}");
        assert!(!context.contains("evil.test"), "{context}");
    }
}
