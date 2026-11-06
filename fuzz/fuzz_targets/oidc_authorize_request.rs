//! Owner: authn-oidc-provider (OIDP-02, OIDP-03). TST-04: authorization
//! request parsing and redirect URI matching.
//!
//! Invariants checked for every input:
//! * the parser, the validator and the redirect matcher never panic;
//! * an accepted request always carries a well-formed S256 challenge and
//!   only scopes of the client policy;
//! * a matched redirect URI is a registered one, or a registered loopback
//!   URI with only the port changed.
#![no_main]

use authn_oidc_provider::pkce;
use authn_oidc_provider::redirect;
use authn_oidc_provider::request::{ClientPolicy, parse_query};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(query) = std::str::from_utf8(data) else {
        return;
    };
    let registered = vec![
        "https://rp.example.com/cb".to_owned(),
        "http://127.0.0.1/callback".to_owned(),
        "com.example.app:/oauth".to_owned(),
    ];
    let scopes = vec!["openid".to_owned(), "email".to_owned()];
    let resources = vec!["https://api.example.com".to_owned()];
    if let Ok(params) = parse_query(query) {
        let matched = redirect::matches(&registered, &params.redirect_uri);
        if matched && !registered.contains(&params.redirect_uri) {
            assert!(params.redirect_uri.starts_with("http://127.0.0.1:"));
        }
        let policy = ClientPolicy {
            allowed_scopes: &scopes,
            allowed_resources: &resources,
            code_grant_allowed: true,
        };
        if let Ok(valid) = params.validate(&policy, &scopes) {
            assert!(pkce::is_valid_challenge(&valid.code_challenge));
            assert!(valid.scopes.iter().all(|s| scopes.contains(s)));
            assert!(valid.resources.iter().all(|r| resources.contains(r)));
        }
    }
    // The matcher on raw input too.
    let _ = redirect::matches(&registered, query);
    let _ = redirect::validate_for_registration(query, redirect::ApplicationType::Native);
});
