//! Error codes of authn-oidc-client (SOC-*).
//!
//! The codes live in the global registry,
//! [`authn_core::error::codes::oidc_client`] (owned by this crate), so they
//! appear in `authn_core::error::codes::all()` and the DOC-04 catalogue.
//! This module re-exports them so that the crate's call sites read
//! `codes::OAUTH_STATE_INVALID`.

pub use authn_core::error::codes::oidc_client::*;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use authn_core::domain::Locale;

    use super::*;

    #[test]
    fn soc_01_codes_are_unique_snake_case_and_in_the_global_registry() {
        let mut seen = HashSet::new();
        assert_eq!(ALL.len(), 12);
        for code in ALL {
            assert!(seen.insert(code.code()), "duplicate {}", code.code());
            assert!(
                code.code()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{}",
                code.code()
            );
            assert_eq!(
                authn_core::error::codes::find(code.code()),
                Some(code),
                "{} is not registered",
                code.code()
            );
            assert!(!code.message(Locale::En).is_empty());
            assert!(!code.message(Locale::Tr).is_empty());
            assert!(!code.is_server_error());
        }
    }

    #[test]
    fn soc_01_wire_strings_are_unchanged() {
        let wire: Vec<&str> = ALL.iter().map(authn_core::error::ErrorCode::code).collect();
        assert_eq!(
            wire,
            [
                "oauth_provider_unknown",
                "oauth_state_invalid",
                "oauth_nonce_invalid",
                "oauth_token_invalid",
                "oauth_authorization_denied",
                "oauth_email_not_verified",
                "oauth_link_required",
                "oauth_native_not_supported",
                "identity_already_linked",
                "identity_provider_already_linked",
                "identity_last_login_method",
                "identity_link_not_allowed",
            ]
        );
    }
}
