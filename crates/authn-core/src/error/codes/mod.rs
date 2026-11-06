//! The error-code registry, one file per owning module.
//!
//! | file | owner |
//! |------|-------|
//! | `common.rs` | authn-core (architect) |
//! | `crypto.rs` | authn-crypto |
//! | `store.rs` | authn-store |
//! | `password.rs` | authn-password |
//! | `account.rs` | authn-account |
//! | `mfa.rs` | authn-mfa |
//! | `webauthn.rs` | authn-webauthn |
//! | `org.rs` | authn-org |
//! | `protect.rs` | authn-protect |
//! | `audit.rs` | authn-audit |
//! | `notify.rs` | authn-notify |
//! | `session.rs` | authn-session |
//! | `oidc_client.rs` | authn-oidc-client |
//! | `oidc_provider.rs` | authn-oidc-provider |
//! | `admin.rs` | authn-admin |
//! | `server.rs` | authn-server |
//!
//! Code strings must be globally unique, `snake_case`, ASCII, and stable
//! forever. The unit tests below enforce uniqueness and format.

use crate::error::ErrorCode;

pub mod account;
pub mod admin;
pub mod audit;
pub mod common;
pub mod crypto;
pub mod mfa;
pub mod notify;
pub mod oidc_client;
pub mod oidc_provider;
pub mod org;
pub mod password;
pub mod protect;
pub mod server;
pub mod session;
pub mod store;
pub mod webauthn;

/// Every module registry, in a fixed order.
const REGISTRIES: &[&[ErrorCode]] = &[
    common::ALL,
    crypto::ALL,
    store::ALL,
    password::ALL,
    account::ALL,
    mfa::ALL,
    webauthn::ALL,
    org::ALL,
    protect::ALL,
    audit::ALL,
    notify::ALL,
    session::ALL,
    oidc_client::ALL,
    oidc_provider::ALL,
    admin::ALL,
    server::ALL,
];

/// Iterates over every registered code (used by the catalogue generator and
/// tests).
pub fn all() -> impl Iterator<Item = &'static ErrorCode> {
    REGISTRIES.iter().flat_map(|codes| codes.iter())
}

/// Looks a code up by its string.
#[must_use]
pub fn find(code: &str) -> Option<&'static ErrorCode> {
    all().find(|c| c.code() == code)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::domain::Locale;

    #[test]
    fn arc_08_codes_are_unique() {
        let mut seen = HashSet::new();
        for code in all() {
            assert!(
                seen.insert(code.code()),
                "duplicate error code {}",
                code.code()
            );
        }
    }

    #[test]
    fn arc_08_codes_are_snake_case_with_messages_in_both_languages() {
        for code in all() {
            let c = code.code();
            assert!(!c.is_empty() && c.len() <= 64, "{c}");
            assert!(
                c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{c} is not snake_case"
            );
            assert!(c.as_bytes()[0].is_ascii_lowercase(), "{c}");
            assert!(!c.ends_with('_') && !c.contains("__"), "{c}");
            assert!(!code.message(Locale::En).is_empty(), "{c} en");
            assert!(!code.message(Locale::Tr).is_empty(), "{c} tr");
            let status = code.status();
            assert!(status.is_client_error() || status.is_server_error(), "{c}");
        }
    }

    #[test]
    fn arc_08_find_by_string() {
        assert_eq!(find("internal_error"), Some(&common::INTERNAL_ERROR));
        assert_eq!(
            find("invalid_credentials"),
            Some(&session::INVALID_CREDENTIALS)
        );
        assert_eq!(find("does_not_exist"), None);
    }

    #[test]
    fn arc_08_status_mapping_for_foreign_errors() {
        use http::StatusCode;
        assert_eq!(common::for_status(StatusCode::NOT_FOUND), common::NOT_FOUND);
        assert_eq!(
            common::for_status(StatusCode::IM_A_TEAPOT),
            common::BAD_REQUEST
        );
        assert_eq!(
            common::for_status(StatusCode::BAD_GATEWAY),
            common::INTERNAL_ERROR
        );
    }
}
