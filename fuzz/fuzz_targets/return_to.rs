//! Owner: authn-protect (PRT-10). TST-04: return_to / redirect_uri validation.
//!
//! Invariants checked for every input:
//! * the validator never panics;
//! * an accepted absolute target is byte-for-byte an allow-list entry;
//! * an accepted relative target starts with `/`, not `//`, contains no
//!   backslash, control or non-ASCII byte, and resolves to the server's own
//!   origin.
#![no_main]

use std::sync::OnceLock;

use authn_protect::web::{RedirectTarget, RedirectValidator};
use libfuzzer_sys::fuzz_target;

fn validator() -> &'static RedirectValidator {
    static VALIDATOR: OnceLock<RedirectValidator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        RedirectValidator::from_strings(
            vec![
                "https://app.example.com/callback".to_owned(),
                "com.example.app:/oauth/callback".to_owned(),
            ],
            "https://auth.example.com",
        )
        .expect("valid fuzz fixture")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let validator = validator();
    match validator.validate(input) {
        Ok(RedirectTarget::Absolute(target)) => {
            assert!(validator.is_allow_listed(&target));
            assert_eq!(target, input);
        }
        Ok(RedirectTarget::Relative(path)) => {
            assert!(path.starts_with('/') && !path.starts_with("//"), "{path:?}");
            assert!(
                path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\'),
                "{path:?}"
            );
            assert!(validator.stays_on_base_origin(&path), "{path:?}");
            // Idempotent: the normalised form validates to itself.
            assert_eq!(
                validator.validate(&path).ok(),
                Some(RedirectTarget::Relative(path.clone()))
            );
        }
        Err(_) => {}
    }
});
