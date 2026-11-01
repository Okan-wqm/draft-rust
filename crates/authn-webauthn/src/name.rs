//! Passkey display names (PKY-04).
//!
//! Names are chosen by the user and shown back to them (passkey list,
//! notifications never include them). They are stored as plain text, so the
//! rules only defend against confusing or deceptive rendering: control
//! characters, bidirectional overrides (`U+202E` "RLO" spoofing that makes
//! `"yek ytiruces"` render reversed), invisible format characters and absurd lengths are
//! rejected; surrounding whitespace is trimmed.

use authn_core::error::{AuthError, codes};

/// Longest name in characters (matches the `webauthn_credentials` CHECK).
pub const MAX_NAME_CHARS: usize = 64;

/// Longest input inspected (bytes) before rejecting outright.
const MAX_INPUT_BYTES: usize = 1024;

/// Default name of a passkey that may be used for passwordless login.
pub const DEFAULT_PASSKEY_NAME: &str = "Passkey";

/// Default name of a credential registered as a second factor only.
pub const DEFAULT_SECURITY_KEY_NAME: &str = "Security key";

/// Validates and normalizes a user-supplied passkey name: trims surrounding
/// whitespace, requires 1–64 characters and rejects control, bidi-override
/// and invisible format characters. Fails with `validation_failed` (the
/// rejected value is never echoed).
pub fn normalize_name(input: &str) -> Result<String, AuthError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(invalid());
    }
    let trimmed = input.trim();
    let count = trimmed.chars().count();
    if count == 0 || count > MAX_NAME_CHARS {
        return Err(invalid());
    }
    if trimmed.chars().any(is_forbidden) {
        return Err(invalid());
    }
    Ok(trimmed.to_owned())
}

fn invalid() -> AuthError {
    AuthError::new(codes::common::VALIDATION_FAILED)
        .with_details(serde_json::json!({ "field": "name", "max_chars": MAX_NAME_CHARS }))
}

/// Characters that may hide or reorder text when rendered.
fn is_forbidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Bidirectional formatting: LRM, RLM, ALM, embeddings/overrides,
            // isolates.
            '\u{200E}'
                | '\u{200F}'
                | '\u{061C}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                // Zero-width and invisible format characters.
                | '\u{200B}'..='\u{200D}'
                | '\u{2060}'..='\u{2064}'
                | '\u{FEFF}'
                | '\u{180E}'
                | '\u{00AD}'
                // Line / paragraph separators.
                | '\u{2028}'
                | '\u{2029}'
                // Interlinear annotations and object replacement.
                | '\u{FFF9}'..='\u{FFFC}'
                // Tag characters (invisible "ASCII smuggling").
                | '\u{E0000}'..='\u{E007F}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pky_04_names_are_trimmed_and_bounded() {
        assert_eq!(normalize_name("  My YubiKey ").unwrap(), "My YubiKey");
        assert_eq!(
            normalize_name("Ömer'in iPhone'u").unwrap(),
            "Ömer'in iPhone'u"
        );
        assert!(normalize_name("").is_err());
        assert!(normalize_name("   ").is_err());
        assert!(normalize_name(&"a".repeat(64)).is_ok());
        assert!(normalize_name(&"a".repeat(65)).is_err());
        assert!(normalize_name(&"ğ".repeat(64)).is_ok());
        assert!(normalize_name(&"x".repeat(5000)).is_err());
    }

    #[test]
    fn pky_04_names_reject_spoofing_characters() {
        for bad in [
            "key\u{202E}yek",
            "a\u{200B}b",
            "line\nbreak",
            "tab\there",
            "nul\0",
            "tag\u{E0041}",
            "isolate\u{2066}x",
            "soft\u{00AD}hyphen",
        ] {
            let err = normalize_name(bad).unwrap_err();
            assert_eq!(err.code(), codes::common::VALIDATION_FAILED, "{bad:?}");
            let details = err.details().unwrap().to_string();
            assert!(!details.contains(bad), "value echoed");
        }
    }
}
