//! Mandatory justifications of admin actions (ADM-03, ADM-04, ADM-08).
//!
//! The text is free-form and may contain personal data, so it never enters
//! the hash-chained audit record (AUD-03). It is stored in
//! `admin_action_reasons`, linked to the audit event by id (migration
//! `2200`).

use authn_core::error::{AuthError, codes};

/// Maximum characters of a justification (same bound as the impersonation
/// reason enforced by authn-session).
pub const MAX_REASON_CHARS: usize = 1000;

/// A validated justification: trimmed, 1–1000 characters, no control
/// characters, line / paragraph separators or invisible formatting and
/// filler characters (bidirectional controls, zero-width characters, tag
/// characters, Hangul fillers) that could hide or disguise what an auditor
/// reads.
#[derive(Clone, PartialEq, Eq)]
pub struct Justification(String);

impl Justification {
    /// Validates `raw`; `None` or an invalid value is `admin_reason_required`.
    pub fn parse(raw: Option<&str>) -> Result<Self, AuthError> {
        let trimmed = raw.map(str::trim).unwrap_or_default();
        let chars = trimmed.chars().count();
        if chars == 0 || chars > MAX_REASON_CHARS || trimmed.chars().any(is_disallowed) {
            return Err(AuthError::new(codes::admin::REASON_REQUIRED));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Free text may contain personal data: never printed by `Debug`.
impl std::fmt::Debug for Justification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Justification({} chars)", self.0.chars().count())
    }
}

/// Control characters, line / paragraph separators and invisible
/// formatting or filler characters: every format character (`Cf`) of the
/// BMP and the supplementary planes that a reader cannot see, plus the
/// invisible Hangul fillers and the combining grapheme joiner. Emoji
/// variation selectors stay allowed.
fn is_disallowed(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adm_08_reason_is_required_and_bounded() {
        for bad in [
            None,
            Some(""),
            Some("   \t "),
            Some("line\nbreak"),
            Some("bidi \u{202E}override"),
            Some("zero\u{200B}width"),
        ] {
            let err = Justification::parse(bad).unwrap_err();
            assert_eq!(err.code(), codes::admin::REASON_REQUIRED, "{bad:?}");
        }
        let long = "x".repeat(MAX_REASON_CHARS + 1);
        assert!(Justification::parse(Some(&long)).is_err());
        let max = "ç".repeat(MAX_REASON_CHARS);
        assert!(Justification::parse(Some(&max)).is_ok());
        let ok = Justification::parse(Some("  Ticket SUP-1234: user lost phone  ")).unwrap();
        assert_eq!(ok.as_str(), "Ticket SUP-1234: user lost phone");
    }

    #[test]
    fn adm_08_reason_is_not_printed_by_debug() {
        let reason = Justification::parse(Some("customer alice@example.com called")).unwrap();
        let debug = format!("{reason:?}");
        assert!(!debug.contains("alice"), "{debug}");
    }
}
