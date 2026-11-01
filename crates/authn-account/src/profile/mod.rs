//! Profile field validation (ACC-03 display-name hardening, ACC-08).
//!
//! **Display names** are shown to other people (organization member lists,
//! invitations, e-mail greetings), so they are an impersonation surface.
//! [`normalize_display_name`]:
//!
//! 1. rejects oversized input before any work (DoS guard);
//! 2. applies Unicode NFKC, maps every whitespace character to a space,
//!    collapses runs and trims;
//! 3. accepts only characters allowed in identifiers by UTS #39 (letters,
//!    marks, digits of recommended scripts) plus space and a few
//!    punctuation marks common in names (`- ' ’ . , ( ) &`); invisible and
//!    format characters (zero-width joiners, bidi controls, soft hyphen),
//!    controls, symbols and emoji are rejected;
//! 4. rejects more than two consecutive combining marks ("Zalgo");
//! 5. requires the UTS #39 *moderately restrictive* profile on the letters:
//!    one script, or Latin plus one other recommended script except
//!    Cyrillic/Greek (so `Аdmin` with a Cyrillic `А` is rejected, while
//!    `山田 Taro` is accepted);
//! 6. rejects names whose confusable skeleton (UTS #39) equals a reserved
//!    word such as `admin`, `support` or `security`;
//! 7. enforces `account.display_name_max_chars`.
//!
//! **Time zones** must be IANA names ([`canonical_time_zone`]); input is
//! matched case-insensitively and stored in canonical spelling.

mod tz_names;

use authn_core::error::{AuthError, codes};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use unicode_security::{GeneralSecurityProfile, RestrictionLevel, RestrictionLevelDetection};

/// Input above this many bytes is rejected before normalization.
pub const MAX_DISPLAY_NAME_INPUT_BYTES: usize = 1024;
/// Longest accepted time zone name (bytes; `user_profiles` limit).
pub const MAX_TIME_ZONE_BYTES: usize = 64;
/// Longest accepted run of consecutive combining marks.
const MAX_COMBINING_RUN: usize = 2;
/// Punctuation allowed in display names besides letters, digits and space.
const NAME_PUNCTUATION: &[char] = &['-', '\'', '\u{2019}', '.', ',', '(', ')', '&'];
/// Invisible joiners that UTS #39 allows in identifiers but that can hide
/// differences between two visually identical names.
const INVISIBLE_JOINERS: &[char] = &['\u{200C}', '\u{200D}'];
/// Names that must not be imitated (compared by confusable skeleton, case
/// and punctuation insensitive).
const RESERVED_NAMES: &[&str] = &[
    "admin",
    "administrator",
    "support",
    "security",
    "system",
    "root",
    "staff",
    "moderator",
    "official",
    "noreply",
    "helpdesk",
];

/// Why a display name was rejected (never echoes the input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayNameError {
    /// Empty after normalization.
    Empty,
    /// Longer than allowed.
    TooLong,
    /// Contains a character outside the allowed set.
    ForbiddenCharacter,
    /// Too many stacked combining marks.
    CombiningMarks,
    /// Mixes scripts in a confusable way.
    MixedScript,
    /// Imitates a reserved name.
    Reserved,
}

impl DisplayNameError {
    /// Stable reason code (envelope `details.reason`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong => "too_long",
            Self::ForbiddenCharacter => "forbidden_character",
            Self::CombiningMarks => "combining_marks",
            Self::MixedScript => "mixed_script",
            Self::Reserved => "reserved",
        }
    }
}

impl From<DisplayNameError> for AuthError {
    fn from(err: DisplayNameError) -> Self {
        AuthError::new(codes::account::INVALID_DISPLAY_NAME)
            .with_details(serde_json::json!({ "reason": err.as_str() }))
    }
}

/// Validates and normalizes a display name (see the module docs). Returns
/// the normalized value to store.
pub fn normalize_display_name(input: &str, max_chars: u32) -> Result<String, DisplayNameError> {
    if input.len() > MAX_DISPLAY_NAME_INPUT_BYTES {
        return Err(DisplayNameError::TooLong);
    }
    let nfkc: String = input.nfkc().collect();
    let mut name = String::with_capacity(nfkc.len());
    let mut pending_space = false;
    for c in nfkc.chars() {
        if c.is_whitespace() {
            pending_space = !name.is_empty();
            continue;
        }
        if pending_space {
            name.push(' ');
            pending_space = false;
        }
        name.push(c);
    }
    if name.is_empty() {
        return Err(DisplayNameError::Empty);
    }
    let limit = usize::try_from(max_chars).unwrap_or(usize::MAX);
    if name.chars().count() > limit {
        return Err(DisplayNameError::TooLong);
    }
    let mut has_letter_or_digit = false;
    let mut combining_run = 0_usize;
    for c in name.chars() {
        let punctuation = c == ' ' || NAME_PUNCTUATION.contains(&c);
        let identifier =
            !c.is_ascii_punctuation() && !INVISIBLE_JOINERS.contains(&c) && c.identifier_allowed();
        if !punctuation && !identifier {
            return Err(DisplayNameError::ForbiddenCharacter);
        }
        if is_combining_mark(c) {
            combining_run += 1;
            if combining_run > MAX_COMBINING_RUN {
                return Err(DisplayNameError::CombiningMarks);
            }
        } else {
            combining_run = 0;
            has_letter_or_digit |= identifier;
        }
    }
    if !has_letter_or_digit {
        return Err(DisplayNameError::ForbiddenCharacter);
    }
    let letters: String = name
        .chars()
        .filter(|c| *c != ' ' && !NAME_PUNCTUATION.contains(c))
        .collect();
    if !letters
        .as_str()
        .check_restriction_level(RestrictionLevel::ModeratelyRestrictive)
    {
        return Err(DisplayNameError::MixedScript);
    }
    let skeleton = folded_skeleton(&letters);
    if RESERVED_NAMES
        .iter()
        .any(|reserved| folded_skeleton(reserved) == skeleton)
    {
        return Err(DisplayNameError::Reserved);
    }
    Ok(name)
}

/// Case-folded UTS #39 skeleton of the alphanumeric characters of `s`.
fn folded_skeleton(s: &str) -> String {
    let lowered = s.to_lowercase();
    unicode_security::skeleton(&lowered)
        .flat_map(char::to_lowercase)
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// The canonical spelling of an IANA time zone name, matched
/// case-insensitively (`europe/istanbul` → `Europe/Istanbul`), or `None`.
#[must_use]
pub fn canonical_time_zone(input: &str) -> Option<&'static str> {
    if input.is_empty() || input.len() > MAX_TIME_ZONE_BYTES || !input.is_ascii() {
        return None;
    }
    let zones = tz_names::IANA_TIME_ZONES;
    if let Ok(i) = zones.binary_search(&input) {
        return zones.get(i).copied();
    }
    zones
        .iter()
        .copied()
        .find(|zone| zone.eq_ignore_ascii_case(input))
}

/// [`canonical_time_zone`] as a validation step.
pub fn validate_time_zone(input: &str) -> Result<&'static str, AuthError> {
    canonical_time_zone(input).ok_or_else(|| AuthError::new(codes::account::INVALID_TIME_ZONE))
}

/// Default time zone of new profiles.
pub const DEFAULT_TIME_ZONE: &str = "UTC";

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn ok(input: &str) -> String {
        normalize_display_name(input, 64).unwrap_or_else(|e| panic!("{input:?}: {e:?}"))
    }

    fn err(input: &str) -> DisplayNameError {
        normalize_display_name(input, 64).expect_err(input)
    }

    #[test]
    fn acc_08_display_names_are_normalized() {
        assert_eq!(ok("  Ayşe   Yılmaz \t"), "Ayşe Yılmaz");
        assert_eq!(ok("Mary-Jane O'Neil Jr."), "Mary-Jane O'Neil Jr.");
        assert_eq!(ok("ＡＬＩ"), "ALI");
        assert_eq!(ok("Line\nbreak"), "Line break");
        assert_eq!(ok("山田 太郎"), "山田 太郎");
        assert_eq!(ok("Tanaka たなか"), "Tanaka たなか");
        assert_eq!(ok("Иван Петров"), "Иван Петров");
        assert_eq!(ok("محمد علي"), "محمد علي");
        assert_eq!(ok("José Ñúñez"), "José Ñúñez");
    }

    #[test]
    fn acc_03_display_name_rejects_mixed_script_confusables() {
        // Latin "dmin" + Cyrillic "А".
        assert_eq!(err("\u{0410}dmin Team"), DisplayNameError::MixedScript);
        // Latin + Greek omicron.
        assert_eq!(err("G\u{03BF}\u{03BF}gle"), DisplayNameError::MixedScript);
        // Latin word + Cyrillic word.
        assert_eq!(err("Ivan Иванов"), DisplayNameError::MixedScript);
    }

    #[test]
    fn acc_03_display_name_rejects_invisible_and_format_characters() {
        for input in [
            "Ali\u{200B}ce",    // zero-width space
            "Ali\u{200D}ce",    // zero-width joiner
            "Ali\u{202E}ecila", // right-to-left override
            "Ali\u{00AD}ce",    // soft hyphen
            "Ali\u{0000}ce",
            "Ali\u{2066}ce", // left-to-right isolate
            "Alice 😀",
            "<script>",
            "Alice\u{E000}", // private use
        ] {
            assert_eq!(
                err(input),
                DisplayNameError::ForbiddenCharacter,
                "{input:?}"
            );
        }
    }

    #[test]
    fn acc_03_display_name_rejects_zalgo_and_reserved_names() {
        assert_eq!(
            err("Ze\u{0300}\u{0301}\u{0302}\u{0303}lda"),
            DisplayNameError::CombiningMarks
        );
        assert_eq!(err("Admin"), DisplayNameError::Reserved);
        assert_eq!(err("S U P P O R T"), DisplayNameError::Reserved);
        assert_eq!(err("Security."), DisplayNameError::Reserved);
        // "rn" is confusable with "m" (UTS #39 skeleton).
        assert_eq!(err("Adrnin"), DisplayNameError::Reserved);
        assert_eq!(ok("Admin Team"), "Admin Team");
    }

    #[test]
    fn acc_08_display_name_length_and_emptiness() {
        assert_eq!(err("   "), DisplayNameError::Empty);
        assert_eq!(err("..."), DisplayNameError::ForbiddenCharacter);
        assert_eq!(err(&"a".repeat(65)), DisplayNameError::TooLong);
        assert_eq!(ok(&"a".repeat(64)).len(), 64);
        assert_eq!(
            err(&"a".repeat(MAX_DISPLAY_NAME_INPUT_BYTES + 1)),
            DisplayNameError::TooLong
        );
        let e = AuthError::from(DisplayNameError::Reserved);
        assert_eq!(e.code(), codes::account::INVALID_DISPLAY_NAME);
        assert_eq!(e.details().unwrap()["reason"], "reserved");
    }

    #[test]
    fn acc_08_time_zones_are_iana_names() {
        assert_eq!(
            canonical_time_zone("Europe/Istanbul"),
            Some("Europe/Istanbul")
        );
        assert_eq!(
            canonical_time_zone("europe/istanbul"),
            Some("Europe/Istanbul")
        );
        assert_eq!(canonical_time_zone("UTC"), Some("UTC"));
        assert!(canonical_time_zone("America/Argentina/Buenos_Aires").is_some());
        // Backward-compatible links are accepted too.
        assert_eq!(canonical_time_zone("Turkey"), Some("Turkey"));
        for bad in [
            "",
            "Mars/Olympus_Mons",
            "Europe/Istanbul ",
            "../../etc/passwd",
            "Europe/İstanbul",
            "+03:00",
            "localtime",
        ] {
            assert_eq!(canonical_time_zone(bad), None, "{bad:?}");
        }
        assert!(canonical_time_zone(&"A".repeat(65)).is_none());
        assert_eq!(
            validate_time_zone("Nowhere/City").unwrap_err().code(),
            codes::account::INVALID_TIME_ZONE
        );
    }

    #[test]
    fn acc_08_time_zone_table_is_sorted_and_unique() {
        let zones = tz_names::IANA_TIME_ZONES;
        assert!(zones.len() > 400);
        assert!(zones.windows(2).all(|w| w[0] < w[1]));
        assert!(zones.iter().all(|z| z.len() <= MAX_TIME_ZONE_BYTES));
    }

    proptest! {
        #[test]
        fn tst_03_display_name_normalization_is_idempotent(input in "\\PC{0,80}") {
            if let Ok(first) = normalize_display_name(&input, 128) {
                let second = normalize_display_name(&first, 128).unwrap();
                prop_assert_eq!(first, second);
            }
        }

        #[test]
        fn tst_04_display_name_never_panics(input in "\\PC*") {
            let _ = normalize_display_name(&input, 64);
        }
    }
}
