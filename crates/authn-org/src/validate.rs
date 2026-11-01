//! Input validation shared by the use cases.
//!
//! Every value that ends up in another user's e-mail or screen (organization
//! and role names, service-account names) is NFKC-normalized and stripped of
//! characters that can hide or reorder text: control characters, bidi
//! overrides / isolates (Trojan-Source style spoofing), zero-width and other
//! invisible format characters, line / paragraph separators.

use authn_core::domain::EmailAddress;
use authn_core::error::{AuthError, codes};
use unicode_normalization::UnicodeNormalization;

/// Longest organization name (characters, matches the CHECK constraint).
pub const MAX_ORG_NAME_CHARS: usize = 200;
/// Longest role name.
pub const MAX_ROLE_NAME_CHARS: usize = 100;
/// Longest role / service-account description.
pub const MAX_DESCRIPTION_CHARS: usize = 500;
/// Longest service-account / API-key name.
pub const MAX_RESOURCE_NAME_CHARS: usize = 100;
/// Longest accepted raw text input before normalization (bytes).
const MAX_RAW_TEXT_BYTES: usize = 4096;
/// Longest accepted raw domain input (bytes).
const MAX_RAW_DOMAIN_BYTES: usize = 300;

/// Slugs that would be confusing or collide with routes / brand names.
const RESERVED_SLUGS: &[&str] = &[
    "admin",
    "administrator",
    "api",
    "auth",
    "help",
    "login",
    "logout",
    "me",
    "new",
    "null",
    "root",
    "security",
    "settings",
    "signup",
    "support",
    "system",
    "undefined",
    "www",
];

/// A `validation_failed` error naming the offending field (safe to show).
#[must_use]
pub fn invalid(field: &'static str) -> AuthError {
    AuthError::new(codes::common::VALIDATION_FAILED)
        .with_details(serde_json::json!({ "field": field }))
        .with_context(field)
}

/// Normalizes a slug: trimmed, ASCII-lowercased, `[a-z0-9-]`, 1–63
/// characters, no leading / trailing hyphen, not reserved (ORG-01).
pub fn slug(input: &str) -> Result<String, AuthError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.len() > 63 || !trimmed.is_ascii() {
        return Err(invalid("slug"));
    }
    let lowered = trimmed.to_ascii_lowercase();
    let bytes = lowered.as_bytes();
    let edge_ok = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let ok = edge_ok(bytes.first())
        && edge_ok(bytes.last())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && !lowered.contains("--")
        && !RESERVED_SLUGS.contains(&lowered.as_str());
    if ok {
        Ok(lowered)
    } else {
        Err(invalid("slug"))
    }
}

/// Whether `c` may hide, reorder or break displayed text.
fn is_disallowed_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFFB}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

/// Normalizes display text: bounded raw size, NFKC, trimmed, 1–`max_chars`
/// characters, no invisible / control / bidi characters.
pub fn display_text(
    input: &str,
    max_chars: usize,
    field: &'static str,
) -> Result<String, AuthError> {
    if input.len() > MAX_RAW_TEXT_BYTES {
        return Err(invalid(field));
    }
    let normalized: String = input.nfkc().collect();
    let trimmed = normalized.trim();
    let count = trimmed.chars().count();
    if count == 0 || count > max_chars || trimmed.chars().any(is_disallowed_char) {
        return Err(invalid(field));
    }
    Ok(trimmed.to_owned())
}

/// Optional description: `None` / empty → `None`.
pub fn description(input: Option<&str>) -> Result<Option<String>, AuthError> {
    match input {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => display_text(s, MAX_DESCRIPTION_CHARS, "description").map(Some),
    }
}

/// Normalizes a domain for verification (ORG-06): IDNA / punycode ASCII,
/// lowercase, no trailing dot, at least two labels, letter-initial TLD —
/// reusing the hardened e-mail domain pipeline (homograph and mixed-script
/// rejection of ACC-03) so a domain verifies exactly what e-mail addresses
/// of that domain normalize to.
pub fn domain(input: &str) -> Result<String, AuthError> {
    if input.len() > MAX_RAW_DOMAIN_BYTES {
        return Err(invalid("domain"));
    }
    let trimmed = input.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c == '@' || c == '/' || c == ':' || c.is_whitespace() || is_disallowed_char(c))
    {
        return Err(invalid("domain"));
    }
    let probe = format!("verify@{trimmed}");
    let parsed = EmailAddress::parse(&probe).map_err(|_| invalid("domain"))?;
    let ascii = parsed.domain().to_owned();
    if is_storable_domain(&ascii) {
        Ok(ascii)
    } else {
        Err(invalid("domain"))
    }
}

/// Mirrors the `org_domains_domain_check` constraint.
fn is_storable_domain(domain: &str) -> bool {
    if domain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let Some((tld, rest)) = labels.split_last() else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let ldh = |label: &str| {
        let b = label.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && b.first().is_some_and(|c| *c != b'-')
            && b.last().is_some_and(|c| *c != b'-')
    };
    rest.iter().all(|l| ldh(l))
        && ldh(tld)
        && tld.len() >= 2
        && tld.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_01_slugs_are_normalized_and_restricted() {
        assert_eq!(slug("  Acme-Corp ").unwrap(), "acme-corp");
        assert_eq!(slug("a").unwrap(), "a");
        assert_eq!(slug("a1-b2").unwrap(), "a1-b2");
        for bad in [
            "",
            "-acme",
            "acme-",
            "ac--me",
            "acme corp",
            "acme_corp",
            "açme",
            "admin",
            "API",
            &"a".repeat(64),
            "acme\u{200B}",
        ] {
            assert!(slug(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn org_01_display_text_rejects_invisible_and_bidi_characters() {
        assert_eq!(
            display_text("  Acme Ltd. ", 200, "name").unwrap(),
            "Acme Ltd."
        );
        assert_eq!(display_text("Ａｃｍｅ", 200, "name").unwrap(), "Acme");
        assert_eq!(display_text("Şirket Ğ", 200, "name").unwrap(), "Şirket Ğ");
        for bad in [
            "",
            "   ",
            "evil\u{202E}gpj.exe",
            "zero\u{200B}width",
            "tag\u{E0041}",
            "line\nbreak",
            "nul\0",
            "bom\u{FEFF}",
            "isolate\u{2067}x",
        ] {
            assert!(display_text(bad, 200, "name").is_err(), "{bad:?}");
        }
        assert!(display_text(&"x".repeat(201), 200, "name").is_err());
        assert!(display_text(&"x".repeat(5000), 10_000, "name").is_err());
        let err = display_text("", 10, "name").unwrap_err();
        assert_eq!(err.details().unwrap()["field"], "name");
    }

    #[test]
    fn org_06_domains_are_normalized_like_email_domains() {
        assert_eq!(domain("Example.COM.").unwrap(), "example.com");
        assert_eq!(domain("sub.example.co.uk").unwrap(), "sub.example.co.uk");
        assert_eq!(domain("bücher.example").unwrap(), "xn--bcher-kva.example");
        for bad in [
            "",
            "localhost",
            "com",
            "example",
            "exa mple.com",
            "user@example.com",
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "-example.com",
            "1.2.3.4",
            "[::1]",
            "example.c",
            "exаmple.com", // Cyrillic 'а'
            &format!("{}.com", "a".repeat(64)),
            &"a.".repeat(200),
        ] {
            assert!(domain(bad).is_err(), "{bad:?}");
        }
    }
}
