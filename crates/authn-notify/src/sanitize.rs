//! Neutralisation of untrusted text before it reaches a message (NTF-02).
//!
//! HTML templates auto-escape every value, but plain-text bodies, subject
//! lines, SMS texts and mail headers have no escaping. Values that come
//! from users or tenants (display names, organization names, device
//! descriptions) are therefore normalised here **before** rendering:
//!
//! * control characters (CR, LF, NUL, ESC…) and Unicode line/paragraph
//!   separators become spaces — no header injection, no fake paragraphs;
//! * bidirectional overrides/isolates and zero-width characters are
//!   removed — no `gpj.exe`-style reordering or invisible text;
//! * whitespace runs collapse to one space; the result is trimmed;
//! * `://` is defanged to `[://]` so a name such as
//!   `https://evil.example` is not turned into a clickable link;
//! * the length is capped (in characters) with an ellipsis.

/// Longest display name kept in greetings and headers.
pub const MAX_NAME_CHARS: usize = 64;
/// Longest organization name kept (invitation, ownership transfer).
pub const MAX_ORG_NAME_CHARS: usize = 80;
/// Longest device / location description kept.
pub const MAX_DETAIL_CHARS: usize = 120;
/// Longest subject line.
pub const MAX_SUBJECT_CHARS: usize = 200;

/// Characters removed outright: bidi controls, zero-width characters, BOM,
/// soft hyphen, Arabic letter mark, Mongolian vowel separator.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Characters turned into a space: controls, line/paragraph separators,
/// every other Unicode whitespace.
fn is_breaking(c: char) -> bool {
    c.is_control() || c.is_whitespace() || matches!(c, '\u{2028}' | '\u{2029}')
}

/// Collapses, strips and truncates `input` (see the module docs) without
/// defanging.
fn normalize(input: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_chars.saturating_mul(4)));
    let mut pending_space = false;
    for c in input.chars() {
        if is_invisible(c) {
            continue;
        }
        if is_breaking(c) {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    truncate(out, max_chars)
}

fn truncate(value: String, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value;
    }
    let mut out: String = value.chars().take(max_chars.saturating_sub(1)).collect();
    let trimmed_len = out.trim_end().len();
    out.truncate(trimmed_len);
    out.push('…');
    out
}

/// Sanitizes an untrusted value for any message part (body, subject, SMS):
/// normalized, defanged and capped at `max_chars`.
#[must_use]
pub fn user_text(input: &str, max_chars: usize) -> String {
    // Normalise first: a zero-width character inside `:/​/` must not hide
    // the scheme separator from the defanging step.
    let defanged = normalize(input, usize::MAX).replace("://", "[://]");
    truncate(defanged, max_chars)
}

/// Like [`user_text`], but `None` when nothing printable remains.
#[must_use]
pub fn optional_user_text(input: Option<&str>, max_chars: usize) -> Option<String> {
    input
        .map(|value| user_text(value, max_chars))
        .filter(|value| !value.is_empty())
}

/// A single-line header value (subject, display name): no control
/// characters, separators or bidi controls, collapsed and capped.
#[must_use]
pub fn header_value(input: &str, max_chars: usize) -> String {
    normalize(input, max_chars)
}

/// Normalizes a rendered plain-text body: Unix newlines, no trailing
/// whitespace, at most one blank line in a row, no leading/trailing blank
/// lines, and no control characters other than `\n` (a template or a value
/// can never smuggle `\r`, NUL or escape sequences into the message).
#[must_use]
pub fn text_body(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut blank_run = 0_usize;
    for raw_line in input.lines() {
        let line: String = raw_line
            .chars()
            .filter(|c| !is_invisible(*c))
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let line = line.trim_end();
        if line.is_empty() {
            blank_run += 1;
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
            if blank_run > 0 {
                out.push('\n');
            }
        }
        blank_run = 0;
        out.push_str(line);
    }
    out
}

/// Whether `value` can be placed into a header unchanged.
#[must_use]
pub fn is_header_safe(value: &str) -> bool {
    !value
        .chars()
        .any(|c| is_breaking(c) && c != ' ' || is_invisible(c))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn ntf_02_control_characters_and_line_breaks_are_neutralised() {
        assert_eq!(
            header_value("Hi\r\nBcc: victim@example.com", 200),
            "Hi Bcc: victim@example.com"
        );
        assert_eq!(user_text("  Alice \t\n Smith  ", 64), "Alice Smith");
        assert_eq!(user_text("a\u{2028}b\u{0085}c\0d", 64), "a b c d");
        assert_eq!(user_text("\u{1b}[31mred", 64), "[31mred");
    }

    #[test]
    fn ntf_02_bidi_and_zero_width_characters_are_removed() {
        assert_eq!(user_text("invoice\u{202E}fdp.exe", 64), "invoicefdp.exe");
        assert_eq!(user_text("pay\u{200B}pal", 64), "paypal");
        assert_eq!(user_text("\u{FEFF}\u{2066}x\u{2069}", 64), "x");
    }

    #[test]
    fn ntf_02_urls_in_untrusted_values_are_defanged() {
        assert_eq!(
            user_text("Visit https://evil.example/login", 64),
            "Visit https[://]evil.example/login"
        );
        // Headers are not defanged (they are never auto-linked), but the
        // defanged form survives header sanitisation unchanged.
        assert_eq!(header_value("https[://]x", 64), "https[://]x");
        // Invisible characters cannot hide the separator.
        assert_eq!(user_text("https:\u{200B}//evil", 64), "https[://]evil");
        assert_eq!(user_text("https:\u{202E}//evil", 64), "https[://]evil");
    }

    #[test]
    fn ntf_02_values_are_truncated_on_character_boundaries() {
        assert_eq!(user_text("ğğğğğğ", 4), "ğğğ…");
        assert_eq!(user_text("abc def", 5), "abc…");
        assert_eq!(user_text("abc", 3), "abc");
        assert_eq!(optional_user_text(Some(" \u{200B} "), 10), None);
        assert_eq!(optional_user_text(None, 10), None);
    }

    #[test]
    fn ntf_02_text_bodies_are_normalised() {
        let raw = "\n\nHello,\r\n\n\n\nline one   \nline\u{7}two\n\n";
        assert_eq!(text_body(raw), "Hello,\n\nline one\nline two");
        assert!(is_header_safe("Plain subject"));
        assert!(!is_header_safe("a\nb"));
        assert!(!is_header_safe("a\u{202E}b"));
    }

    proptest! {
        #[test]
        fn ntf_02_sanitised_values_are_always_header_safe(input in "\\PC*|[\\x00-\\x1f\\u{2028}\\u{202A}-\\u{202E} a-z:/]*") {
            let header = header_value(&input, 50);
            prop_assert!(is_header_safe(&header));
            prop_assert!(header.chars().count() <= 50);
            let text = user_text(&input, 50);
            prop_assert!(is_header_safe(&text));
            // Every remaining scheme separator is the defanged `[://]` form.
            prop_assert!(text
                .match_indices("://")
                .all(|(i, _)| i > 0 && text.as_bytes().get(i - 1) == Some(&b'[')));
            let body = text_body(&input);
            prop_assert!(!body.contains('\r'));
            prop_assert!(body.chars().all(|c| c == '\n' || !c.is_control()));
        }
    }
}
