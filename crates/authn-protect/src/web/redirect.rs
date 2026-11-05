//! `return_to` / `redirect_uri` validation (PRT-10, SOC-02).
//!
//! A value is accepted in exactly two cases:
//!
//! 1. it is **byte-for-byte equal** to an entry of
//!    `protect.redirect_allow_list` (absolute URLs, custom app schemes);
//! 2. it is a **safe relative path** on this server: starts with `/` but not
//!    `//`, and stays a same-origin path after every decoding a browser,
//!    proxy or front-end might apply.
//!
//! Rejected on sight: empty or > 2048 bytes, any byte outside printable
//! ASCII (spaces, tabs, CR/LF, NUL, DEL, raw Unicode — browsers strip some
//! of these, which turns `/\t/evil` into `//evil`), backslashes (`/\evil`
//! is `//evil` for browsers), malformed percent-escapes. The path is then
//! percent-decoded up to four times; every layer must be valid UTF-8, free
//! of control characters and backslashes, must not start with `//`, and
//! must not contain non-ASCII characters whose compatibility form (NFKC)
//! contains ASCII punctuation (fullwidth `／`, `＼`, `：`…). Finally the
//! path is resolved against `server.public_base_url` (WHATWG rules: dot
//! segments, `/..//evil`) and must keep the same origin and not start with
//! `//`; the *normalised* relative form is returned.

use std::sync::Arc;

use authn_core::config::protect::ProtectConfig;
use authn_core::error::{AuthError, codes};
use unicode_normalization::UnicodeNormalization;
use url::Url;

/// Longest accepted value.
pub const MAX_REDIRECT_LEN: usize = 2048;
/// Percent-decoding layers inspected.
const MAX_DECODE_LAYERS: usize = 4;

/// A validated redirect target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectTarget {
    /// A same-origin path (`/…`, normalised), to be resolved against
    /// `server.public_base_url`.
    Relative(String),
    /// An allow-listed absolute URL, exactly as configured.
    Absolute(String),
}

impl RedirectTarget {
    /// The value to put in a `Location` header / response.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Relative(s) | Self::Absolute(s) => s,
        }
    }
}

/// Validates redirect targets. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RedirectValidator {
    allow_list: Arc<[String]>,
    base: Url,
}

fn invalid() -> AuthError {
    AuthError::new(codes::protect::INVALID_REDIRECT)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// One percent-decoding pass; `None` on a malformed escape.
fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut iter = input.iter().copied();
    while let Some(b) = iter.next() {
        if b == b'%' {
            let hi = hex(iter.next()?)?;
            let lo = hex(iter.next()?)?;
            out.push(hi << 4 | lo);
        } else {
            out.push(b);
        }
    }
    Some(out)
}

/// Whether `value` parses as a URL with a script or local-document scheme
/// (`javascript:`, `data:` …; unparsable values are not absolute targets).
fn has_forbidden_scheme(value: &str) -> bool {
    Url::parse(value)
        .is_ok_and(|u| authn_core::config::protect::is_forbidden_redirect_scheme(u.scheme()))
}

/// Checks one decoded layer of a relative path.
fn layer_is_safe(layer: &str) -> bool {
    if layer.starts_with("//") || layer.contains('\\') {
        return false;
    }
    layer.chars().all(|c| {
        if c.is_control() {
            return false;
        }
        if c.is_ascii() {
            return true;
        }
        // A non-ASCII character must not *become* URL syntax under
        // compatibility normalisation (e.g. U+FF0F FULLWIDTH SOLIDUS → '/').
        std::iter::once(c)
            .nfkc()
            .all(|n| !n.is_ascii() || n.is_ascii_alphanumeric())
    })
}

impl RedirectValidator {
    /// A validator over exact allow-list entries; relative paths resolve
    /// against `base` (`server.public_base_url`).
    #[must_use]
    pub fn new(allow_list: Vec<String>, base: Url) -> Self {
        Self {
            allow_list: Arc::from(allow_list),
            base,
        }
    }

    /// From `protect.redirect_allow_list` and `server.public_base_url`.
    #[must_use]
    pub fn from_config(config: &ProtectConfig, public_base_url: &Url) -> Self {
        Self::new(config.redirect_allow_list.clone(), public_base_url.clone())
    }

    /// Like [`RedirectValidator::new`] with the base URL as a string
    /// (fuzzing, embedding without the `url` crate).
    pub fn from_strings(allow_list: Vec<String>, base: &str) -> Result<Self, AuthError> {
        let base =
            Url::parse(base).map_err(|_| AuthError::internal("invalid redirect base URL"))?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            return Err(AuthError::internal(
                "redirect base URL must be absolute http(s)",
            ));
        }
        Ok(Self::new(allow_list, base))
    }

    /// Whether `relative` resolves to the base origin (fuzz invariant).
    #[must_use]
    pub fn stays_on_base_origin(&self, relative: &str) -> bool {
        self.base
            .join(relative)
            .is_ok_and(|u| u.origin() == self.base.origin())
    }

    /// Whether `value` is an allow-list entry.
    #[must_use]
    pub fn is_allow_listed(&self, value: &str) -> bool {
        self.allow_list.iter().any(|e| e == value) && !has_forbidden_scheme(value)
    }

    /// `relative` resolved against the base, if it keeps the origin, has
    /// no credentials and its path does not start with `//`.
    fn resolve_same_origin(&self, relative: &str) -> Option<Url> {
        let resolved = self.base.join(relative).ok()?;
        (resolved.origin() == self.base.origin()
            && resolved.username().is_empty()
            && resolved.password().is_none()
            && !resolved.path().starts_with("//"))
        .then_some(resolved)
    }

    /// Validates `input`; `invalid_redirect` (400) when refused.
    pub fn validate(&self, input: &str) -> Result<RedirectTarget, AuthError> {
        if input.is_empty()
            || input.len() > MAX_REDIRECT_LEN
            || !input.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
        {
            return Err(invalid());
        }
        if let Some(entry) = self.allow_list.iter().find(|e| e.as_str() == input) {
            // Defence in depth behind the configuration check (K-58 audit):
            // a script / local-document scheme is never a target.
            if has_forbidden_scheme(entry) {
                return Err(invalid());
            }
            return Ok(RedirectTarget::Absolute(entry.clone()));
        }
        self.validate_relative(input).map(RedirectTarget::Relative)
    }

    fn validate_relative(&self, input: &str) -> Result<String, AuthError> {
        if !input.starts_with('/') {
            return Err(invalid());
        }
        let mut layer = input.as_bytes().to_vec();
        for _ in 0..MAX_DECODE_LAYERS {
            let text = std::str::from_utf8(&layer).map_err(|_| invalid())?;
            // Every decoding of the value must still be a same-origin path,
            // also after dot-segment removal (`/..//evil` → `//evil`).
            if !layer_is_safe(text) || self.resolve_same_origin(text).is_none() {
                return Err(invalid());
            }
            if !layer.contains(&b'%') {
                break;
            }
            let decoded = percent_decode(&layer).ok_or_else(invalid)?;
            if decoded == layer {
                break;
            }
            layer = decoded;
        }
        let resolved = self.resolve_same_origin(input).ok_or_else(invalid)?;
        let mut relative = resolved.path().to_owned();
        if let Some(query) = resolved.query() {
            relative.push('?');
            relative.push_str(query);
        }
        if let Some(fragment) = resolved.fragment() {
            relative.push('#');
            relative.push_str(fragment);
        }
        if !relative.starts_with('/') || relative.starts_with("//") || relative.contains('\\') {
            return Err(invalid());
        }
        Ok(relative)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn validator() -> RedirectValidator {
        RedirectValidator::new(
            vec![
                "https://app.example.com/callback".to_owned(),
                "com.example.app:/oauth/callback".to_owned(),
            ],
            Url::parse("https://auth.example.com").unwrap(),
        )
    }

    #[test]
    fn prt_10_k58_script_and_document_schemes_are_never_redirect_targets() {
        // Defence in depth behind the configuration check: even an
        // allow-listed entry with such a scheme is refused.
        let entries = [
            "javascript:alert(document.cookie)",
            "JAVASCRIPT:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "blob:https://app.example.com/0d1e",
            "about:blank",
        ];
        let v = RedirectValidator::new(
            entries.iter().map(|e| (*e).to_owned()).collect(),
            Url::parse("https://auth.example.com").unwrap(),
        );
        for entry in entries {
            assert!(v.validate(entry).is_err(), "{entry}");
            assert!(!v.is_allow_listed(entry), "{entry}");
        }
    }

    #[test]
    fn prt_10_allow_listed_absolute_urls_match_exactly() {
        let v = validator();
        assert_eq!(
            v.validate("https://app.example.com/callback").unwrap(),
            RedirectTarget::Absolute("https://app.example.com/callback".to_owned())
        );
        assert_eq!(
            v.validate("com.example.app:/oauth/callback")
                .unwrap()
                .as_str(),
            "com.example.app:/oauth/callback"
        );
        for near_miss in [
            "https://app.example.com/callback/",
            "https://app.example.com/callback?x=1",
            "https://app.example.com/callback#x",
            "https://APP.example.com/callback",
            "HTTPS://app.example.com/callback",
            "https://app.example.com:443/callback",
            "http://app.example.com/callback",
            "https://app.example.com/Callback",
            "https://app.example.com/callback/../callback",
            "https://app.example.com.evil.com/callback",
            "https://app.example.com@evil.com/callback",
            "https://evil.com/https://app.example.com/callback",
            "https://evil.com#https://app.example.com/callback",
            "com.example.app:/oauth/callback2",
        ] {
            assert!(v.validate(near_miss).is_err(), "{near_miss}");
        }
    }

    #[test]
    fn prt_10_safe_relative_paths_are_accepted_and_normalised() {
        let v = validator();
        for (input, expected) in [
            ("/", "/"),
            ("/settings", "/settings"),
            ("/settings?tab=security#mfa", "/settings?tab=security#mfa"),
            ("/a/./b/../c", "/a/c"),
            ("/%C3%BCr%C3%BCn", "/%C3%BCr%C3%BCn"),
            ("/@evil.com", "/@evil.com"),
            ("/.evil.com", "/.evil.com"),
            ("/?next=//evil.com", "/?next=//evil.com"),
            ("/%2e%2e/x", "/x"),
        ] {
            assert_eq!(
                v.validate(input).unwrap(),
                RedirectTarget::Relative(expected.to_owned()),
                "{input}"
            );
        }
    }

    #[test]
    fn prt_10_open_redirect_tricks_are_rejected() {
        let v = validator();
        for attack in [
            "",
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "/\\evil.com",
            "\\\\evil.com",
            "\\/evil.com",
            "/\\/evil.com",
            "/%2F%2Fevil.com",
            "/%2f/evil.com",
            "%2F%2Fevil.com",
            "/%252F%252Fevil.com",
            "/%25252F%25252Fevil.com",
            "/%5Cevil.com",
            "/%5cevil.com",
            "/%09/evil.com",
            "/%0a/evil.com",
            "/%00",
            "/%zz",
            "/%2",
            "/a/../..//evil.com",
            "/.//evil.com",
            "https://evil.com",
            "http://evil.com",
            "//evil.com/%2F..",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox",
            "evil.com",
            "?next=x",
            "#x",
            " /settings",
            "/settings ",
            "\t/settings",
            "/\t/evil.com",
            "/\n/evil.com",
            "/\r\n/evil.com",
            "/settings\u{0}",
            "/\u{FF0F}\u{FF0F}evil.com",
            "/%EF%BC%8F%EF%BC%8Fevil.com",
            "/%EF%BC%BCevil.com",
            "/\u{2215}evil.com",
            "/ürün",
            "/%C0%AF",
            "/%FF",
            "/%2e%2e%2f%2fevil.com",
            "/%2E%2E/%2F/evil.com",
            "/x/%2e%2e%2f%2e%2e%2f%2fevil.com",
        ] {
            let err = v.validate(attack).unwrap_err();
            assert_eq!(err.code(), codes::protect::INVALID_REDIRECT, "{attack:?}");
        }
        assert!(
            v.validate(&format!("/{}", "a".repeat(MAX_REDIRECT_LEN)))
                .is_err()
        );
    }

    proptest! {
        /// Whatever the input, an accepted relative target resolves to the
        /// server's own origin, and an accepted absolute target is an
        /// allow-list entry (TST-02 open redirect).
        #[test]
        fn prt_10_accepted_targets_never_leave_the_allow_list(input in "\\PC{0,64}") {
            let v = validator();
            if let Ok(target) = v.validate(&input) {
                match target {
                    RedirectTarget::Absolute(s) => {
                        prop_assert!(v.allow_list.contains(&s));
                    }
                    RedirectTarget::Relative(s) => {
                        prop_assert!(s.starts_with('/') && !s.starts_with("//"));
                        let resolved = v.base.join(&s).unwrap();
                        prop_assert_eq!(resolved.origin(), v.base.origin());
                    }
                }
            }
        }

        #[test]
        fn prt_10_slash_prefixed_ascii_paths_are_handled(path in "/[ -~]{0,40}") {
            let v = validator();
            if let Ok(RedirectTarget::Relative(s)) = v.validate(&path) {
                prop_assert!(!s.starts_with("//"));
                prop_assert!(!s.contains('\\'));
            }
        }
    }
}
