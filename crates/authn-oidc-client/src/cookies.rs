//! The browser-binding cookie of the web flow (SOC-02, login CSRF).
//!
//! `GET /v1/oauth/{provider}/start` stores only `SHA-256(binding)` with the
//! state; the binding itself goes to the browser as
//! `__Host-authn_oauth` (`HttpOnly; Secure; Path=/`, no `Domain`, so a
//! sibling sub-domain cannot set or overwrite it). The callback is accepted
//! only from the browser that presents the binding: a callback URL carrying
//! an attacker's `state` and `code` (login CSRF / session swapping) fails in
//! the victim's browser.
//!
//! `SameSite=None` is required because Apple returns with a cross-site
//! `POST` (`response_mode=form_post`), on which `Lax` cookies are not sent;
//! the cookie grants nothing by itself (it is useless without the matching
//! single-use `state`). Several concurrent flows in one browser share one
//! binding value (an existing well-formed cookie is reused).

use std::time::Duration;

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};

/// Cookie name.
pub const BINDING_COOKIE: &str = "__Host-authn_oauth";

/// Longest cookie header inspected (bytes).
const MAX_COOKIE_HEADER_BYTES: usize = 8 * 1024;
/// Most cookie pairs inspected per header.
const MAX_COOKIE_PAIRS: usize = 64;

/// Reads the binding cookie. Several *different* values (cookie tossing)
/// count as absent.
#[must_use]
pub fn read_binding(headers: &HeaderMap) -> Option<String> {
    let mut found: Option<String> = None;
    for header in headers.get_all(COOKIE) {
        if header.len() > MAX_COOKIE_HEADER_BYTES {
            continue;
        }
        let Ok(text) = header.to_str() else {
            continue;
        };
        for pair in text.split(';').take(MAX_COOKIE_PAIRS) {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key != BINDING_COOKIE {
                continue;
            }
            match &found {
                None => found = Some(value.to_owned()),
                Some(existing) if existing == value => {}
                Some(_) => return None,
            }
        }
    }
    found
}

/// `Set-Cookie` value for the binding (base64url token, no escaping
/// needed).
#[must_use]
pub fn binding_cookie(value: &str, max_age: Duration) -> Option<HeaderValue> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    HeaderValue::from_str(&format!(
        "{BINDING_COOKIE}={value}; Max-Age={}; Path=/; Secure; HttpOnly; SameSite=None",
        max_age.as_secs()
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_02_binding_cookie_attributes() {
        let cookie = binding_cookie("abc_DEF-123", Duration::from_secs(600)).unwrap();
        let text = cookie.to_str().unwrap();
        assert!(text.starts_with("__Host-authn_oauth=abc_DEF-123;"));
        for attr in [
            "Max-Age=600",
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=None",
        ] {
            assert!(text.contains(attr), "{attr} missing: {text}");
        }
        assert!(!text.contains("Domain"));
        assert!(binding_cookie("a;b", Duration::from_secs(1)).is_none());
        assert!(binding_cookie("", Duration::from_secs(1)).is_none());
    }

    #[test]
    fn soc_02_tossed_binding_cookies_are_ignored() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("a=1; __Host-authn_oauth=x"),
        );
        assert_eq!(read_binding(&headers).as_deref(), Some("x"));
        headers.append(COOKIE, HeaderValue::from_static("__Host-authn_oauth=y"));
        assert_eq!(read_binding(&headers), None);
    }
}
