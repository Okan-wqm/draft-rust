//! The browser-binding cookie of pending authorization requests (OIDP-04).
//!
//! `GET /v1/oauth2/authorize` stores only `SHA-256(binding)` with the
//! interaction; the binding goes to the browser as
//! `__Host-authn_oidc_browser` (`HttpOnly; Secure; Path=/; SameSite=Lax`,
//! no `Domain`). The interaction endpoints answer only to the browser that
//! presents it, so an interaction id sent to someone else (consent
//! phishing with a request the attacker started) is useless. `Lax` is
//! enough: the cookie is set on the top-level navigation from the client
//! and read by same-site requests of the login / consent page; a
//! cross-site `POST` never carries it. Several concurrent requests in one
//! browser share one value (an existing well-formed cookie is reused).

use std::time::Duration;

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};

/// Cookie name.
pub const BROWSER_COOKIE: &str = "__Host-authn_oidc_browser";

const MAX_COOKIE_HEADER_BYTES: usize = 8 * 1024;
const MAX_COOKIE_PAIRS: usize = 64;

/// Reads the binding cookie. Several *different* values (cookie tossing)
/// count as absent.
#[must_use]
pub fn read_browser_binding(headers: &HeaderMap) -> Option<String> {
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
            if key != BROWSER_COOKIE {
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

/// `Set-Cookie` value of the binding (base64url token).
#[must_use]
pub fn browser_cookie(value: &str, max_age: Duration) -> Option<HeaderValue> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    HeaderValue::from_str(&format!(
        "{BROWSER_COOKIE}={value}; Max-Age={}; Path=/; Secure; HttpOnly; SameSite=Lax",
        max_age.as_secs()
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidp_04_cookie_tossing_counts_as_absent() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("__Host-authn_oidc_browser=a; other=1"),
        );
        assert_eq!(read_browser_binding(&headers).as_deref(), Some("a"));
        headers.append(
            COOKIE,
            HeaderValue::from_static("__Host-authn_oidc_browser=b"),
        );
        assert_eq!(read_browser_binding(&headers), None);
    }

    #[test]
    fn oidp_04_cookie_attributes() {
        let value = browser_cookie("abc_DEF-1", Duration::from_secs(600)).unwrap();
        let text = value.to_str().unwrap();
        for attr in [
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Path=/",
            "Max-Age=600",
        ] {
            assert!(text.contains(attr), "{text}");
        }
        assert!(!text.contains("Domain"));
        assert!(browser_cookie("a;b", Duration::from_secs(1)).is_none());
    }
}
