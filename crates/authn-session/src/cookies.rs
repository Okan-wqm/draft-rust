//! Cookies of the web session (SES-03, SES-04, SES-07).
//!
//! Every cookie uses the `__Host-` prefix: the browser accepts it only with
//! `Secure`, `Path=/` and without `Domain`, so a sibling sub-domain can
//! neither set nor overwrite it (cookie tossing / session fixation).
//! Values are always base64url (or the validated device id alphabet), so no
//! quoting or escaping is ever needed.

use std::time::Duration;

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};

/// The opaque web session token (SES-03).
pub const SESSION_COOKIE: &str = "__Host-authn_session";
/// The pre-session secret behind login-CSRF tokens (SES-04).
pub const PRE_SESSION_COOKIE: &str = "__Host-authn_csrf";
/// The device id cookie read by the request context (risk, known devices).
pub const DEVICE_COOKIE: &str = authn_core::http::DEVICE_ID_COOKIE;
/// Token of a pending login challenge for web clients (SES-02;
/// `SameSite=Strict`, lifetime of the challenge). Keeping it out of the
/// response body binds the challenge to the browser that started it.
pub const CHALLENGE_COOKIE: &str = "__Host-authn_challenge";
/// Binding token of a passkey step-up ceremony (`SameSite=Strict`, short
/// lived; PKY-01).
pub const PASSKEY_BINDING_COOKIE: &str = "__Host-authn_passkey";

/// Longest cookie header inspected (bytes); longer headers are ignored.
const MAX_COOKIE_HEADER_BYTES: usize = 8 * 1024;
/// Most cookie pairs inspected per header.
const MAX_COOKIE_PAIRS: usize = 64;
/// Lifetime of the device id cookie (browsers cap at 400 days).
pub const DEVICE_COOKIE_MAX_AGE: Duration = Duration::from_secs(365 * 86_400);

/// What a request presents for one cookie name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieValue {
    /// Not present.
    Absent,
    /// Exactly one distinct value.
    One(String),
    /// Several different values (cookie tossing): treated as absent by
    /// callers, never guessed.
    Ambiguous,
}

/// Reads the cookie `name` from every `Cookie` header.
#[must_use]
pub fn read_cookie(headers: &HeaderMap, name: &str) -> CookieValue {
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
            if key != name {
                continue;
            }
            match &found {
                None => found = Some(value.to_owned()),
                Some(existing) if existing == value => {}
                Some(_) => return CookieValue::Ambiguous,
            }
        }
    }
    found.map_or(CookieValue::Absent, CookieValue::One)
}

/// Whether `value` may be written into a cookie unquoted (base64url /
/// device-id alphabet only).
fn is_cookie_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn build(name: &str, value: &str, same_site: &str, max_age: Option<Duration>) -> HeaderValue {
    let value = if is_cookie_safe(value) { value } else { "" };
    let mut cookie = format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite={same_site}");
    if let Some(max_age) = max_age {
        cookie.push_str(&format!("; Max-Age={}", max_age.as_secs()));
    }
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// `Set-Cookie` for the session token (SES-03): `HttpOnly; Secure;
/// SameSite=Lax; Path=/`. `persistent_for = None` is a browser-session
/// cookie (normal and "not my device" sessions, SES-07); `Some` only for
/// "remember me" (`Max-Age` = remaining absolute lifetime).
#[must_use]
pub fn session_cookie(token: &str, persistent_for: Option<Duration>) -> HeaderValue {
    build(SESSION_COOKIE, token, "Lax", persistent_for)
}

/// `Set-Cookie` deleting the session cookie.
#[must_use]
pub fn clear_session_cookie() -> HeaderValue {
    build_clear(SESSION_COOKIE, "Lax")
}

/// `Set-Cookie` for the pre-session secret (login CSRF, SES-04):
/// `SameSite=Strict`, browser-session cookie.
#[must_use]
pub fn pre_session_cookie(secret: &str) -> HeaderValue {
    build(PRE_SESSION_COOKIE, secret, "Strict", None)
}

/// `Set-Cookie` deleting the pre-session cookie (after a login).
#[must_use]
pub fn clear_pre_session_cookie() -> HeaderValue {
    build_clear(PRE_SESSION_COOKIE, "Strict")
}

/// `Set-Cookie` for a new device id (`SameSite=Lax`, one year).
#[must_use]
pub fn device_cookie(device_id: &str) -> HeaderValue {
    build(DEVICE_COOKIE, device_id, "Lax", Some(DEVICE_COOKIE_MAX_AGE))
}

/// `Set-Cookie` for the passkey step-up binding token (`SameSite=Strict`).
#[must_use]
pub fn passkey_binding_cookie(token: &str, max_age: Duration) -> HeaderValue {
    build(PASSKEY_BINDING_COOKIE, token, "Strict", Some(max_age))
}

/// `Set-Cookie` for a pending login challenge (`SameSite=Strict`).
#[must_use]
pub fn challenge_cookie(token: &str, max_age: Duration) -> HeaderValue {
    build(CHALLENGE_COOKIE, token, "Strict", Some(max_age))
}

/// `Set-Cookie` deleting the challenge cookie.
#[must_use]
pub fn clear_challenge_cookie() -> HeaderValue {
    build_clear(CHALLENGE_COOKIE, "Strict")
}

/// `Set-Cookie` deleting the passkey binding cookie.
#[must_use]
pub fn clear_passkey_binding_cookie() -> HeaderValue {
    build_clear(PASSKEY_BINDING_COOKIE, "Strict")
}

fn build_clear(name: &str, same_site: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}=; Path=/; Secure; HttpOnly; SameSite={same_site}; Max-Age=0"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for v in values {
            map.append(COOKIE, HeaderValue::from_str(v).unwrap());
        }
        map
    }

    #[test]
    fn ses_03_session_cookie_attributes() {
        let cookie = session_cookie("abc", None);
        assert_eq!(
            cookie.to_str().unwrap(),
            "__Host-authn_session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
        let persistent = session_cookie("abc", Some(Duration::from_secs(60)));
        assert!(persistent.to_str().unwrap().ends_with("; Max-Age=60"));
        let cleared = clear_session_cookie();
        assert!(cleared.to_str().unwrap().contains("Max-Age=0"));
        assert!(!cleared.to_str().unwrap().contains("Domain"));
    }

    #[test]
    fn ses_03_unsafe_values_are_never_written() {
        let cookie = session_cookie("a;b=c", None);
        assert!(
            cookie
                .to_str()
                .unwrap()
                .starts_with("__Host-authn_session=;")
        );
    }

    #[test]
    fn ses_03_cookie_tossing_is_ambiguous() {
        assert_eq!(
            read_cookie(&headers(&["a=1; __Host-authn_session=x"]), SESSION_COOKIE),
            CookieValue::One("x".into())
        );
        assert_eq!(
            read_cookie(
                &headers(&["__Host-authn_session=x", "__Host-authn_session=x"]),
                SESSION_COOKIE
            ),
            CookieValue::One("x".into())
        );
        assert_eq!(
            read_cookie(
                &headers(&["__Host-authn_session=x; __Host-authn_session=y"]),
                SESSION_COOKIE
            ),
            CookieValue::Ambiguous
        );
        assert_eq!(
            read_cookie(&headers(&[]), SESSION_COOKIE),
            CookieValue::Absent
        );
        assert_eq!(
            read_cookie(&headers(&["authn_session=x"]), SESSION_COOKIE),
            CookieValue::Absent
        );
    }
}
