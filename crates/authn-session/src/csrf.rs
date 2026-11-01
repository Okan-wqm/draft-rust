//! CSRF protection of cookie sessions (SES-04).
//!
//! Two independent checks on every state-changing request that is
//! authenticated by the session cookie:
//!
//! 1. **Origin:** the `Origin` header must be one of the allowed origins
//!    (`server.public_base_url` + `session.csrf_allowed_origins`, exact
//!    match). Without `Origin`, `Sec-Fetch-Site: same-origin` is accepted;
//!    without both the request is refused (every current browser sends
//!    `Origin` on non-GET requests, so only non-browser clients lack both,
//!    and those do not need cookies).
//! 2. **Synchronizer token:** `X-CSRF-Token` must equal
//!    `base64url(HMAC(K_csrf, "session" ‖ session id ‖ SHA-256(session token)))`.
//!    The key is the HKDF purpose key `CsrfToken` (CRY-11); the token is
//!    bound to the session *and* to its current token, so rotating the
//!    session (login, MFA, organization switch, step-up) invalidates it.
//!
//! **Login CSRF:** before a session exists, the login form is protected by
//! a *pre-session*: a random secret in the `__Host-authn_csrf` cookie
//! (`SameSite=Strict`) and the token
//! `base64url(HMAC(K_csrf, "pre-session" ‖ SHA-256(secret)))`. Web login
//! handlers call [`crate::SessionService::verify_login_csrf`], whose
//! [`LoginCsrfVerified`] proof is required to establish a web session.

use authn_core::error::{AuthError, codes};
use authn_core::id::SessionId;
use authn_crypto::kdf::{KeyPurpose, KeyRing};
use authn_crypto::token::{OpaqueToken, TokenHash};
use axum::http::header::ORIGIN;
use axum::http::{HeaderMap, HeaderName, Method};
use data_encoding::BASE64URL_NOPAD;

use crate::cookies::{CookieValue, PRE_SESSION_COOKIE, read_cookie};

/// Header carrying the synchronizer token.
pub const CSRF_HEADER: HeaderName = HeaderName::from_static("x-csrf-token");
/// Fetch-metadata header (`same-origin`, `same-site`, `cross-site`, `none`).
pub const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

const SESSION_LABEL: &[u8] = b"authn-session/csrf/session/v1";
const PRE_SESSION_LABEL: &[u8] = b"authn-session/csrf/pre-session/v1";
/// Length of an encoded token (32-byte HMAC, base64url without padding).
const TOKEN_LEN: usize = 43;

/// Proof that a web login request passed the login-CSRF checks (origin +
/// pre-session token). Only [`CsrfProtector::verify_login`] and the
/// federated-login path of this crate (protected by the OAuth `state` /
/// PKCE binding of authn-oidc-client instead) can create one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginCsrfVerified {
    _private: (),
}

impl LoginCsrfVerified {
    /// Federated callbacks are top-level redirects from the identity
    /// provider: their CSRF protection is the server-side `state` bound to
    /// the browser (SOC-02).
    pub(crate) const fn federated() -> Self {
        Self { _private: () }
    }

    /// A signed-in browser's state-changing request that already passed the
    /// session CSRF checks of the middleware.
    pub(crate) const fn session_checked() -> Self {
        Self { _private: () }
    }
}

/// Whether the method changes state (everything except GET, HEAD, OPTIONS
/// and TRACE).
#[must_use]
pub fn is_state_changing(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Computes and checks CSRF tokens and origins.
#[derive(Clone)]
pub struct CsrfProtector {
    keys: KeyRing,
    allowed_origins: Vec<String>,
}

impl std::fmt::Debug for CsrfProtector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrfProtector")
            .field("allowed_origins", &self.allowed_origins)
            .finish_non_exhaustive()
    }
}

fn failed(context: &'static str) -> AuthError {
    AuthError::new(codes::session::CSRF_FAILED).with_context(context)
}

impl CsrfProtector {
    /// A protector over the purpose keys and the allowed origins.
    #[must_use]
    pub fn new(keys: KeyRing, allowed_origins: Vec<String>) -> Self {
        Self {
            keys,
            allowed_origins,
        }
    }

    fn tag(&self, fields: &[&[u8]]) -> Result<[u8; 32], AuthError> {
        let key = self
            .keys
            .key(KeyPurpose::CsrfToken)
            .map_err(|e| AuthError::internal("csrf key unavailable").with_source(e))?;
        Ok(key.sign_fields(fields))
    }

    /// The synchronizer token of a session (SES-04).
    pub fn session_token(
        &self,
        session: SessionId,
        token_hash: &TokenHash,
    ) -> Result<String, AuthError> {
        let id = session.as_uuid();
        let tag = self.tag(&[SESSION_LABEL, id.as_bytes(), token_hash.as_bytes()])?;
        Ok(BASE64URL_NOPAD.encode(&tag))
    }

    /// The login-CSRF token of a pre-session secret.
    pub fn pre_session_token(&self, secret: &OpaqueToken) -> Result<String, AuthError> {
        let tag = self.tag(&[PRE_SESSION_LABEL, secret.hash().as_bytes()])?;
        Ok(BASE64URL_NOPAD.encode(&tag))
    }

    /// Constant-time check of a presented token against the expected one.
    fn token_matches(expected: &str, presented: Option<&str>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        presented.len() == TOKEN_LEN
            && authn_core::secret::constant_time_eq(expected.as_bytes(), presented.as_bytes())
    }

    /// Check 1: `Origin` / `Sec-Fetch-Site`.
    pub fn check_origin(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        let origins: Vec<_> = headers.get_all(ORIGIN).iter().collect();
        match origins.as_slice() {
            [] => {
                let site = headers.get(SEC_FETCH_SITE).and_then(|v| v.to_str().ok());
                if site == Some("same-origin") {
                    Ok(())
                } else {
                    Err(failed("missing Origin and no same-origin fetch metadata"))
                }
            }
            [origin] => {
                let origin = origin.to_str().map_err(|_| failed("unreadable Origin"))?;
                if self.allowed_origins.iter().any(|allowed| allowed == origin) {
                    Ok(())
                } else {
                    Err(failed("Origin not allowed"))
                }
            }
            _ => Err(failed("several Origin headers")),
        }
    }

    fn presented(headers: &HeaderMap) -> Option<&str> {
        let mut values = headers.get_all(CSRF_HEADER).iter();
        let first = values.next()?;
        if values.next().is_some() {
            return None;
        }
        first.to_str().ok()
    }

    /// Both checks for a request authenticated by the session cookie.
    pub fn verify_session_request(
        &self,
        headers: &HeaderMap,
        session: SessionId,
        token_hash: &TokenHash,
    ) -> Result<(), AuthError> {
        self.check_origin(headers)?;
        let expected = self.session_token(session, token_hash)?;
        if Self::token_matches(&expected, Self::presented(headers)) {
            Ok(())
        } else {
            Err(failed("synchronizer token mismatch"))
        }
    }

    /// Both checks for a web login request (login CSRF): origin and the
    /// pre-session token bound to the `__Host-authn_csrf` cookie.
    pub fn verify_login(&self, headers: &HeaderMap) -> Result<LoginCsrfVerified, AuthError> {
        self.check_origin(headers)?;
        let CookieValue::One(secret) = read_cookie(headers, PRE_SESSION_COOKIE) else {
            return Err(failed("missing or ambiguous pre-session cookie"));
        };
        let secret = OpaqueToken::parse(&secret).map_err(|_| failed("malformed pre-session"))?;
        let expected = self.pre_session_token(&secret)?;
        if Self::token_matches(&expected, Self::presented(headers)) {
            Ok(LoginCsrfVerified { _private: () })
        } else {
            Err(failed("pre-session token mismatch"))
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use axum::http::header::COOKIE;

    use super::*;

    fn protector() -> CsrfProtector {
        CsrfProtector::new(
            KeyRing::derive(&[7_u8; 32]).unwrap(),
            vec!["https://auth.test.example".to_owned()],
        )
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn ses_04_origin_check() {
        let p = protector();
        assert!(
            p.check_origin(&headers(&[("origin", "https://auth.test.example")]))
                .is_ok()
        );
        for bad in [
            "https://evil.example",
            "null",
            "https://auth.test.example.evil.example",
            "http://auth.test.example",
        ] {
            assert!(
                p.check_origin(&headers(&[("origin", bad)])).is_err(),
                "{bad}"
            );
        }
        assert!(
            p.check_origin(&headers(&[("sec-fetch-site", "same-origin")]))
                .is_ok()
        );
        assert!(
            p.check_origin(&headers(&[("sec-fetch-site", "same-site")]))
                .is_err()
        );
        assert!(
            p.check_origin(&headers(&[("sec-fetch-site", "cross-site")]))
                .is_err()
        );
        assert!(p.check_origin(&headers(&[])).is_err());
        assert!(
            p.check_origin(&headers(&[
                ("origin", "https://auth.test.example"),
                ("origin", "https://evil.example")
            ]))
            .is_err()
        );
    }

    #[test]
    fn ses_04_session_token_is_bound_to_session_and_token() {
        let p = protector();
        let session = SessionId::generate();
        let hash = OpaqueToken::generate().unwrap().hash();
        let token = p.session_token(session, &hash).unwrap();
        assert_eq!(token.len(), TOKEN_LEN);
        let ok = headers(&[
            ("origin", "https://auth.test.example"),
            ("x-csrf-token", &token),
        ]);
        assert!(p.verify_session_request(&ok, session, &hash).is_ok());
        // Another session or a rotated token does not accept it.
        assert!(
            p.verify_session_request(&ok, SessionId::generate(), &hash)
                .is_err()
        );
        let rotated = OpaqueToken::generate().unwrap().hash();
        assert!(p.verify_session_request(&ok, session, &rotated).is_err());
        // Missing / wrong / duplicated token.
        let missing = headers(&[("origin", "https://auth.test.example")]);
        assert!(p.verify_session_request(&missing, session, &hash).is_err());
        let doubled = headers(&[
            ("origin", "https://auth.test.example"),
            ("x-csrf-token", &token),
            ("x-csrf-token", &token),
        ]);
        assert!(p.verify_session_request(&doubled, session, &hash).is_err());
        // Right token, wrong origin.
        let cross = headers(&[("origin", "https://evil.example"), ("x-csrf-token", &token)]);
        assert!(p.verify_session_request(&cross, session, &hash).is_err());
    }

    #[test]
    fn ses_04_login_csrf_needs_pre_session_cookie_and_token() {
        let p = protector();
        let secret = OpaqueToken::generate().unwrap();
        let token = p.pre_session_token(&secret).unwrap();
        let cookie = format!("{PRE_SESSION_COOKIE}={}", secret.expose());
        let mut ok = headers(&[
            ("origin", "https://auth.test.example"),
            ("x-csrf-token", &token),
        ]);
        ok.append(COOKIE, HeaderValue::from_str(&cookie).unwrap());
        assert!(p.verify_login(&ok).is_ok());
        let no_cookie = headers(&[
            ("origin", "https://auth.test.example"),
            ("x-csrf-token", &token),
        ]);
        assert!(p.verify_login(&no_cookie).is_err());
        let other = OpaqueToken::generate().unwrap();
        let mut wrong = headers(&[
            ("origin", "https://auth.test.example"),
            ("x-csrf-token", &token),
        ]);
        wrong.append(
            COOKIE,
            HeaderValue::from_str(&format!("{PRE_SESSION_COOKIE}={}", other.expose())).unwrap(),
        );
        assert!(p.verify_login(&wrong).is_err());
        // A session token is never a valid login token (separate labels).
        let session_token = p
            .session_token(SessionId::generate(), &secret.hash())
            .unwrap();
        assert_ne!(session_token, token);
    }

    #[test]
    fn ses_04_safe_methods() {
        assert!(!is_state_changing(&Method::GET));
        assert!(!is_state_changing(&Method::HEAD));
        assert!(!is_state_changing(&Method::OPTIONS));
        assert!(is_state_changing(&Method::POST));
        assert!(is_state_changing(&Method::DELETE));
        assert!(is_state_changing(&Method::PATCH));
        assert!(is_state_changing(&Method::PUT));
    }
}
