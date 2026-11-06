//! OAuth protocol error responses (RFC 6749 §5.2, RFC 6750 §3, RFC 7009
//! §2.2.1, RFC 7662 §2.3).
//!
//! The token-family endpoints answer `{"error": "...", "error_description":
//! "..."}` — the format relying-party libraries parse — instead of the
//! project envelope. Descriptions are fixed English strings; they never
//! echo input or reveal internal state. Server-side failures stay
//! [`AuthError`]s (`internal_error` envelope, details only in the log).

use authn_core::error::AuthError;
use axum::http::header::{CACHE_CONTROL, PRAGMA, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// A protocol error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    status: StatusCode,
    error: &'static str,
    description: &'static str,
    www_authenticate: Option<&'static str>,
    /// Internal reason (logged, never sent).
    reason: &'static str,
}

#[derive(Serialize)]
struct Body {
    error: &'static str,
    error_description: &'static str,
}

impl OAuthError {
    fn new(status: StatusCode, error: &'static str, description: &'static str) -> Self {
        Self {
            status,
            error,
            description,
            www_authenticate: None,
            reason: error,
        }
    }

    /// `invalid_request` (400).
    #[must_use]
    pub fn invalid_request(description: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    /// `invalid_client` (401). `basic`: the client used HTTP Basic, so the
    /// response carries `WWW-Authenticate: Basic` (RFC 6749 §5.2).
    #[must_use]
    pub fn invalid_client(basic: bool) -> Self {
        let mut err = Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
        if basic {
            err.www_authenticate = Some("Basic realm=\"oauth2\"");
        }
        err
    }

    /// `invalid_grant` (400) with an internal `reason` for the log.
    #[must_use]
    pub fn invalid_grant(reason: &'static str) -> Self {
        let mut err = Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the authorization grant is invalid, expired or revoked",
        );
        err.reason = reason;
        err
    }

    /// `unauthorized_client` (400).
    #[must_use]
    pub fn unauthorized_client() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client may not use this grant type",
        )
    }

    /// `unsupported_grant_type` (400).
    #[must_use]
    pub fn unsupported_grant_type() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "the grant type is not supported",
        )
    }

    /// `invalid_scope` (400).
    #[must_use]
    pub fn invalid_scope() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "the requested scope exceeds the grant",
        )
    }

    /// `invalid_token` (401, RFC 6750) with `WWW-Authenticate: Bearer`.
    #[must_use]
    pub fn invalid_token(reason: &'static str) -> Self {
        let mut err = Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "the access token is invalid, expired or revoked",
        );
        err.www_authenticate = Some("Bearer error=\"invalid_token\"");
        err.reason = reason;
        err
    }

    /// No bearer token at all (401, RFC 6750 §3.1: no error code).
    #[must_use]
    pub fn missing_token() -> Self {
        let mut err = Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_request",
            "a bearer access token is required",
        );
        err.www_authenticate = Some("Bearer");
        err
    }

    /// `insufficient_scope` (403, RFC 6750).
    #[must_use]
    pub fn insufficient_scope() -> Self {
        let mut err = Self::new(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "the access token lacks the openid scope",
        );
        err.www_authenticate = Some("Bearer error=\"insufficient_scope\", scope=\"openid\"");
        err
    }

    /// The wire error code.
    #[must_use]
    pub fn error(&self) -> &'static str {
        self.error
    }

    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The internal reason.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        tracing::info!(
            error = self.error,
            reason = self.reason,
            "oauth protocol request refused"
        );
        let mut response = (
            self.status,
            axum::Json(Body {
                error: self.error,
                error_description: self.description,
            }),
        )
            .into_response();
        let headers = response.headers_mut();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        if let Some(value) = self.www_authenticate {
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static(value));
        }
        response
    }
}

/// The result type of protocol handlers: a protocol error or an internal
/// failure.
#[derive(Debug)]
pub enum ProtocolError {
    /// RFC 6749 error.
    OAuth(OAuthError),
    /// Internal / rate limit: the project envelope.
    Internal(AuthError),
}

impl From<OAuthError> for ProtocolError {
    fn from(err: OAuthError) -> Self {
        Self::OAuth(err)
    }
}

impl From<AuthError> for ProtocolError {
    fn from(err: AuthError) -> Self {
        Self::Internal(err)
    }
}

impl From<sqlx::Error> for ProtocolError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(err.into())
    }
}

impl IntoResponse for ProtocolError {
    fn into_response(self) -> Response {
        match self {
            Self::OAuth(err) => err.into_response(),
            Self::Internal(err) => err.into_response(),
        }
    }
}
