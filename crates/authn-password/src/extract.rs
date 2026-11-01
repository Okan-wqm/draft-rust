//! JSON body extractor for requests that carry passwords.
//!
//! `authn_core::http::Json` logs the parser message of a rejected body at
//! debug level; serde's messages can quote the offending *value* (e.g.
//! ``invalid type: integer `12345678`, expected a string``). For bodies that
//! contain passwords, codes or reset tokens that is unacceptable (PWD-05:
//! the password is never logged), so this extractor maps rejections to the
//! same standard codes while logging only the error category and position.

use authn_core::error::{AuthError, codes};
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use http::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;
use serde_json::error::Category;

/// Body extractor whose rejections never echo body content.
///
/// Mapping: missing or non-JSON `Content-Type` → `unsupported_media_type`
/// (415); unreadable or too large body → the matching status code; JSON
/// syntax error → `bad_request` (400); wrong types, missing or unknown
/// fields → `validation_failed` (422).
#[derive(Debug, Clone, Copy, Default)]
pub struct SecretJson<T>(pub T);

impl<T, S> FromRequest<S> for SecretJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !is_json_content_type(req.headers().get(CONTENT_TYPE)) {
            return Err(AuthError::new(codes::common::UNSUPPORTED_MEDIA_TYPE));
        }
        let body = Bytes::from_request(req, state).await.map_err(|rejection| {
            AuthError::new(codes::common::for_status(rejection.status()))
                .with_context("request body could not be read")
        })?;
        serde_json::from_slice::<T>(&body).map(Self).map_err(|err| {
            let code = match err.classify() {
                Category::Data => codes::common::VALIDATION_FAILED,
                Category::Syntax | Category::Eof | Category::Io => codes::common::BAD_REQUEST,
            };
            AuthError::new(code).with_context(format!(
                "json body rejected ({:?} error at line {} column {})",
                err.classify(),
                err.line(),
                err.column()
            ))
        })
    }
}

/// `application/json` or `application/<subtype>+json`, parameters allowed.
fn is_json_content_type(value: Option<&http::HeaderValue>) -> bool {
    let Some(value) = value.and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let essence = value.split(';').next().unwrap_or_default().trim();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    kind.eq_ignore_ascii_case("application")
        && (subtype.eq_ignore_ascii_case("json")
            || (subtype.len() > 5
                && subtype
                    .get(subtype.len() - 5..)
                    .is_some_and(|s| s.eq_ignore_ascii_case("+json"))))
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn pwd_05_content_type_detection() {
        let ok = |v: &str| is_json_content_type(Some(&HeaderValue::from_str(v).unwrap()));
        assert!(ok("application/json"));
        assert!(ok("Application/JSON; charset=utf-8"));
        assert!(ok("application/merge-patch+json"));
        assert!(!ok("text/plain"));
        assert!(!ok("application/jsonx"));
        assert!(!ok("application/+json"));
        assert!(!ok("json"));
        assert!(!is_json_content_type(None));
    }
}
