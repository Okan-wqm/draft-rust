//! JSON body extractor for requests that carry passwords, codes or link
//! tokens.
//!
//! `authn_core::http::Json` keeps the parser message of a rejected body in
//! the (logged) error context; serde's messages can quote the offending
//! *value* (``invalid type: integer `12345678`, expected a string``). For
//! bodies with secrets that would put a password or token into the logs,
//! so this extractor logs only the error category and position.

use authn_core::error::{AuthError, codes};
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use http::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;
use serde_json::error::Category;

/// Body extractor whose rejections never echo body content.
///
/// Missing / non-JSON `Content-Type` → `unsupported_media_type` (415);
/// unreadable or too large body → matching status; syntax error →
/// `bad_request` (400); wrong types, missing or unknown fields →
/// `validation_failed` (422).
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
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    kind == "application"
        && (subtype == "json" || (subtype.len() > 5 && subtype.ends_with("+json")))
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn acc_01_content_type_detection() {
        for ok in [
            "application/json",
            "Application/JSON; charset=utf-8",
            "application/problem+json",
        ] {
            assert!(
                is_json_content_type(Some(&HeaderValue::from_static(ok))),
                "{ok}"
            );
        }
        for bad in [
            "text/plain",
            "application/+json",
            "json",
            "application/jsonp",
        ] {
            assert!(
                !is_json_content_type(Some(&HeaderValue::from_static(bad))),
                "{bad}"
            );
        }
        assert!(!is_json_content_type(None));
    }
}
