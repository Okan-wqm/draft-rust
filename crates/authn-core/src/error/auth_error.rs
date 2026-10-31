//! [`AuthError`] and the JSON error envelope.

use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};

use crate::domain::Locale;
use crate::error::ErrorCode;
use crate::error::codes::common;
use crate::id::RequestId;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The error type of the whole workspace.
///
/// What the client sees: `code`, the localized message, the request id,
/// optional `details` and (for 429/503) a `Retry-After` header.
/// What only the logs see: `context` and the `source` chain.
///
/// The payload is boxed so `Result<T, AuthError>` stays pointer-sized.
pub struct AuthError(Box<Inner>);

struct Inner {
    code: ErrorCode,
    retry_after: Option<Duration>,
    details: Option<serde_json::Value>,
    context: Option<Cow<'static, str>>,
    source: Option<BoxError>,
}

impl AuthError {
    /// An error with the given registry code.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self(Box::new(Inner {
            code,
            retry_after: None,
            details: None,
            context: None,
            source: None,
        }))
    }

    /// An `internal_error` with an internal (logged-only) description.
    #[must_use]
    pub fn internal(context: impl Into<Cow<'static, str>>) -> Self {
        Self::new(common::INTERNAL_ERROR).with_context(context)
    }

    /// Attaches an underlying error (logged, never rendered).
    #[must_use]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.0.source = Some(Box::new(source));
        self
    }

    /// Attaches an internal description (logged, never rendered). Must not
    /// contain secrets or personal data.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<Cow<'static, str>>) -> Self {
        self.0.context = Some(context.into());
        self
    }

    /// Sets `Retry-After` (PRT-04). Rounded up to whole seconds, minimum 1.
    #[must_use]
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.0.retry_after = Some(retry_after);
        self
    }

    /// Adds client-visible structured details (e.g. password policy
    /// violations). Only put data here that is safe to show to an
    /// unauthenticated attacker; never anything that reveals account
    /// existence.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.0.details = Some(details);
        self
    }

    /// The registry code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.0.code
    }

    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.0.code.status()
    }

    /// Whether this error carries the given code.
    #[must_use]
    pub fn is(&self, code: ErrorCode) -> bool {
        self.0.code == code
    }

    /// `Retry-After`, if any.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.0.retry_after
    }

    /// Client-visible details, if any.
    #[must_use]
    pub fn details(&self) -> Option<&serde_json::Value> {
        self.0.details.as_ref()
    }

    /// Internal context, if any.
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.0.context.as_deref()
    }

    /// Renders the envelope in the given locale. Normally called by
    /// [`IntoResponse`] (default locale) and re-rendered by the request
    /// context middleware with the negotiated locale and request id.
    #[must_use]
    pub fn render(&self, locale: Locale, request_id: Option<RequestId>) -> Response {
        let mut response = render_envelope(self.0.code, self.0.details.clone(), locale, request_id);
        if let Some(retry_after) = self.0.retry_after {
            let secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
            if let Ok(value) = HeaderValue::from_str(&secs.max(1).to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }

    fn log(&self) {
        let chain = SourceChain(self.0.source.as_deref());
        if self.0.code.is_server_error() {
            tracing::error!(
                error.code = self.0.code.code(),
                error.context = self.0.context.as_deref().unwrap_or(""),
                error.source = %chain,
                "request failed with server error"
            );
        } else {
            tracing::debug!(
                error.code = self.0.code.code(),
                error.context = self.0.context.as_deref().unwrap_or(""),
                error.source = %chain,
                "request rejected"
            );
        }
    }
}

/// Renders the envelope for a code (also used for foreign error responses).
pub(crate) fn render_envelope(
    code: ErrorCode,
    details: Option<serde_json::Value>,
    locale: Locale,
    request_id: Option<RequestId>,
) -> Response {
    let body = ErrorEnvelope {
        error: ErrorBody {
            code: code.code().to_owned(),
            message: code.message(locale).to_owned(),
            request_id: request_id.map(|id| id.to_string()),
            details: details.clone(),
        },
    };
    let mut response = (code.status(), Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .extensions_mut()
        .insert(RenderedError { code, details });
    response
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        self.log();
        self.render(Locale::En, None)
    }
}

impl fmt::Debug for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthError")
            .field("code", &self.0.code.code())
            .field("status", &self.0.code.status().as_u16())
            .field("context", &self.0.context)
            .field("source", &SourceChain(self.0.source.as_deref()).to_string())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.code.code())?;
        if let Some(context) = &self.0.context {
            write!(f, ": {context}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<ErrorCode> for AuthError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

/// Database errors are internal by default. Code that must react to a
/// specific database condition (unique violation…) classifies the
/// `sqlx::Error` *before* converting it (see `authn_store::error`).
impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::PoolTimedOut => Self::new(common::SERVICE_UNAVAILABLE)
                .with_context("database pool timed out")
                .with_source(err),
            other => Self::internal("database error").with_source(other),
        }
    }
}

struct SourceChain<'a>(Option<&'a (dyn std::error::Error + Send + Sync + 'static)>);

impl fmt::Display for SourceChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut current: Option<&(dyn std::error::Error + 'static)> =
            self.0.map(|e| e as &(dyn std::error::Error + 'static));
        let mut first = true;
        let mut depth = 0;
        while let Some(err) = current {
            if depth >= 8 {
                f.write_str(": …")?;
                break;
            }
            if !first {
                f.write_str(": ")?;
            }
            write!(f, "{err}")?;
            first = false;
            depth += 1;
            current = err.source();
        }
        Ok(())
    }
}

/// The JSON error envelope (ARC-08).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorEnvelope {
    /// The error.
    pub error: ErrorBody,
}

/// Body of the error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// Stable snake_case error code.
    pub code: String,
    /// Localized, user-safe message.
    pub message: String,
    /// Request id, also sent as the `x-request-id` header.
    pub request_id: Option<String>,
    /// Optional structured, user-safe details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Response extension attached to every rendered error so the request
/// context middleware can re-render it in the negotiated locale.
#[derive(Debug, Clone)]
pub struct RenderedError {
    /// The code that was rendered.
    pub code: ErrorCode,
    /// Details that were rendered.
    pub details: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;
    use crate::error::codes;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn arc_08_envelope_shape_and_locale() {
        let request_id = RequestId::generate();
        let err = AuthError::new(codes::session::INVALID_CREDENTIALS);
        let response = err.render(Locale::Tr, Some(request_id));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let json = body_json(response).await;
        assert_eq!(
            json,
            serde_json::json!({
                "error": {
                    "code": "invalid_credentials",
                    "message": "Giriş bilgileri hatalı.",
                    "request_id": request_id.to_string(),
                }
            })
        );
    }

    #[tokio::test]
    async fn arc_08_internal_details_never_rendered() {
        let io = std::io::Error::other("connection to 10.0.0.5:5432 refused; password=hunter2");
        let err = AuthError::internal("loading user row for alice@example.com").with_source(io);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let text = body_json(response).await.to_string();
        assert!(text.contains("internal_error"));
        for leaked in ["10.0.0.5", "hunter2", "alice", "loading user row"] {
            assert!(!text.contains(leaked), "leaked {leaked}");
        }
    }

    #[tokio::test]
    async fn prt_04_retry_after_is_rounded_up() {
        let err = AuthError::new(codes::common::RATE_LIMITED)
            .with_retry_after(Duration::from_millis(1_500));
        let response = err.render(Locale::En, None);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "2");
        let err = AuthError::new(codes::common::RATE_LIMITED).with_retry_after(Duration::ZERO);
        let response = err.render(Locale::En, None);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }

    #[tokio::test]
    async fn arc_08_details_are_rendered_when_set() {
        let err = AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(serde_json::json!({"fields": ["email"]}));
        let json = body_json(err.render(Locale::En, None)).await;
        assert_eq!(json["error"]["details"]["fields"][0], "email");
        assert_eq!(json["error"]["request_id"], serde_json::Value::Null);
    }

    #[test]
    fn arc_08_debug_and_display_show_internal_context_for_logs() {
        let err = AuthError::internal("ctx").with_source(std::io::Error::other("inner"));
        assert_eq!(err.to_string(), "internal_error: ctx");
        let debug = format!("{err:?}");
        assert!(debug.contains("inner") && debug.contains("ctx"));
        assert!(err.is(codes::common::INTERNAL_ERROR));
    }

    #[test]
    fn sqlx_errors_map_to_internal_or_unavailable() {
        let err = AuthError::from(sqlx::Error::RowNotFound);
        assert_eq!(err.code(), codes::common::INTERNAL_ERROR);
        let err = AuthError::from(sqlx::Error::PoolTimedOut);
        assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
    }
}
