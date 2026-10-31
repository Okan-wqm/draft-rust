//! Extractors whose rejections become standard error envelopes.
//!
//! Handlers use `authn_core::http::Json<T>` (and `Query`, `Path`) instead of
//! the axum originals so that a malformed body never produces axum's plain
//! text rejection (which echoes parser details). Mapping:
//! syntax error → `bad_request` (400), wrong field types / missing fields →
//! `validation_failed` (422), missing `Content-Type: application/json` →
//! `unsupported_media_type` (415), body too large → `payload_too_large` (413).

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{AuthError, codes};

/// JSON body extractor / response with envelope-mapped rejections.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection(&rejection)),
        }
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

fn json_rejection(rejection: &JsonRejection) -> AuthError {
    AuthError::new(codes::common::for_status(rejection.status()))
        .with_context(format!("json rejection: {}", rejection.body_text()))
}

/// Query-string extractor with envelope-mapped rejections.
#[derive(Debug, Clone, Copy, Default)]
pub struct Query<T>(pub T);

impl<T, S> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(query_rejection(&rejection)),
        }
    }
}

fn query_rejection(rejection: &QueryRejection) -> AuthError {
    AuthError::new(codes::common::VALIDATION_FAILED)
        .with_context(format!("query rejection: {}", rejection.body_text()))
}

/// Path-parameter extractor with envelope-mapped rejections. Malformed ids
/// are `bad_request`; *unknown* ids must be answered by the handler with
/// `not_found` (ORG-10).
#[derive(Debug, Clone, Copy, Default)]
pub struct Path<T>(pub T);

impl<T, S> FromRequestParts<S> for Path<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(path_rejection(&rejection)),
        }
    }
}

fn path_rejection(rejection: &PathRejection) -> AuthError {
    let code = if rejection.status().is_server_error() {
        codes::common::INTERNAL_ERROR
    } else {
        codes::common::BAD_REQUEST
    };
    AuthError::new(code).with_context(format!("path rejection: {}", rejection.body_text()))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::{get, post};
    use http::{Method, StatusCode, header};
    use http_body_util::BodyExt;
    use serde::Deserialize;
    use tower::ServiceExt;

    use super::*;
    use crate::id::UserId;

    #[derive(Debug, Deserialize, Serialize)]
    struct Input {
        name: String,
        age: u8,
    }

    fn app() -> Router {
        Router::new()
            .route(
                "/json",
                post(|Json(input): Json<Input>| async move { Json(input) }),
            )
            .route(
                "/users/{id}",
                get(|Path(id): Path<UserId>| async move { id.to_string() }),
            )
            .route(
                "/q",
                get(|Query(input): Query<Input>| async move { input.name }),
            )
    }

    async fn call(req: http::Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app().oneshot(req).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn json_req(body: &'static str) -> http::Request<Body> {
        http::Request::builder()
            .method(Method::POST)
            .uri("/json")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn arc_08_json_rejections_use_the_envelope() {
        let (status, body) = call(json_req(r#"{"name":"a","age":3}"#)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["age"], 3);

        let (status, body) = call(json_req("{not json")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "bad_request");

        let (status, body) = call(json_req(r#"{"name":"a","age":"hunter2"}"#)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["code"], "validation_failed");
        assert!(!body.to_string().contains("hunter2"));

        let req = http::Request::builder()
            .method(Method::POST)
            .uri("/json")
            .body(Body::from(r#"{"name":"a","age":3}"#))
            .unwrap();
        let (status, body) = call(req).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(body["error"]["code"], "unsupported_media_type");
    }

    #[tokio::test]
    async fn arc_08_path_and_query_rejections_use_the_envelope() {
        let req = http::Request::builder()
            .uri("/users/not-a-uuid")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "bad_request");

        let req = http::Request::builder()
            .uri("/q?name=x&age=old")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(req).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["code"], "validation_failed");
    }
}
