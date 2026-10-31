//! OpenAPI document (ARC-09, OPS-09). Module crates export their own
//! `utoipa::OpenApi` structs; the server agent nests them here.

use utoipa::OpenApi;

/// The server's OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    info(title = "rust-authentication", description = "Authentication API"),
    paths(
        crate::routes::health::live,
        crate::routes::health::ready,
        crate::routes::example::server_time,
    ),
    components(schemas(
        authn_core::error::ErrorEnvelope,
        authn_core::error::ErrorBody,
        crate::routes::health::HealthResponse,
        crate::routes::example::TimeResponse,
    ))
)]
pub struct ApiDoc;

/// The document as JSON value.
#[must_use]
pub fn document() -> serde_json::Value {
    serde_json::to_value(ApiDoc::openapi()).unwrap_or(serde_json::Value::Null)
}
