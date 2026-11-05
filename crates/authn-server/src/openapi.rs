//! OpenAPI document (ARC-09, OPS-09): the server's own paths plus every
//! module's `utoipa::OpenApi` document.

use utoipa::OpenApi;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};

/// The server's own paths.
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

/// The merged document.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();
    doc.merge(authn_session::SessionApi::openapi());
    doc.merge(authn_session::LoginApi::openapi());
    doc.merge(authn_password::PasswordApi::openapi());
    doc.merge(authn_account::AccountApi::openapi());
    doc.merge(authn_mfa::MfaApi::openapi());
    doc.merge(authn_webauthn::WebauthnApi::openapi());
    doc.merge(authn_org::OrgApi::openapi());
    doc.merge(authn_protect::ProtectApi::openapi());
    doc.merge(authn_audit::AuditApi::openapi());
    doc.merge(authn_oidc_client::OidcClientApi::openapi());
    doc.merge(authn_admin::AdminApi::openapi());
    #[cfg(feature = "passkey")]
    doc.merge(authn_admin::AdminEnrollmentApi::openapi());
    doc.components
        .get_or_insert_with(Default::default)
        .add_security_schemes_from_iter(security_schemes());
    doc
}

/// The credentials the API accepts (`docs/api/authentication.md`). Every
/// scheme named by an operation's `security` must be defined here
/// (`tests/openapi.rs`).
fn security_schemes() -> [(&'static str, SecurityScheme); 4] {
    [
        (
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "__Host-authn_session",
                "Web session cookie. State-changing requests also need the \
                 `X-CSRF-Token` header (SES-04).",
            ))),
        ),
        (
            "bearer_jwt",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Native clients: the access token of the session \
                         (`Authorization: Bearer <access token>`, SES-08).",
                    ))
                    .build(),
            ),
        ),
        (
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-API-Key",
                "Organization API key `ak_…` (ORG-08) in the `X-API-Key` header.",
            ))),
        ),
        (
            "api_key_bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("ak_…")
                    .description(Some(
                        "Organization API key `ak_…` (ORG-08) as \
                         `Authorization: Bearer ak_…`.",
                    ))
                    .build(),
            ),
        ),
    ]
}

/// The document as JSON value.
#[must_use]
pub fn document() -> serde_json::Value {
    serde_json::to_value(openapi()).unwrap_or(serde_json::Value::Null)
}
