//! OpenAPI document (ARC-09, OPS-09): the server's own paths plus every
//! module's `utoipa::OpenApi` document.

use utoipa::OpenApi;

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
    doc
}

/// The document as JSON value.
#[must_use]
pub fn document() -> serde_json::Value {
    serde_json::to_value(openapi()).unwrap_or(serde_json::Value::Null)
}
