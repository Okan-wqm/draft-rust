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
    #[cfg(feature = "oidc-provider")]
    doc.merge(authn_oidc_provider::OidcProviderApi::openapi());
    doc.components
        .get_or_insert_with(Default::default)
        .add_security_schemes_from_iter(security_schemes());
    declare_public_operations(&mut doc);
    doc
}

/// K-129: every operation declares the credentials it accepts. Protected
/// operations name their schemes in their own `#[utoipa::path(security(…))]`
/// (alternatives: one scheme per requirement); an operation without one
/// needs no credential and is given an explicit empty list (`security:
/// []`). `tests/openapi.rs` probes every operation of the assembled router
/// and fails when a declaration differs from what is enforced, so a
/// forgotten annotation cannot make a protected route look public.
fn declare_public_operations(doc: &mut utoipa::openapi::OpenApi) {
    for item in doc.paths.paths.values_mut() {
        for operation in [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.options,
            &mut item.head,
            &mut item.patch,
            &mut item.trace,
        ]
        .into_iter()
        .flatten()
        {
            operation.security.get_or_insert_with(Vec::new);
        }
    }
}

/// The credentials the API accepts (`docs/api/authentication.md`). Every
/// scheme named by an operation's `security` must be defined here
/// (`tests/openapi.rs`).
fn security_schemes() -> Vec<(&'static str, SecurityScheme)> {
    vec![
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
        (
            "oauth2_client",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Basic)
                    .description(Some(
                        "OAuth client authentication of the provider's token, \
                         revocation and introspection endpoints (OIDP-06, \
                         RFC 6749 §2.3.1): `client_secret_basic` \
                         (`Authorization: Basic`), or `client_id` + \
                         `client_secret` in the form (`client_secret_post`); \
                         public clients send only `client_id` (`none`, PKCE).",
                    ))
                    .build(),
            ),
        ),
        (
            "oauth2_access_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Access token issued by the OAuth 2.1 / OIDC provider to \
                         a registered client (RFC 9068, OIDP-08; never a native \
                         session token).",
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
