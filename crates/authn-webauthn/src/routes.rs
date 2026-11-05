//! HTTP endpoints of authn-webauthn (PKY-01, PKY-04, ARC-03, ARC-09).
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `POST` | `/v1/me/passkeys/registration/options` | session (+ step-up when passkeys exist) | PKY-01/02/03/08 |
//! | `POST` | `/v1/me/passkeys/registration/verify` | same session that started it | PKY-01/02/08 |
//! | `GET` | `/v1/me/passkeys` | session (read-only impersonation ok) | PKY-04 |
//! | `PATCH` | `/v1/me/passkeys/{passkey_id}` | session | PKY-04 |
//! | `DELETE` | `/v1/me/passkeys/{passkey_id}` | session + step-up | PKY-04 |
//!
//! The registration endpoints exist only with the `passkey` feature.
//! Passkey *login* / second-factor / step-up endpoints belong to
//! authn-session (SES-20), which drives
//! [`WebauthnService::start_authentication`] /
//! [`WebauthnService::finish_authentication`]. The well-known documents
//! (PKY-07) have their own router: [`crate::well_known_router`].
//!
//! Every response carries `Cache-Control: no-store`. Unknown or foreign
//! passkey ids answer `404` (ORG-10 style).

use authn_core::domain::Principal;
use authn_core::error::AuthError;
use authn_core::http::{Json, Path, RequestContext};
use authn_core::id::CredentialId;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::service::{PasskeySummary, PasskeyUsage, WebauthnService};
#[cfg(feature = "passkey")]
use crate::service::{
    RegistrationIntent, RegistrationOptionsRequest, RegistrationStart, RegistrationVerifyRequest,
};

/// The module router. Requires [`WebauthnService`] from the state and the
/// session middleware to insert a [`Principal`] (and to enforce CSRF on
/// cookie sessions).
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    WebauthnService: FromRef<S>,
{
    let router = Router::new()
        .route("/v1/me/passkeys", get(list_passkeys))
        .route(
            "/v1/me/passkeys/{passkey_id}",
            patch(rename_passkey).delete(delete_passkey),
        );
    #[cfg(feature = "passkey")]
    let router = router
        .route(
            "/v1/me/passkeys/registration/options",
            axum::routing::post(registration_options),
        )
        .route(
            "/v1/me/passkeys/registration/verify",
            axum::routing::post(registration_verify),
        );
    router
}

/// OpenAPI document of this crate's endpoints (including the well-known
/// documents).
#[cfg(feature = "passkey")]
#[derive(OpenApi)]
#[openapi(
    paths(
        registration_options,
        registration_verify,
        list_passkeys,
        rename_passkey,
        delete_passkey,
        crate::well_known::apple_app_site_association_handler,
        crate::well_known::asset_links_handler,
        crate::well_known::related_origins_handler,
    ),
    components(schemas(
        RegistrationOptionsRequest,
        RegistrationIntent,
        RegistrationStart,
        RegistrationVerifyRequest,
        PasskeySummary,
        PasskeyUsage,
        PasskeyList,
        RenamePasskeyRequest,
    )),
    tags(
        (name = "passkeys", description = "Passkey registration and management"),
        (name = "well-known", description = "Mobile app association and related origins"),
    )
)]
pub struct WebauthnApi;

/// OpenAPI document of this crate's endpoints (without the `passkey`
/// feature: management and well-known documents only).
#[cfg(not(feature = "passkey"))]
#[derive(OpenApi)]
#[openapi(
    paths(
        list_passkeys,
        rename_passkey,
        delete_passkey,
        crate::well_known::apple_app_site_association_handler,
        crate::well_known::asset_links_handler,
        crate::well_known::related_origins_handler,
    ),
    components(schemas(PasskeySummary, PasskeyUsage, PasskeyList, RenamePasskeyRequest)),
    tags(
        (name = "passkeys", description = "Passkey management"),
        (name = "well-known", description = "Mobile app association and related origins"),
    )
)]
pub struct WebauthnApi;

// --- request / response types ------------------------------------------------

/// The caller's passkeys.
#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyList {
    /// Passkeys, oldest first.
    pub passkeys: Vec<PasskeySummary>,
}

/// Body of `PATCH /v1/me/passkeys/{passkey_id}`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RenamePasskeyRequest {
    /// New name (1–64 characters, no control / invisible characters).
    pub name: String,
}

/// JSON with `Cache-Control: no-store`.
fn no_store<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// --- handlers ----------------------------------------------------------------

/// Starts registering a passkey: returns `CredentialCreationOptions` for
/// `navigator.credentials.create()` / the platform passkey APIs.
#[cfg(feature = "passkey")]
#[utoipa::path(
    post,
    path = "/v1/me/passkeys/registration/options",
    tag = "passkeys",
    request_body = RegistrationOptionsRequest,
    responses(
        (status = 200, description = "Creation options and ceremony id", body = RegistrationStart),
        (status = 401, description = "Not authenticated or step-up required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Not allowed (impersonation, API key, organization policy)", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "Passkey limit reached", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "Invalid name", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Too many registrations", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn registration_options(
    State(service): State<WebauthnService>,
    ctx: RequestContext,
    principal: Principal,
    Json(body): Json<RegistrationOptionsRequest>,
) -> Result<Response, AuthError> {
    let start = service.start_registration(&ctx, &principal, body).await?;
    Ok(no_store(StatusCode::OK, start))
}

/// Verifies the authenticator response and stores the passkey.
#[cfg(feature = "passkey")]
#[utoipa::path(
    post,
    path = "/v1/me/passkeys/registration/verify",
    tag = "passkeys",
    request_body = RegistrationVerifyRequest,
    responses(
        (status = 201, description = "Passkey registered", body = PasskeySummary),
        (status = 400, description = "Ceremony invalid / expired / replayed, or response rejected", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Authenticator model not allowed", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "Already registered or limit reached", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn registration_verify(
    State(service): State<WebauthnService>,
    ctx: RequestContext,
    principal: Principal,
    Json(body): Json<RegistrationVerifyRequest>,
) -> Result<Response, AuthError> {
    let passkey = service.finish_registration(&ctx, &principal, body).await?;
    Ok(no_store(StatusCode::CREATED, passkey))
}

/// Lists the caller's passkeys (PKY-04).
#[utoipa::path(
    get,
    path = "/v1/me/passkeys",
    tag = "passkeys",
    responses(
        (status = 200, description = "Passkeys", body = PasskeyList),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn list_passkeys(
    State(service): State<WebauthnService>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let passkeys = service.list_passkeys(&principal).await?;
    Ok(no_store(StatusCode::OK, PasskeyList { passkeys }))
}

/// Renames a passkey (PKY-04).
#[utoipa::path(
    patch,
    path = "/v1/me/passkeys/{passkey_id}",
    tag = "passkeys",
    params(("passkey_id" = String, Path, format = Uuid, description = "Passkey id")),
    request_body = RenamePasskeyRequest,
    responses(
        (status = 200, description = "Renamed", body = PasskeySummary),
        (status = 404, description = "Unknown passkey", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "Invalid name", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn rename_passkey(
    State(service): State<WebauthnService>,
    ctx: RequestContext,
    principal: Principal,
    Path(passkey_id): Path<CredentialId>,
    Json(body): Json<RenamePasskeyRequest>,
) -> Result<Response, AuthError> {
    let passkey = service
        .rename_passkey(&ctx, &principal, passkey_id, &body.name)
        .await?;
    Ok(no_store(StatusCode::OK, passkey))
}

/// Removes a passkey (PKY-04; step-up required).
#[utoipa::path(
    delete,
    path = "/v1/me/passkeys/{passkey_id}",
    tag = "passkeys",
    params(("passkey_id" = String, Path, format = Uuid, description = "Passkey id")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Step-up required", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown passkey", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "Last login method / last required factor", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn delete_passkey(
    State(service): State<WebauthnService>,
    ctx: RequestContext,
    principal: Principal,
    Path(passkey_id): Path<CredentialId>,
) -> Result<Response, AuthError> {
    service.delete_passkey(&ctx, &principal, passkey_id).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}
