//! HTTP endpoints of the provider (OIDP-01 … OIDP-11, ARC-03, ARC-09).
//!
//! Two routers, because the protocol endpoints must not pass through the
//! session middleware (its bearer handling would consume a provider
//! access token as a native one, and they authenticate clients
//! themselves):
//!
//! [`router`] — **behind** the authentication + CSRF layer:
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `GET` | `/v1/oauth2/authorize` | optional browser session | OIDP-02 … OIDP-04 |
//! | `GET` | `/v1/oauth2/interactions/{interaction_id}` | browser binding cookie (+ optional session) | OIDP-04 |
//! | `POST` | `/v1/oauth2/interactions/{interaction_id}/accept` | session + CSRF + binding | OIDP-04, OIDP-05 |
//! | `POST` | `/v1/oauth2/interactions/{interaction_id}/deny` | binding | OIDP-04 |
//! | `GET` | `/v1/me/oauth2/consents` | session | OIDP-05 |
//! | `DELETE` | `/v1/me/oauth2/consents/{client_id}` | session + CSRF | OIDP-05 |
//! | `GET`, `POST` | `/v1/admin/oauth2/clients` | staff (`oauth_clients:read` / `:manage`) | OIDP-01 |
//! | `GET`, `PATCH`, `DELETE` | `/v1/admin/oauth2/clients/{client_id}` | staff | OIDP-01 |
//! | `POST` | `/v1/admin/oauth2/clients/{client_id}/secret` | staff | OIDP-01 |
//!
//! [`protocol_router`] — **outside** the authentication layer:
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `POST` | `/v1/oauth2/token` | client (Basic / post / none) | OIDP-06 … OIDP-08 |
//! | `POST` | `/v1/oauth2/revoke` | client | OIDP-11 |
//! | `POST` | `/v1/oauth2/introspect` | confidential client | OIDP-11 |
//! | `GET`, `POST` | `/v1/oauth2/userinfo` | provider access token | OIDP-10 |
//! | `GET` | `/.well-known/openid-configuration` | — | OIDP-09 |
//! | `GET` | `/.well-known/oauth-authorization-server` | — | OIDP-09 |
//!
//! Every response carries `Cache-Control: no-store` except the discovery
//! documents.

use authn_core::domain::Principal;
use authn_core::error::AuthError;
use authn_core::http::{Json, Path, RequestContext};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRef, RawQuery, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, LOCATION, PRAGMA, SET_COOKIE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::cookies::{browser_cookie, read_browser_binding};
use crate::discovery::{AuthorizationServerMetadata, metadata};
use crate::error::{OAuthError, ProtocolError};
use crate::service::{
    ClientInput, ClientPatch, ClientSummary, ClientView, ConsentView, CreatedClient,
    InteractionView, IntrospectionResponse, OidcProviderService, RedirectTarget, TokenResponse,
    UserInfo,
};

/// Routes behind the session middleware (see the module docs).
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    OidcProviderService: FromRef<S>,
{
    Router::new()
        .route("/v1/oauth2/authorize", get(authorize))
        .route("/v1/oauth2/interactions/{interaction_id}", get(interaction))
        .route(
            "/v1/oauth2/interactions/{interaction_id}/accept",
            post(accept),
        )
        .route("/v1/oauth2/interactions/{interaction_id}/deny", post(deny))
        .route("/v1/me/oauth2/consents", get(list_consents))
        .route(
            "/v1/me/oauth2/consents/{client_id}",
            axum::routing::delete(revoke_consent),
        )
        .route(
            "/v1/admin/oauth2/clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/v1/admin/oauth2/clients/{client_id}",
            get(get_client).patch(update_client).delete(delete_client),
        )
        .route(
            "/v1/admin/oauth2/clients/{client_id}/secret",
            post(rotate_secret),
        )
}

/// Protocol routes, merged **outside** the session middleware.
pub fn protocol_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    OidcProviderService: FromRef<S>,
{
    Router::new()
        .route("/v1/oauth2/token", post(token))
        .route("/v1/oauth2/revoke", post(revoke))
        .route("/v1/oauth2/introspect", post(introspect))
        .route("/v1/oauth2/userinfo", get(userinfo_get).post(userinfo_post))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
}

/// OpenAPI document of the provider.
#[derive(OpenApi)]
#[openapi(
    paths(
        authorize,
        interaction,
        accept,
        deny,
        list_consents,
        revoke_consent,
        list_clients,
        create_client,
        get_client,
        update_client,
        delete_client,
        rotate_secret,
        token,
        revoke,
        introspect,
        userinfo_get,
        userinfo_post,
        openid_configuration,
        authorization_server_metadata,
    ),
    components(schemas(
        ClientInput,
        ClientPatch,
        ClientView,
        ClientList,
        CreatedClient,
        ClientSummary,
        InteractionView,
        RedirectTarget,
        ConsentView,
        ConsentList,
        TokenResponse,
        TokenRequest,
        TokenTypeRequest,
        IntrospectionResponse,
        UserInfo,
        OAuthErrorBody,
        AuthorizationServerMetadata,
    )),
    tags((name = "oauth2-provider", description = "OAuth 2.1 / OpenID Connect provider"))
)]
pub struct OidcProviderApi;

/// Registered clients.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientList {
    /// Clients, newest first.
    pub clients: Vec<ClientView>,
}

/// The user's consents.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentList {
    /// Consents.
    pub consents: Vec<ConsentView>,
}

/// Form body of `POST /v1/oauth2/token` (documentation only; the handler
/// parses the form itself and refuses repeated fields).
#[derive(Debug, ToSchema)]
#[allow(dead_code)]
pub struct TokenRequest {
    /// `authorization_code` or `refresh_token`.
    pub grant_type: String,
    /// The authorization code.
    pub code: Option<String>,
    /// The redirect URI of the authorization request.
    pub redirect_uri: Option<String>,
    /// PKCE code verifier.
    pub code_verifier: Option<String>,
    /// The refresh token.
    pub refresh_token: Option<String>,
    /// Narrower scope on refresh.
    pub scope: Option<String>,
    /// Client id (`client_secret_post` / public clients).
    pub client_id: Option<String>,
    /// Client secret (`client_secret_post`).
    pub client_secret: Option<String>,
}

/// Form body of `POST /v1/oauth2/revoke` and `/introspect`
/// (documentation only).
#[derive(Debug, ToSchema)]
#[allow(dead_code)]
pub struct TokenTypeRequest {
    /// The token.
    pub token: String,
    /// `access_token` or `refresh_token` (optional hint).
    pub token_type_hint: Option<String>,
    /// Client id (`client_secret_post` / public clients).
    pub client_id: Option<String>,
    /// Client secret (`client_secret_post`).
    pub client_secret: Option<String>,
}

/// OAuth error body (RFC 6749 §5.2).
#[derive(Debug, ToSchema)]
#[allow(dead_code)]
pub struct OAuthErrorBody {
    /// Error code (`invalid_request`, `invalid_client`, `invalid_grant`,
    /// `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`,
    /// `invalid_token`, `insufficient_scope`).
    pub error: String,
    /// Fixed English description.
    pub error_description: String,
}

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn json<T: Serialize>(status: StatusCode, body: T) -> Response {
    no_store((status, axum::Json(body)).into_response())
}

fn authorization(headers: &HeaderMap) -> Result<Option<&str>, OAuthError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(OAuthError::invalid_request("several Authorization headers"));
    }
    match first {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .map(Some)
            .map_err(|_| OAuthError::invalid_request("malformed Authorization header")),
    }
}

/// The token-family endpoints take a form body. A request without one and
/// without `Authorization` carries no client credentials at all:
/// `invalid_client` (401), like any unauthenticated client.
fn require_form(headers: &HeaderMap, authorization: Option<&str>) -> Result<(), OAuthError> {
    let ok = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';').next().is_some_and(|m| {
                m.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        });
    match (ok, authorization) {
        (true, _) => Ok(()),
        (false, None) => Err(OAuthError::invalid_client(false)),
        (false, Some(_)) => Err(OAuthError::invalid_request(
            "the body must be application/x-www-form-urlencoded",
        )),
    }
}

// --- authorization ------------------------------------------------------------

/// Authorization endpoint (OAuth 2.1 §4.1.1, OIDC Core §3.1.2): code flow
/// with PKCE `S256` only. Answers `303` to the client's redirect URI (code
/// or error, always with `iss`, RFC 9207) or to the login / consent page
/// (`oidc_provider.interaction_url?interaction_id=…`, sets the
/// `__Host-authn_oidc_browser` binding cookie). Requests whose client or
/// redirect URI cannot be validated are never redirected (`400`).
#[utoipa::path(
    get,
    path = "/v1/oauth2/authorize",
    operation_id = "oauth2_authorize",
    tag = "oauth2-provider",
    params(
        ("client_id" = String, Query, description = "Client id"),
        ("redirect_uri" = String, Query, description = "Registered redirect URI (exact)"),
        ("response_type" = String, Query, description = "`code`"),
        ("scope" = String, Query, description = "Space-separated scopes"),
        ("code_challenge" = String, Query, description = "PKCE S256 challenge"),
        ("code_challenge_method" = String, Query, description = "`S256`"),
        ("state" = Option<String>, Query, description = "Opaque client state"),
        ("nonce" = Option<String>, Query, description = "OIDC nonce"),
        ("prompt" = Option<String>, Query, description = "`none`, `login`, `consent`"),
        ("max_age" = Option<i64>, Query, description = "Maximum authentication age (s)"),
        ("acr_values" = Option<String>, Query, description = "Requested `acr` values"),
        ("resource" = Option<String>, Query, description = "RFC 8707 resource (repeatable)"),
    ),
    responses(
        (status = 303, description = "Redirect to the client (code / error + `iss`) or to the interaction page"),
        (status = 400, description = "invalid_authorization_request (never redirected)", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Too many requests", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn authorize(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    headers: HeaderMap,
    principal: Option<Principal>,
    RawQuery(query): RawQuery,
) -> Result<Response, AuthError> {
    let outcome = service
        .authorize(
            &ctx,
            query.as_deref().unwrap_or_default(),
            principal.as_ref(),
            read_browser_binding(&headers),
        )
        .await?;
    let mut response = StatusCode::SEE_OTHER.into_response();
    let location = HeaderValue::from_str(&outcome.location)
        .map_err(|_| AuthError::internal("redirect location is not a header value"))?;
    response.headers_mut().insert(LOCATION, location);
    if let Some(binding) = outcome.browser_cookie
        && let Some(cookie) = browser_cookie(&binding, service.settings().authorization_request_ttl)
    {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    Ok(no_store(response))
}

/// The pending authorization request, for the login / consent page
/// (OIDP-04). Only the browser that started it (binding cookie) may read
/// it; the session, if any, decides `login_required` / `consent_required`.
#[utoipa::path(
    get,
    path = "/v1/oauth2/interactions/{interaction_id}",
    operation_id = "oauth2_interaction",
    tag = "oauth2-provider",
    params(("interaction_id" = Uuid, Path, description = "Interaction id")),
    responses(
        (status = 200, description = "The request", body = InteractionView),
        (status = 400, description = "oauth_interaction_invalid", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn interaction(
    State(service): State<OidcProviderService>,
    headers: HeaderMap,
    principal: Option<Principal>,
    Path(interaction_id): Path<Uuid>,
) -> Result<Response, AuthError> {
    let view = service
        .interaction(
            interaction_id,
            principal.as_ref(),
            read_browser_binding(&headers).as_deref(),
        )
        .await?;
    Ok(json(StatusCode::OK, view))
}

/// The signed-in user approves the request (OIDP-04, OIDP-05). Answers the
/// client redirect (`redirect_to`, with `code`); the page navigates there.
/// `401 step_up_required` (`details.login_reasons`) while the session does
/// not meet `prompt=login` / `max_age` / `acr_values`: re-authenticate with
/// `POST /v1/reauth`, then accept again.
#[utoipa::path(
    post,
    path = "/v1/oauth2/interactions/{interaction_id}/accept",
    operation_id = "oauth2_accept",
    tag = "oauth2-provider",
    params(("interaction_id" = Uuid, Path, description = "Interaction id")),
    responses(
        (status = 200, description = "Where to send the browser", body = RedirectTarget),
        (status = 400, description = "oauth_interaction_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / read-only impersonation", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []))
)]
pub async fn accept(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    headers: HeaderMap,
    principal: Principal,
    Path(interaction_id): Path<Uuid>,
) -> Result<Response, AuthError> {
    let target = service
        .accept(
            &ctx,
            interaction_id,
            &principal,
            read_browser_binding(&headers).as_deref(),
        )
        .await?;
    Ok(json(StatusCode::OK, target))
}

/// The user refuses the request: the client receives `access_denied`.
#[utoipa::path(
    post,
    path = "/v1/oauth2/interactions/{interaction_id}/deny",
    operation_id = "oauth2_deny",
    tag = "oauth2-provider",
    params(("interaction_id" = Uuid, Path, description = "Interaction id")),
    responses(
        (status = 200, description = "Where to send the browser", body = RedirectTarget),
        (status = 400, description = "oauth_interaction_invalid", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn deny(
    State(service): State<OidcProviderService>,
    headers: HeaderMap,
    Path(interaction_id): Path<Uuid>,
) -> Result<Response, AuthError> {
    let target = service
        .deny(interaction_id, read_browser_binding(&headers).as_deref())
        .await?;
    Ok(json(StatusCode::OK, target))
}

// --- consents -------------------------------------------------------------------

/// The applications the user granted access (OIDP-05).
#[utoipa::path(
    get,
    path = "/v1/me/oauth2/consents",
    operation_id = "oauth2_list_consents",
    tag = "oauth2-provider",
    responses(
        (status = 200, description = "Consents", body = ConsentList),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn list_consents(
    State(service): State<OidcProviderService>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let consents = service.list_consents(&principal).await?;
    Ok(json(StatusCode::OK, ConsentList { consents }))
}

/// Revokes an application's access: the consent and every token of it for
/// the user (OIDP-05).
#[utoipa::path(
    delete,
    path = "/v1/me/oauth2/consents/{client_id}",
    operation_id = "oauth2_revoke_consent",
    tag = "oauth2-provider",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Nothing to revoke", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn revoke_consent(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    principal: Principal,
    Path(client_id): Path<String>,
) -> Result<Response, AuthError> {
    service.revoke_consent(&ctx, &principal, &client_id).await?;
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

// --- client registry ------------------------------------------------------------

/// Lists the registered clients (staff, `oauth_clients:read`; OIDP-01).
#[utoipa::path(
    get,
    path = "/v1/admin/oauth2/clients",
    operation_id = "oauth2_list_clients",
    tag = "oauth2-provider",
    responses(
        (status = 200, description = "Clients", body = ClientList),
        (status = 401, description = "Not authenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Not allowed", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn list_clients(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    principal: Principal,
) -> Result<Response, AuthError> {
    let clients = service.list_clients(&principal, &ctx).await?;
    Ok(json(StatusCode::OK, ClientList { clients }))
}

/// Registers a client (staff, `oauth_clients:manage`; OIDP-01). The secret
/// of a confidential client is returned once.
#[utoipa::path(
    post,
    path = "/v1/admin/oauth2/clients",
    operation_id = "oauth2_create_client",
    tag = "oauth2-provider",
    request_body = ClientInput,
    responses(
        (status = 201, description = "Registered", body = CreatedClient),
        (status = 401, description = "Not authenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Not allowed", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "invalid_client_metadata", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn create_client(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    principal: Principal,
    Json(input): Json<ClientInput>,
) -> Result<Response, AuthError> {
    let created = service.create_client(&principal, &ctx, input).await?;
    Ok(json(StatusCode::CREATED, created))
}

/// One client (staff, `oauth_clients:read`).
#[utoipa::path(
    get,
    path = "/v1/admin/oauth2/clients/{client_id}",
    operation_id = "oauth2_get_client",
    tag = "oauth2-provider",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 200, description = "Client", body = ClientView),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Not allowed", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown client", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn get_client(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    principal: Principal,
    Path(client_id): Path<String>,
) -> Result<Response, AuthError> {
    let client = service.get_client(&principal, &ctx, &client_id).await?;
    Ok(json(StatusCode::OK, client))
}

/// Changes a client (staff, `oauth_clients:manage`). Disabling it or
/// narrowing what it may do revokes its grants.
#[utoipa::path(
    patch,
    path = "/v1/admin/oauth2/clients/{client_id}",
    operation_id = "oauth2_update_client",
    tag = "oauth2-provider",
    params(("client_id" = String, Path, description = "Client id")),
    request_body = ClientPatch,
    responses(
        (status = 200, description = "Updated", body = ClientView),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Not allowed", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown client", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "invalid_client_metadata", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn update_client(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    principal: Principal,
    Path(client_id): Path<String>,
    Json(patch): Json<ClientPatch>,
) -> Result<Response, AuthError> {
    let client = service
        .update_client(&principal, &ctx, &client_id, patch)
        .await?;
    Ok(json(StatusCode::OK, client))
}

/// Deletes a client and everything issued to it (staff,
/// `oauth_clients:manage`).
#[utoipa::path(
    delete,
    path = "/v1/admin/oauth2/clients/{client_id}",
    operation_id = "oauth2_delete_client",
    tag = "oauth2-provider",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Not allowed", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown client", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn delete_client(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    principal: Principal,
    Path(client_id): Path<String>,
) -> Result<Response, AuthError> {
    service.delete_client(&principal, &ctx, &client_id).await?;
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

/// Rotates the secret of a confidential client (staff,
/// `oauth_clients:manage`); the old secret stops working at once.
#[utoipa::path(
    post,
    path = "/v1/admin/oauth2/clients/{client_id}/secret",
    operation_id = "oauth2_rotate_secret",
    tag = "oauth2-provider",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 200, description = "New secret (shown once)", body = CreatedClient),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Not allowed", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown client", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "Public clients have no secret", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn rotate_secret(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    principal: Principal,
    Path(client_id): Path<String>,
) -> Result<Response, AuthError> {
    let created = service
        .rotate_client_secret(&principal, &ctx, &client_id)
        .await?;
    Ok(json(StatusCode::OK, created))
}

// --- protocol endpoints ------------------------------------------------------------

/// Token endpoint (RFC 6749 §3.2; OIDP-06 … OIDP-08): `authorization_code`
/// (PKCE verifier required, single-use code) and `refresh_token`
/// (rotation, replay revokes the grant). Client authentication:
/// `client_secret_basic`, `client_secret_post`, `none` (public clients).
/// Errors use the OAuth format (`{"error": …}`).
#[utoipa::path(
    post,
    path = "/v1/oauth2/token",
    operation_id = "oauth2_token",
    tag = "oauth2-provider",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Tokens", body = TokenResponse),
        (status = 400, description = "invalid_request / invalid_grant / unauthorized_client / unsupported_grant_type / invalid_scope", body = OAuthErrorBody),
        (status = 401, description = "invalid_client", body = OAuthErrorBody),
        (status = 429, description = "Too many requests", body = authn_core::error::ErrorEnvelope),
    ),
    security(("oauth2_client" = []))
)]
pub async fn token(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProtocolError> {
    let authorization = authorization(&headers)?;
    require_form(&headers, authorization)?;
    let response = service.token(&ctx, authorization, &body).await?;
    Ok(json(StatusCode::OK, response))
}

/// Token revocation (RFC 7009; OIDP-11). A refresh token revokes its whole
/// grant. Unknown tokens and tokens of other clients also answer `200`.
#[utoipa::path(
    post,
    path = "/v1/oauth2/revoke",
    operation_id = "oauth2_revoke",
    tag = "oauth2-provider",
    request_body(content = TokenTypeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Revoked (or nothing to revoke)"),
        (status = 400, description = "invalid_request", body = OAuthErrorBody),
        (status = 401, description = "invalid_client", body = OAuthErrorBody),
    ),
    security(("oauth2_client" = []))
)]
pub async fn revoke(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProtocolError> {
    let authorization = authorization(&headers)?;
    require_form(&headers, authorization)?;
    service.revoke(&ctx, authorization, &body).await?;
    Ok(no_store(StatusCode::OK.into_response()))
}

/// Token introspection (RFC 7662; OIDP-11) for confidential clients. A
/// token is active only for the client it was issued to or a client in
/// its audience.
#[utoipa::path(
    post,
    path = "/v1/oauth2/introspect",
    operation_id = "oauth2_introspect",
    tag = "oauth2-provider",
    request_body(content = TokenTypeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Introspection result", body = IntrospectionResponse),
        (status = 400, description = "invalid_request", body = OAuthErrorBody),
        (status = 401, description = "invalid_client", body = OAuthErrorBody),
    ),
    security(("oauth2_client" = []))
)]
pub async fn introspect(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProtocolError> {
    let authorization = authorization(&headers)?;
    require_form(&headers, authorization)?;
    let response = service.introspect(&ctx, authorization, &body).await?;
    Ok(json(StatusCode::OK, response))
}

/// UserInfo (OIDC Core §5.3; OIDP-10): `sub`, plus `name`, `locale`,
/// `zoneinfo` (`profile`) and `email`, `email_verified` (`email`).
#[utoipa::path(
    get,
    path = "/v1/oauth2/userinfo",
    operation_id = "oauth2_userinfo_get",
    tag = "oauth2-provider",
    responses(
        (status = 200, description = "Claims", body = UserInfo),
        (status = 401, description = "invalid_token (WWW-Authenticate: Bearer)", body = OAuthErrorBody),
        (status = 403, description = "insufficient_scope", body = OAuthErrorBody),
    ),
    security(("oauth2_access_token" = []))
)]
pub async fn userinfo_get(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> Result<Response, ProtocolError> {
    let authorization = authorization(&headers)?;
    let info = service.userinfo(&ctx, authorization).await?;
    Ok(json(StatusCode::OK, info))
}

/// UserInfo with `POST` (OIDC Core §5.3.1); the token is read from the
/// `Authorization` header only.
#[utoipa::path(
    post,
    path = "/v1/oauth2/userinfo",
    operation_id = "oauth2_userinfo_post",
    tag = "oauth2-provider",
    responses(
        (status = 200, description = "Claims", body = UserInfo),
        (status = 401, description = "invalid_token (WWW-Authenticate: Bearer)", body = OAuthErrorBody),
        (status = 403, description = "insufficient_scope", body = OAuthErrorBody),
    ),
    security(("oauth2_access_token" = []))
)]
pub async fn userinfo_post(
    State(service): State<OidcProviderService>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> Result<Response, ProtocolError> {
    userinfo_get(State(service), ctx, headers).await
}

fn discovery_response(body: AuthorizationServerMetadata) -> Response {
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
}

/// OpenID Provider metadata (OpenID Connect Discovery 1.0; OIDP-09).
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    operation_id = "oauth2_openid_configuration",
    tag = "oauth2-provider",
    responses((status = 200, description = "Provider metadata", body = AuthorizationServerMetadata))
)]
pub async fn openid_configuration(State(service): State<OidcProviderService>) -> Response {
    discovery_response(metadata(service.settings()))
}

/// OAuth 2.0 Authorization Server Metadata (RFC 8414; OIDP-09).
#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    operation_id = "oauth2_authorization_server_metadata",
    tag = "oauth2-provider",
    responses((status = 200, description = "Authorization server metadata", body = AuthorizationServerMetadata))
)]
pub async fn authorization_server_metadata(State(service): State<OidcProviderService>) -> Response {
    discovery_response(metadata(service.settings()))
}
