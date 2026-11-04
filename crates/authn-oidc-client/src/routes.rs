//! HTTP endpoints of authn-oidc-client (SOC-01 … SOC-08, ARC-03, ARC-09).
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `GET` | `/v1/oauth/providers` | — | SOC-01 |
//! | `GET` | `/v1/oauth/{provider}/start` | — (browser) | SOC-02 |
//! | `GET`, `POST` | `/v1/oauth/{provider}/callback` | browser binding cookie | SOC-02, SOC-03, SOC-05, SOC-07 |
//! | `POST` | `/v1/oauth/nonce` | — | SOC-04 |
//! | `POST` | `/v1/oauth/{provider}/native` | — | SOC-03, SOC-04, SOC-05 |
//! | `GET` | `/v1/me/identities` | session | SOC-06 |
//! | `POST` | `/v1/me/identities/link` | session + step-up | SOC-06 |
//! | `POST` | `/v1/me/identities/link/native` | session + step-up | SOC-06 |
//! | `DELETE` | `/v1/me/identities/{identity_id}` | session + step-up | SOC-06 |
//!
//! Login responses (session cookie / tokens / challenge) are rendered by
//! the `SessionIssuer` port (authn-session), so cookie attributes, CSRF
//! tokens and challenge handling are the same as for every other login.
//! The callback accepts `POST` for Apple's `form_post`; it carries no
//! session cookie on that cross-site request, so the server's CSRF layer
//! does not apply — the single-use `state` bound to the browser is the
//! CSRF protection (SOC-02). Every response carries
//! `Cache-Control: no-store`.

use authn_core::domain::Principal;
use authn_core::error::AuthError;
use authn_core::http::{Json, Path, Query, RequestContext};
use authn_core::id::IdentityId;
use axum::Router;
use axum::extract::{Form, FromRef, State};
use axum::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::cookies::{binding_cookie, read_binding};
use crate::service::{
    CallbackParams, CallbackResult, IdentitySummary, NativeLoginRequest, NativeNonce,
    OidcClientService, ProviderInfo, WebLoginOptions, WebStart,
};

/// The module router. Requires [`OidcClientService`] from the state; the
/// `/v1/me/…` routes need the session middleware's [`Principal`] (and its
/// CSRF enforcement for cookie sessions).
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    OidcClientService: FromRef<S>,
{
    Router::new()
        .route("/v1/oauth/providers", get(list_providers))
        .route("/v1/oauth/nonce", post(native_nonce))
        .route("/v1/oauth/{provider}/start", get(start_login))
        .route(
            "/v1/oauth/{provider}/callback",
            get(callback_query).post(callback_form),
        )
        .route("/v1/oauth/{provider}/native", post(native_login))
        .route("/v1/me/identities", get(list_identities))
        .route("/v1/me/identities/link", post(start_link))
        .route("/v1/me/identities/link/native", post(link_native))
        .route("/v1/me/identities/{identity_id}", delete(unlink_identity))
}

/// OpenAPI document of this crate's endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(
        list_providers,
        start_login,
        callback_query,
        callback_form,
        native_nonce,
        native_login,
        list_identities,
        start_link,
        link_native,
        unlink_identity,
    ),
    components(schemas(
        ProviderInfo,
        ProviderList,
        CallbackParams,
        NativeNonceRequest,
        NativeNonce,
        NativeLoginRequest,
        IdentitySummary,
        IdentityList,
        LinkStartRequest,
        LinkStartResponse,
        LinkNativeRequest,
    )),
    tags((name = "social-login", description = "Social login and linked identities"))
)]
pub struct OidcClientApi;

// --- request / response types ------------------------------------------------

/// Enabled providers.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderList {
    /// Providers.
    pub providers: Vec<ProviderInfo>,
}

/// Query of `GET /v1/oauth/{provider}/start`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct StartParams {
    /// Where to go after login: a same-origin path or an allow-listed
    /// absolute URL (PRT-10). Default `/`.
    pub return_to: Option<String>,
    /// "Remember me" (SES-06): a long-lived session. Default `false`.
    #[serde(default)]
    pub remember_me: bool,
    /// "This is not my device" (SES-07). Default `false`.
    #[serde(default)]
    pub shared_device: bool,
}

/// Body of `POST /v1/oauth/nonce`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeNonceRequest {
    /// Provider id (`google`, `apple`, …).
    pub provider: String,
}

/// The caller's identities.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityList {
    /// Identities, oldest first.
    pub identities: Vec<IdentitySummary>,
}

/// Body of `POST /v1/me/identities/link`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LinkStartRequest {
    /// Provider id.
    pub provider: String,
    /// Where to return after linking (PRT-10). Default `/`.
    #[serde(default)]
    pub return_to: Option<String>,
}

/// Answer of `POST /v1/me/identities/link`.
#[derive(Debug, Serialize, ToSchema)]
pub struct LinkStartResponse {
    /// Navigate the browser here.
    pub authorization_url: String,
}

/// Body of `POST /v1/me/identities/link/native`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LinkNativeRequest {
    /// Provider id.
    pub provider: String,
    /// ID token from the platform SDK (nonce from `POST /v1/oauth/nonce`).
    pub id_token: String,
    /// Sign in with Apple only: the SDK's `authorizationCode` (K-35).
    #[serde(default)]
    pub authorization_code: Option<String>,
}

impl std::fmt::Debug for LinkNativeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkNativeRequest")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn json<T: Serialize>(status: StatusCode, body: T) -> Response {
    no_store((status, Json(body)).into_response())
}

fn redirect(location: &str) -> Result<Response, AuthError> {
    let value = HeaderValue::from_str(location)
        .map_err(|_| AuthError::internal("redirect target is not a header value"))?;
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(LOCATION, value);
    Ok(no_store(response))
}

fn with_binding(mut response: Response, start: &WebStart) -> Response {
    if let Some(cookie) = binding_cookie(start.binding.expose(), start.binding_max_age) {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    response
}

// --- handlers ----------------------------------------------------------------

/// Lists the enabled providers (SOC-01).
#[utoipa::path(
    get,
    path = "/v1/oauth/providers",
    tag = "social-login",
    responses((status = 200, description = "Enabled providers", body = ProviderList))
)]
pub async fn list_providers(State(service): State<OidcClientService>) -> Response {
    json(
        StatusCode::OK,
        ProviderList {
            providers: service.providers(),
        },
    )
}

/// Starts a browser login: redirects to the provider and sets the
/// browser-binding cookie (SOC-02).
#[utoipa::path(
    get,
    path = "/v1/oauth/{provider}/start",
    tag = "social-login",
    params(("provider" = String, Path, description = "Provider id"), StartParams),
    responses(
        (status = 303, description = "Redirect to the provider; sets `__Host-authn_oauth`"),
        (status = 400, description = "Invalid return_to", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown provider", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Too many starts", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn start_login(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(params): Query<StartParams>,
) -> Result<Response, AuthError> {
    let cookie = read_binding(&headers);
    let start = service
        .start_web_login(
            &ctx,
            &provider,
            params.return_to.as_deref(),
            cookie.as_deref(),
            WebLoginOptions {
                remember_me: params.remember_me,
                shared_device: params.shared_device,
            },
        )
        .await?;
    let response = redirect(start.authorization_url.as_str())?;
    Ok(with_binding(response, &start))
}

async fn finish_callback(
    service: &OidcClientService,
    ctx: &RequestContext,
    headers: &HeaderMap,
    provider: &str,
    params: &CallbackParams,
) -> Result<Response, AuthError> {
    let cookie = read_binding(headers);
    let result = service
        .web_callback(ctx, provider, params, cookie.as_deref())
        .await;
    match result {
        Ok(CallbackResult::Login { outcome, return_to }) => Ok(no_store(
            service
                .deps()
                .sessions
                .login_response(outcome, Some(&return_to)),
        )),
        Ok(CallbackResult::Linked { return_to }) => redirect(&return_to),
        // K-36: a configured (start-up validated, allow-listed) error page
        // gets the stable code; never the state's `return_to` (the state
        // may be forged) and never error details.
        Err(err) => match service.error_redirect_location(&err) {
            Some(location) => redirect(&location),
            None => Err(err),
        },
    }
}

/// Provider callback (query parameters).
#[utoipa::path(
    get,
    path = "/v1/oauth/{provider}/callback",
    tag = "social-login",
    params(("provider" = String, Path, description = "Provider id"), CallbackParams),
    responses(
        (status = 303, description = "Logged in (session cookie) / challenge cookie / identity linked; redirect to return_to. With `oidc_client.error_redirect`, failures also answer 303 to that page with `error=<code>`"),
        (status = 400, description = "oauth_state_invalid / oauth_authorization_denied", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "oauth_token_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "oauth_email_not_verified / identity_link_not_allowed", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "oauth_link_required / identity_already_linked", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn callback_query(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(params): Query<CallbackParams>,
) -> Result<Response, AuthError> {
    finish_callback(&service, &ctx, &headers, &provider, &params).await
}

/// Provider callback (`response_mode=form_post`, Sign in with Apple).
#[utoipa::path(
    post,
    path = "/v1/oauth/{provider}/callback",
    tag = "social-login",
    params(("provider" = String, Path, description = "Provider id")),
    request_body(content = CallbackParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 303, description = "As the GET callback"),
        (status = 400, description = "oauth_state_invalid / oauth_authorization_denied", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "oauth_token_invalid", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn callback_form(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Form(params): Form<CallbackParams>,
) -> Result<Response, AuthError> {
    finish_callback(&service, &ctx, &headers, &provider, &params).await
}

/// Issues a single-use nonce for a native ID token (SOC-04).
#[utoipa::path(
    post,
    path = "/v1/oauth/nonce",
    tag = "social-login",
    request_body = NativeNonceRequest,
    responses(
        (status = 200, description = "Nonce", body = NativeNonce),
        (status = 400, description = "Provider has no native flow", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown provider", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Too many requests", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn native_nonce(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    Json(body): Json<NativeNonceRequest>,
) -> Result<Response, AuthError> {
    let nonce = service.issue_native_nonce(&ctx, &body.provider).await?;
    Ok(json(StatusCode::OK, nonce))
}

/// Native login with a platform-SDK ID token (SOC-04). Answers like every
/// native login: tokens, or a challenge (MFA / required actions, SOC-09).
#[utoipa::path(
    post,
    path = "/v1/oauth/{provider}/native",
    tag = "social-login",
    params(("provider" = String, Path, description = "Provider id")),
    request_body = NativeLoginRequest,
    responses(
        (status = 200, description = "Tokens or challenge (authn-session login response)"),
        (status = 400, description = "oauth_nonce_invalid / oauth_native_not_supported", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "oauth_token_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "oauth_email_not_verified", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "oauth_link_required", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn native_login(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    Path(provider): Path<String>,
    Json(body): Json<NativeLoginRequest>,
) -> Result<Response, AuthError> {
    let outcome = service.native_login(&ctx, &provider, &body).await?;
    Ok(no_store(
        service.deps().sessions.login_response(outcome, None),
    ))
}

/// The caller's linked identities (SOC-06).
#[utoipa::path(
    get,
    path = "/v1/me/identities",
    tag = "social-login",
    responses(
        (status = 200, description = "Identities", body = IdentityList),
        (status = 401, description = "Not authenticated", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn list_identities(
    State(service): State<OidcClientService>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let identities = service.list_identities(&principal).await?;
    Ok(json(StatusCode::OK, IdentityList { identities }))
}

/// Starts linking a provider in the browser (SOC-06; step-up required).
#[utoipa::path(
    post,
    path = "/v1/me/identities/link",
    tag = "social-login",
    request_body = LinkStartRequest,
    responses(
        (status = 200, description = "Authorization URL; sets `__Host-authn_oauth`", body = LinkStartResponse),
        (status = 401, description = "Step-up required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "identity_link_not_allowed", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown provider", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn start_link(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    principal: Principal,
    headers: HeaderMap,
    Json(body): Json<LinkStartRequest>,
) -> Result<Response, AuthError> {
    let cookie = read_binding(&headers);
    let start = service
        .start_web_link(
            &ctx,
            &principal,
            &body.provider,
            body.return_to.as_deref(),
            cookie.as_deref(),
        )
        .await?;
    let response = json(
        StatusCode::OK,
        LinkStartResponse {
            authorization_url: start.authorization_url.to_string(),
        },
    );
    Ok(with_binding(response, &start))
}

/// Links a provider with a native ID token (SOC-06; step-up required).
#[utoipa::path(
    post,
    path = "/v1/me/identities/link/native",
    tag = "social-login",
    request_body = LinkNativeRequest,
    responses(
        (status = 201, description = "Linked", body = IdentitySummary),
        (status = 401, description = "Step-up required / oauth_token_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "identity_already_linked / identity_provider_already_linked", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn link_native(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    principal: Principal,
    Json(body): Json<LinkNativeRequest>,
) -> Result<Response, AuthError> {
    let identity = service
        .native_link(
            &ctx,
            &principal,
            &body.provider,
            &body.id_token,
            body.authorization_code.as_deref(),
        )
        .await?;
    Ok(json(StatusCode::CREATED, identity))
}

/// Unlinks an identity (SOC-06; step-up required; never the last way to
/// sign in).
#[utoipa::path(
    delete,
    path = "/v1/me/identities/{identity_id}",
    tag = "social-login",
    params(("identity_id" = String, Path, format = Uuid, description = "Identity id")),
    responses(
        (status = 204, description = "Unlinked"),
        (status = 401, description = "Step-up required", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "Unknown identity", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "identity_last_login_method", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn unlink_identity(
    State(service): State<OidcClientService>,
    ctx: RequestContext,
    principal: Principal,
    Path(identity_id): Path<IdentityId>,
) -> Result<Response, AuthError> {
    service.unlink(&ctx, &principal, identity_id).await?;
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}
