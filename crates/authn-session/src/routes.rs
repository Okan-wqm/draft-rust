//! HTTP endpoints of the session core (ARC-03, ARC-09).
//!
//! | Method & path | Requirement | Auth |
//! |---------------|-------------|------|
//! | `GET /v1/csrf` | SES-04 | optional (session → session token, else pre-session token) |
//! | `GET /v1/me` | SES-16 | session |
//! | `GET /v1/me/sessions` | SES-11 | session |
//! | `DELETE /v1/me/sessions/{session_id}` | SES-11 | session |
//! | `POST /v1/me/sessions/revoke-others` | SES-11 | session |
//! | `POST /v1/logout` | SES-12 | session |
//! | `POST /v1/logout/all` | SES-11, SES-12 | session |
//! | `POST /v1/session/org` | SES-17 | session |
//! | `POST /v1/reauth` | SES-13 | session |
//! | `POST /v1/reauth/passkey/options` | SES-13 | session (`passkey_not_available` without the `passkey` feature) |
//! | `POST /v1/token/refresh` | SES-05 | refresh token in the body |
//! | `POST /v1/token/introspect` | SES-10 | organization API key |
//! | `GET /.well-known/jwks.json` | SES-09 | none |

use authn_account::SecretJson;
use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::{Json, Path, RequestContext};
use authn_core::id::SessionId;
use authn_core::secret::SensitiveString;
use authn_crypto::jwt::JwkSet;
use authn_crypto::token::{OpaqueToken, TokenHash};
use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::cookies::{self, CookieValue, PASSKEY_BINDING_COOKIE, PRE_SESSION_COOKIE, read_cookie};
use crate::model::CurrentSession;
use crate::response::{ChallengeBody, CredentialsBody, credentials_response};
use crate::service::{
    IntrospectionResponse, MeResponse, OrgSwitch, RefreshedTokens, SessionService, SessionSummary,
    StepUpProof,
};

/// `Clear-Site-Data` (SES-12).
pub const CLEAR_SITE_DATA: HeaderName = HeaderName::from_static("clear-site-data");

/// The session router. Mount it **behind** [`crate::authenticate`] (the
/// endpoints read the `Principal` it inserts) — except that the refresh,
/// introspection and JWKS endpoints need no principal.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    SessionService: FromRef<S>,
{
    Router::new()
        .route("/v1/csrf", get(csrf_token))
        .route("/v1/me", get(me))
        .route("/v1/me/sessions", get(list_sessions))
        .route("/v1/me/sessions/{session_id}", delete(revoke_session))
        .route("/v1/me/sessions/revoke-others", post(revoke_other_sessions))
        .route("/v1/logout", post(logout))
        .route("/v1/logout/all", post(logout_all))
        .route("/v1/session/org", post(switch_org))
        .route("/v1/reauth", post(reauth))
        .route("/v1/reauth/passkey/options", post(passkey_options))
        .route("/v1/token/refresh", post(refresh))
        .route("/v1/token/introspect", post(introspect))
        .route("/.well-known/jwks.json", get(jwks))
        .merge(crate::login::routes::router())
}

/// OpenAPI document of the session endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(
        csrf_token,
        me,
        list_sessions,
        revoke_session,
        revoke_other_sessions,
        logout,
        logout_all,
        switch_org,
        reauth,
        passkey_options,
        refresh,
        introspect,
        jwks
    ),
    components(schemas(
        CsrfTokenResponse,
        MeResponse,
        SessionSummary,
        SessionList,
        RevokedCount,
        OrgSwitch,
        StepUpProof,
        PasskeyOptionsResponse,
        CredentialsBody,
        ChallengeBody,
        RefreshRequest,
        RefreshedTokens,
        IntrospectionRequest,
        IntrospectionResponse,
    )),
    tags((name = "session", description = "Sessions, tokens, CSRF, step-up (SES-*)"))
)]
pub struct SessionApi;

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /v1/csrf` response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CsrfTokenResponse {
    /// Value for the `X-CSRF-Token` header.
    pub csrf_token: String,
    /// `session` (bound to the current session) or `pre_session` (login
    /// forms, bound to the `__Host-authn_csrf` cookie).
    pub kind: &'static str,
}

/// Returns the CSRF token of the current session, or a pre-session token
/// for login forms (setting the `__Host-authn_csrf` cookie when needed).
#[utoipa::path(
    get,
    path = "/v1/csrf",
    tag = "session",
    responses(
        (status = 200, description = "CSRF token", body = CsrfTokenResponse),
    )
)]
pub async fn csrf_token(
    State(service): State<SessionService>,
    headers: HeaderMap,
    current: Option<CurrentSession>,
) -> Result<Response, AuthError> {
    if let Some(current) = current
        && let Some(hash) = current.token_hash
    {
        let token = service
            .csrf()
            .session_token(current.record.id, &TokenHash::from_bytes(hash))?;
        return Ok(no_store(
            axum::Json(CsrfTokenResponse {
                csrf_token: token,
                kind: "session",
            })
            .into_response(),
        ));
    }
    let existing = match read_cookie(&headers, PRE_SESSION_COOKIE) {
        CookieValue::One(value) => OpaqueToken::parse(&value).ok(),
        _ => None,
    };
    let (secret, set_cookie) = match existing {
        Some(secret) => (secret, None),
        None => {
            let secret = OpaqueToken::generate().map_err(AuthError::from)?;
            let cookie = cookies::pre_session_cookie(secret.expose());
            (secret, Some(cookie))
        }
    };
    let token = service.csrf().pre_session_token(&secret)?;
    let mut response = axum::Json(CsrfTokenResponse {
        csrf_token: token,
        kind: "pre_session",
    })
    .into_response();
    if let Some(cookie) = set_cookie {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    Ok(no_store(response))
}

/// The signed-in user (SES-16).
#[utoipa::path(
    get,
    path = "/v1/me",
    tag = "session",
    responses(
        (status = 200, description = "The caller", body = MeResponse),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn me(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
    current: CurrentSession,
) -> Result<Response, AuthError> {
    let me = service.me(&ctx, &principal, current.record()).await?;
    Ok(no_store(axum::Json(me).into_response()))
}

/// `GET /v1/me/sessions` response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionList {
    /// Live sessions, newest first.
    pub sessions: Vec<SessionSummary>,
}

/// The caller's live sessions (SES-11).
#[utoipa::path(
    get,
    path = "/v1/me/sessions",
    tag = "session",
    responses(
        (status = 200, description = "Sessions", body = SessionList),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn list_sessions(
    State(service): State<SessionService>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let sessions = service.list_sessions(&principal).await?;
    Ok(no_store(
        axum::Json(SessionList { sessions }).into_response(),
    ))
}

fn logged_out(web: bool) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    if web {
        response
            .headers_mut()
            .append(SET_COOKIE, cookies::clear_session_cookie());
        response
            .headers_mut()
            .insert(CLEAR_SITE_DATA, HeaderValue::from_static("\"cookies\""));
    }
    no_store(response)
}

fn is_web(current: Option<&CurrentSession>) -> bool {
    current.is_some_and(CurrentSession::is_cookie)
}

/// Revokes one of the caller's sessions (SES-11). Another user's session
/// is `404`.
#[utoipa::path(
    delete,
    path = "/v1/me/sessions/{session_id}",
    tag = "session",
    params(("session_id" = SessionId, Path, description = "Session id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / forbidden", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "not_found", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn revoke_session(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
    current: Option<CurrentSession>,
    Path(session_id): Path<SessionId>,
) -> Result<Response, AuthError> {
    let was_current = service
        .revoke_own_session(&ctx, &principal, session_id)
        .await?;
    Ok(logged_out(was_current && is_web(current.as_ref())))
}

/// Number of revoked sessions.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RevokedCount {
    /// Sessions revoked.
    pub revoked: u64,
}

/// Signs out every other session of the caller (SES-11); also revokes the
/// trusted devices (MFA-09).
#[utoipa::path(
    post,
    path = "/v1/me/sessions/revoke-others",
    tag = "session",
    responses(
        (status = 200, description = "Revoked", body = RevokedCount),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / forbidden", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn revoke_other_sessions(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
) -> Result<Response, AuthError> {
    let revoked = service.revoke_other_sessions(&ctx, &principal).await?;
    Ok(no_store(
        axum::Json(RevokedCount { revoked }).into_response(),
    ))
}

/// Logout (SES-12): revokes the session and its refresh tokens; web
/// clients get the cookie deleted and `Clear-Site-Data: "cookies"`.
#[utoipa::path(
    post,
    path = "/v1/logout",
    tag = "session",
    responses(
        (status = 204, description = "Signed out"),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn logout(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
    current: Option<CurrentSession>,
) -> Result<Response, AuthError> {
    service.logout(&ctx, &principal).await?;
    Ok(logged_out(is_web(current.as_ref())))
}

/// Signs out everywhere (SES-11, SES-12): every session of the user and
/// the trusted devices (MFA-09).
#[utoipa::path(
    post,
    path = "/v1/logout/all",
    tag = "session",
    responses(
        (status = 204, description = "Signed out everywhere"),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / forbidden", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn logout_all(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
    current: Option<CurrentSession>,
) -> Result<Response, AuthError> {
    service.logout_everywhere(&ctx, &principal).await?;
    Ok(logged_out(is_web(current.as_ref())))
}

/// Switches the active organization (SES-17); rotates the session.
#[utoipa::path(
    post,
    path = "/v1/session/org",
    tag = "session",
    request_body = OrgSwitch,
    responses(
        (status = 200, description = "New credentials", body = CredentialsBody),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / org_policy_mfa_required / org_policy_ip_denied / login_method_not_allowed", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "not_found (no membership)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn switch_org(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
    current: CurrentSession,
    Json(body): Json<OrgSwitch>,
) -> Result<Response, AuthError> {
    let (record, credentials) = service
        .switch_org(&ctx, &principal, &current, body.org_id)
        .await?;
    if current.is_impersonation_header() {
        // K-12: never a `Set-Cookie` for a header-authenticated
        // impersonation (it would replace the admin's session cookie).
        return Ok(crate::response::impersonation_credentials_response(
            &record,
            credentials,
            service.now(),
        ));
    }
    Ok(credentials_response(&record, credentials, service.now()))
}

/// Step-up re-authentication (SES-13); rotates the session.
#[utoipa::path(
    post,
    path = "/v1/reauth",
    tag = "session",
    request_body = StepUpProof,
    responses(
        (status = 200, description = "Re-authenticated; new credentials", body = CredentialsBody),
        (status = 401, description = "unauthenticated / reauthentication_failed", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / step_up_method_not_allowed / forbidden", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited / too_many_attempts", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn reauth(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
    current: CurrentSession,
    headers: HeaderMap,
    SecretJson(proof): SecretJson<StepUpProof>,
) -> Result<Response, AuthError> {
    let binding = match read_cookie(&headers, PASSKEY_BINDING_COOKIE) {
        CookieValue::One(value) if current.is_cookie() => Some(SensitiveString::new(value)),
        _ => None,
    };
    let passkey = matches!(proof, StepUpProof::Passkey { .. });
    let (record, credentials) = service
        .step_up(&ctx, &principal, &current, proof, binding)
        .await?;
    let mut response = credentials_response(&record, credentials, service.now());
    if passkey && current.is_cookie() {
        response
            .headers_mut()
            .append(SET_COOKIE, cookies::clear_passkey_binding_cookie());
    }
    Ok(response)
}

/// `POST /v1/reauth/passkey/options` response.
#[derive(Clone, Serialize, ToSchema)]
pub struct PasskeyOptionsResponse {
    /// Ceremony id (send back with the assertion).
    pub ceremony_id: authn_core::id::CeremonyId,
    /// `CredentialRequestOptions` for `navigator.credentials.get()`.
    #[schema(value_type = Object)]
    pub options: serde_json::Value,
    /// Native clients: the binding token (web clients get a cookie).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub binding_token: Option<SensitiveString>,
    /// Ceremony expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: time::OffsetDateTime,
}

impl std::fmt::Debug for PasskeyOptionsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyOptionsResponse")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

/// Starts a passkey step-up ceremony bound to the current session (SES-13).
#[utoipa::path(
    post,
    path = "/v1/reauth/passkey/options",
    operation_id = "reauth_passkey_options",
    tag = "session",
    responses(
        (status = 200, description = "WebAuthn request options", body = PasskeyOptionsResponse),
        (status = 400, description = "passkey_not_available", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / forbidden", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn passkey_options(
    State(service): State<SessionService>,
    ctx: RequestContext,
    principal: Principal,
    current: CurrentSession,
) -> Result<Response, AuthError> {
    let start = service
        .start_passkey_step_up(&ctx, &principal, &current)
        .await?;
    let web = current.is_cookie();
    let cookie = web.then(|| {
        cookies::passkey_binding_cookie(
            start.binding_token.expose(),
            service.settings().passkey_ceremony_ttl,
        )
    });
    let body = PasskeyOptionsResponse {
        ceremony_id: start.ceremony_id,
        options: start.options,
        binding_token: (!web).then_some(start.binding_token),
        expires_at: start.expires_at,
    };
    let mut response = axum::Json(body).into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    Ok(no_store(response))
}

/// Body of `POST /v1/token/refresh`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    /// The current refresh token.
    #[schema(value_type = String)]
    pub refresh_token: SensitiveString,
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshRequest")
    }
}

/// Rotates a refresh token (SES-05). A replayed token revokes its whole
/// family; every failure is `invalid_refresh_token`.
#[utoipa::path(
    post,
    path = "/v1/token/refresh",
    tag = "session",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "New tokens", body = RefreshedTokens),
        (status = 401, description = "invalid_refresh_token", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn refresh(
    State(service): State<SessionService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<RefreshRequest>,
) -> Result<Response, AuthError> {
    let tokens = service.refresh(&ctx, body.refresh_token.expose()).await?;
    Ok(no_store(axum::Json(tokens).into_response()))
}

/// Body of `POST /v1/token/introspect` (form or JSON, RFC 7662 §2.1).
#[derive(Clone, Deserialize, ToSchema)]
pub struct IntrospectionRequest {
    /// The token.
    #[schema(value_type = String)]
    pub token: SensitiveString,
    /// `access_token` / `refresh_token`.
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

impl std::fmt::Debug for IntrospectionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IntrospectionRequest")
    }
}

/// Token introspection (SES-10, RFC 7662). The client authenticates with an
/// organization API key; it only sees tokens of its own organization.
#[utoipa::path(
    post,
    path = "/v1/token/introspect",
    tag = "session",
    request_body(content = IntrospectionRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Introspection result", body = IntrospectionResponse),
        (status = 401, description = "unauthenticated (API key)", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited", body = authn_core::error::ErrorEnvelope),
    ),
    security(("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn introspect(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AuthError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let request: IntrospectionRequest = if content_type.starts_with("application/json") {
        serde_json::from_slice(&body).map_err(|_| AuthError::new(codes::common::BAD_REQUEST))?
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        parse_form(&body)?
    } else {
        return Err(AuthError::new(codes::common::UNSUPPORTED_MEDIA_TYPE));
    };
    let response = service
        .introspect(
            &ctx,
            &headers,
            request.token.expose(),
            request.token_type_hint.as_deref(),
        )
        .await
        .map_err(|err| {
            if err.code() == codes::common::UNAUTHENTICATED {
                err.with_context("introspection client authentication failed")
            } else {
                err
            }
        })?;
    Ok(no_store(axum::Json(response).into_response()))
}

/// Minimal `application/x-www-form-urlencoded` parser for the two RFC 7662
/// parameters (percent-decoding via `url`). Duplicate parameters are
/// refused.
fn parse_form(body: &[u8]) -> Result<IntrospectionRequest, AuthError> {
    let mut token = None;
    let mut hint = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        let slot = match key.as_ref() {
            "token" => &mut token,
            "token_type_hint" => &mut hint,
            _ => continue,
        };
        if slot.is_some() {
            return Err(AuthError::new(codes::common::BAD_REQUEST));
        }
        *slot = Some(value.into_owned());
    }
    let token = token.ok_or_else(|| AuthError::new(codes::common::VALIDATION_FAILED))?;
    Ok(IntrospectionRequest {
        token: SensitiveString::new(token),
        token_type_hint: hint,
    })
}

/// The JSON Web Key Set (SES-09): public keys only, cacheable.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "session",
    responses(
        (status = 200, description = "JWKS", body = Object),
    )
)]
pub async fn jwks(State(service): State<SessionService>) -> Result<Response, AuthError> {
    let set: JwkSet = service.jwks().await?;
    let mut response = axum::Json(set).into_response();
    let max_age = service.settings().jwks_max_age.as_secs();
    if let Ok(value) = HeaderValue::from_str(&format!("public, max-age={max_age}")) {
        response.headers_mut().insert(CACHE_CONTROL, value);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use utoipa::OpenApi as _;

    #[test]
    fn ses_09_openapi_documents_every_session_endpoint() {
        let doc = serde_json::to_value(super::SessionApi::openapi()).unwrap();
        for path in [
            "/v1/csrf",
            "/v1/me",
            "/v1/me/sessions",
            "/v1/me/sessions/{session_id}",
            "/v1/me/sessions/revoke-others",
            "/v1/logout",
            "/v1/logout/all",
            "/v1/session/org",
            "/v1/reauth",
            "/v1/reauth/passkey/options",
            "/v1/token/refresh",
            "/v1/token/introspect",
            "/.well-known/jwks.json",
        ] {
            assert!(doc["paths"][path].is_object(), "{path} undocumented");
        }
    }
}
