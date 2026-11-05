//! HTTP endpoints of the login flows (SES-01, SES-02, SES-18 … SES-22,
//! RSK-04).
//!
//! | Method & path | Requirement |
//! |---------------|-------------|
//! | `POST /v1/login/password` | SES-01 |
//! | `POST /v1/login/passkey/options` | SES-20 |
//! | `POST /v1/login/passkey` | SES-20, SES-21 |
//! | `POST /v1/login/magic-link` | SES-18 |
//! | `POST /v1/login/magic-link/verify` | SES-18 |
//! | `POST /v1/login/email-code` | SES-19 |
//! | `POST /v1/login/email-code/verify` | SES-19 |
//! | `POST /v1/login/challenge/verify` | SES-02 |
//! | `POST /v1/login/challenge/send-code` | SES-02, RSK-03 |
//! | `POST /v1/login/challenge/passkey/options` | SES-02 |
//! | `POST /v1/login/challenge/passkey/register/options` | SES-22, MFA-07 (K-112) |
//! | `POST /v1/login/challenge/passkey/register/verify` | SES-22, MFA-07 (K-112) |
//! | `POST /v1/login/challenge/step` | SES-22 |
//! | `POST /v1/login/not-me` | RSK-04 |
//!
//! Client kind: browsers are the default; native apps send
//! `X-Authn-Client: native` and receive tokens in the body. Web requests
//! need the login-CSRF proof (`GET /v1/csrf` + `X-CSRF-Token`); the
//! pending-challenge token travels in the `__Host-authn_challenge` cookie
//! (web) or the `X-Authn-Challenge` header (native).

use authn_account::SecretJson;
use authn_core::domain::ClientKind;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::ChallengeId;
use authn_core::ports::RequiredAction;
use authn_core::secret::SensitiveString;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::header::{CACHE_CONTROL, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};

use super::challenge::ChallengeOutcome;
use super::not_me::NotMeRequest;
use super::passkey::{PasskeyLogin, PasskeyLoginOptions, PasskeyLoginStart};
use super::password::PasswordLogin;
use super::passwordless::{EmailCodeVerify, MagicLinkRequest, MagicLinkVerify};
use super::pipeline::PipelineOutcome;
use super::{
    ChallengeStep, FactorSubmission, MAGIC_LINK_BINDING_COOKIE, PasskeyEnrollmentVerify,
    SendCodeChannel, single_cookie, trusted_device_token,
};
use crate::cookies::{self, CHALLENGE_COOKIE, PASSKEY_BINDING_COOKIE};
use crate::model::CurrentSession;
use crate::response::{ChallengeBody, CredentialsBody, challenge_response, credentials_parts};
use crate::service::{ChallengeState, ClientChannel, SessionService, remaining};

/// Request header selecting the native client flow.
pub const CLIENT_HEADER: HeaderName = HeaderName::from_static("x-authn-client");
/// Request header carrying the challenge token of native clients.
pub const CHALLENGE_HEADER: HeaderName = HeaderName::from_static("x-authn-challenge");

/// The login router (merged into [`crate::router`]).
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    SessionService: FromRef<S>,
{
    Router::new()
        .route("/v1/login/password", post(login_password))
        .route("/v1/login/passkey/options", post(passkey_options))
        .route("/v1/login/passkey", post(login_passkey))
        .route("/v1/login/magic-link", post(request_magic_link))
        .route("/v1/login/magic-link/verify", post(verify_magic_link))
        .route("/v1/login/email-code", post(request_email_code))
        .route("/v1/login/email-code/verify", post(verify_email_code))
        .route("/v1/login/challenge/verify", post(challenge_verify))
        .route("/v1/login/challenge/send-code", post(challenge_send_code))
        .route(
            "/v1/login/challenge/passkey/options",
            post(challenge_passkey_options),
        )
        .route(
            "/v1/login/challenge/passkey/register/options",
            post(challenge_passkey_register_options),
        )
        .route(
            "/v1/login/challenge/passkey/register/verify",
            post(challenge_passkey_register_verify),
        )
        .route("/v1/login/challenge/step", post(challenge_step))
        .route("/v1/login/not-me", post(not_me))
}

/// OpenAPI document of the login endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(
        login_password,
        passkey_options,
        login_passkey,
        request_magic_link,
        verify_magic_link,
        request_email_code,
        verify_email_code,
        challenge_verify,
        challenge_send_code,
        challenge_passkey_options,
        challenge_passkey_register_options,
        challenge_passkey_register_verify,
        challenge_step,
        not_me
    ),
    components(schemas(
        PasswordLogin,
        PasskeyLoginOptions,
        PasskeyLogin,
        LoginPasskeyOptionsResponse,
        MagicLinkRequest,
        MagicLinkVerify,
        PasswordlessStarted,
        EmailCodeVerify,
        FactorSubmission,
        SendCodeChannel,
        ChallengeStep,
        PasskeyEnrollmentVerify,
        LoginPasskeyRegistrationOptionsResponse,
        ChallengeStatusBody,
        ChallengeCompletedBody,
        LoginResponse,
        ChallengeStepResponse,
        NotMeRequest,
        NotMeResponse,
        CredentialsBody,
        ChallengeBody,
    )),
    tags((name = "login", description = "Login flows (SES-01, SES-02, SES-18 … SES-22)"))
)]
pub struct LoginApi;

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The client kind of a login request (`X-Authn-Client: native`).
fn client_kind(headers: &HeaderMap) -> Result<ClientKind, AuthError> {
    let mut values = headers.get_all(CLIENT_HEADER).iter();
    let Some(first) = values.next() else {
        return Ok(ClientKind::Web);
    };
    if values.next().is_some() {
        return Err(AuthError::new(codes::common::BAD_REQUEST).with_context("repeated client"));
    }
    match first.to_str().unwrap_or("") {
        "native" => Ok(ClientKind::Native),
        "web" => Ok(ClientKind::Web),
        _ => Err(AuthError::new(codes::common::BAD_REQUEST).with_context("unknown client")),
    }
}

/// The client channel: web requests must carry the login-CSRF proof.
fn channel(
    service: &SessionService,
    headers: &HeaderMap,
    current: Option<&CurrentSession>,
) -> Result<ClientChannel, AuthError> {
    match client_kind(headers)? {
        ClientKind::Native => Ok(ClientChannel::Native),
        ClientKind::Web => Ok(ClientChannel::Web(
            service.verify_login_csrf_request(headers, current)?,
        )),
    }
}

/// The challenge token: cookie (web) or header (native).
fn challenge_token(headers: &HeaderMap, client: ClientKind) -> Result<SensitiveString, AuthError> {
    let invalid = || AuthError::new(codes::session::CHALLENGE_INVALID);
    match client {
        ClientKind::Web => single_cookie(headers, CHALLENGE_COOKIE).ok_or_else(invalid),
        ClientKind::Native => {
            let mut values = headers.get_all(CHALLENGE_HEADER).iter();
            let first = values.next().ok_or_else(invalid)?;
            if values.next().is_some() {
                return Err(invalid());
            }
            first
                .to_str()
                .ok()
                .map(|v| SensitiveString::new(v.to_owned()))
                .ok_or_else(invalid)
        }
    }
}

/// Renders a pipeline result.
fn pipeline_response(service: &SessionService, outcome: PipelineOutcome) -> Response {
    let now = service.now();
    match outcome {
        PipelineOutcome::Established(established) => {
            let client = established.session.client_kind;
            session_response(
                &established.session,
                established.credentials,
                now,
                None,
                None,
                client,
            )
        }
        PipelineOutcome::Challenge(issued) => challenge_response(*issued, now),
    }
}

/// The credentials response with the extra fields of a completed
/// challenge; clears the challenge cookie of web clients.
fn session_response(
    record: &crate::model::SessionRecord,
    credentials: crate::model::IssuedCredentials,
    now: time::OffsetDateTime,
    trusted_device_token: Option<SensitiveString>,
    data: Option<serde_json::Value>,
    client: ClientKind,
) -> Response {
    let (credentials, cookies_to_set) = credentials_parts(record, credentials, now);
    let body = ChallengeCompletedBody {
        credentials,
        trusted_device_token,
        data,
    };
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    for cookie in cookies_to_set {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    if client == ClientKind::Web {
        response
            .headers_mut()
            .append(SET_COOKIE, cookies::clear_challenge_cookie());
    }
    no_store(response)
}

/// Body of a challenge that still has steps.
#[derive(Clone, Serialize, ToSchema)]
pub struct ChallengeStatusBody {
    /// `challenge_required`.
    pub status: &'static str,
    /// Challenge id.
    pub challenge_id: ChallengeId,
    /// Expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: time::OffsetDateTime,
    /// Second factors that may be used now.
    pub allowed_factors: Vec<authn_core::domain::FactorKind>,
    /// Outstanding steps.
    pub required_actions: Vec<RequiredAction>,
    /// Data of the step (TOTP secret, code destination, recovery codes) —
    /// shown once.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub data: Option<serde_json::Value>,
}

/// Body of a login that completed (`authenticated`): the issued
/// credentials plus, after the last challenge step, the trusted-device
/// token and the data of that step.
#[derive(Clone, Serialize, ToSchema)]
pub struct ChallengeCompletedBody {
    /// The issued credentials.
    #[serde(flatten)]
    pub credentials: CredentialsBody,
    /// Native clients that asked to trust the device (`trust_device`,
    /// MFA-09): the trusted-device token to send as
    /// `X-Trusted-Device` on later logins. Web clients receive the
    /// `__Host-authn_trusted_device` cookie instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub trusted_device_token: Option<SensitiveString>,
    /// Data the last step returned once (recovery codes after an MFA
    /// enrollment).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub data: Option<serde_json::Value>,
}

impl std::fmt::Debug for ChallengeCompletedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeCompletedBody")
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

/// `200` body of the login endpoints that start a login: signed in, or a
/// challenge with outstanding steps (tell them apart by `status`).
/// Documentation type of the OpenAPI document.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum LoginResponse {
    /// `status = authenticated`.
    Authenticated(CredentialsBody),
    /// `status = challenge_required`.
    ChallengeRequired(ChallengeBody),
}

/// `200` body of the challenge steps: signed in, or the next step (tell
/// them apart by `status`). Documentation type of the OpenAPI document.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum ChallengeStepResponse {
    /// `status = authenticated`.
    Authenticated(ChallengeCompletedBody),
    /// `status = challenge_required`.
    ChallengeRequired(ChallengeStatusBody),
}

impl std::fmt::Debug for ChallengeStatusBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeStatusBody")
            .field("challenge_id", &self.challenge_id)
            .finish_non_exhaustive()
    }
}

fn status_body(state: &ChallengeState, data: Option<serde_json::Value>) -> ChallengeStatusBody {
    ChallengeStatusBody {
        status: "challenge_required",
        challenge_id: state.id,
        expires_at: state.expires_at,
        allowed_factors: state.allowed_factors.clone(),
        required_actions: state.required_actions.clone(),
        data,
    }
}

/// Renders a challenge step result (trusted-device token: web cookie,
/// native body).
fn challenge_outcome_response(service: &SessionService, outcome: ChallengeOutcome) -> Response {
    let now = service.now();
    match outcome {
        ChallengeOutcome::Pending { challenge, data } => {
            no_store((StatusCode::OK, axum::Json(status_body(&challenge, data))).into_response())
        }
        ChallengeOutcome::Established {
            session,
            trusted_device,
            data,
        } => {
            let client = session.session.client_kind;
            let mut cookie = None;
            let mut device_token = None;
            if let Some(device) = trusted_device {
                match client {
                    ClientKind::Web => {
                        cookie = Some(cookies::trusted_device_cookie(
                            device.token.expose(),
                            remaining(now, device.expires_at),
                        ));
                    }
                    ClientKind::Native => {
                        device_token = Some(SensitiveString::new(device.token.expose().to_owned()));
                    }
                }
            }
            let mut response = session_response(
                &session.session,
                session.credentials,
                now,
                device_token,
                data,
                client,
            );
            if let Some(cookie) = cookie {
                response.headers_mut().append(SET_COOKIE, cookie);
            }
            response
        }
    }
}

/// SES-01: e-mail + password.
#[utoipa::path(
    post,
    path = "/v1/login/password",
    tag = "login",
    request_body = PasswordLogin,
    responses(
        (status = 200, description = "Signed in (`authenticated`) or more steps needed (`challenge_required`)", body = LoginResponse),
        (status = 401, description = "invalid_credentials (uniform)", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / `captcha_required` / `captcha_failed` (challenge in `details`) / account_suspended … (only after a correct password)", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited / login_temporarily_blocked (`Retry-After`)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn login_password(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<PasswordLogin>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let outcome = service
        .login_with_password(&ctx, body, client, trusted_device_token(&headers))
        .await?;
    Ok(pipeline_response(&service, outcome))
}

/// `POST /v1/login/passkey/options` response.
#[derive(Clone, Serialize, ToSchema)]
pub struct LoginPasskeyOptionsResponse {
    /// Ceremony id.
    pub ceremony_id: authn_core::id::CeremonyId,
    /// `CredentialRequestOptions`.
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

impl std::fmt::Debug for LoginPasskeyOptionsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginPasskeyOptionsResponse")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

fn passkey_options_response(
    service: &SessionService,
    start: PasskeyLoginStart,
    client: ClientKind,
) -> Response {
    let web = client == ClientKind::Web;
    let max_age = remaining(service.now(), start.expires_at);
    let cookie =
        web.then(|| cookies::passkey_binding_cookie(start.binding_token.expose(), max_age));
    let body = LoginPasskeyOptionsResponse {
        ceremony_id: start.ceremony_id,
        options: start.options,
        binding_token: (!web).then_some(start.binding_token),
        expires_at: start.expires_at,
    };
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    no_store(response)
}

/// SES-20: starts a username-less passkey login.
#[utoipa::path(
    post,
    path = "/v1/login/passkey/options",
    operation_id = "login_passkey_options",
    tag = "login",
    request_body = PasskeyLoginOptions,
    responses(
        (status = 200, description = "Ceremony started", body = LoginPasskeyOptionsResponse),
        (status = 403, description = "csrf_failed / passkey_not_available", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn passkey_options(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<PasskeyLoginOptions>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let start = service.start_passkey_login(&ctx, body).await?;
    Ok(passkey_options_response(&service, start, client.kind()))
}

/// SES-20, SES-21: finishes a passkey login.
#[utoipa::path(
    post,
    path = "/v1/login/passkey",
    tag = "login",
    request_body = PasskeyLogin,
    responses(
        (status = 200, description = "Signed in (`authenticated`) or more steps needed (`challenge_required`)", body = LoginResponse),
        (status = 401, description = "passkey_ceremony_invalid / passkey_verification_failed", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "csrf_failed / account status / organization policy", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn login_passkey(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<PasskeyLogin>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let binding = match client.kind() {
        ClientKind::Web => single_cookie(&headers, PASSKEY_BINDING_COOKIE),
        ClientKind::Native => None,
    };
    let web = client.kind() == ClientKind::Web;
    let outcome = service
        .login_with_passkey(&ctx, body, client, binding, trusted_device_token(&headers))
        .await?;
    let mut response = pipeline_response(&service, outcome);
    if web {
        response
            .headers_mut()
            .append(SET_COOKIE, cookies::clear_passkey_binding_cookie());
    }
    Ok(response)
}

/// Answer of the passwordless start endpoints (same for every address).
#[derive(Clone, Serialize, ToSchema)]
pub struct PasswordlessStarted {
    /// `sent` (also for unknown addresses).
    pub status: &'static str,
    /// Seconds the link / code stays valid.
    pub expires_in: u64,
    /// Native clients: the binding token (magic link) or challenge token
    /// (e-mail code). Web clients get a cookie instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub token: Option<SensitiveString>,
}

impl std::fmt::Debug for PasswordlessStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordlessStarted")
            .finish_non_exhaustive()
    }
}

fn passwordless_started(
    token: SensitiveString,
    expires_in: std::time::Duration,
    client: ClientKind,
    cookie: impl FnOnce(&str, std::time::Duration) -> HeaderValue,
) -> Response {
    let web = client == ClientKind::Web;
    let set = web.then(|| cookie(token.expose(), expires_in));
    let body = PasswordlessStarted {
        status: "sent",
        expires_in: expires_in.as_secs(),
        token: (!web).then_some(token),
    };
    let mut response = (StatusCode::ACCEPTED, axum::Json(body)).into_response();
    if let Some(set) = set {
        response.headers_mut().append(SET_COOKIE, set);
    }
    no_store(response)
}

/// SES-18: requests a magic link (same answer for every address).
#[utoipa::path(
    post,
    path = "/v1/login/magic-link",
    tag = "login",
    request_body = MagicLinkRequest,
    responses(
        (status = 202, description = "Accepted (also for unknown addresses)", body = PasswordlessStarted),
        (status = 403, description = "csrf_failed", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "validation_failed (e-mail syntax)", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn request_magic_link(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<MagicLinkRequest>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?.kind();
    let start = service.request_magic_link(&ctx, body, client).await?;
    Ok(passwordless_started(
        start.binding_token,
        start.expires_in,
        client,
        cookies::magic_link_binding_cookie,
    ))
}

/// SES-18: signs in with the token of a magic link (POST only).
#[utoipa::path(
    post,
    path = "/v1/login/magic-link/verify",
    tag = "login",
    request_body = MagicLinkVerify,
    responses(
        (status = 200, description = "Signed in (`authenticated`) or more steps needed (`challenge_required`)", body = LoginResponse),
        (status = 400, description = "invalid_or_expired_token", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "magic_link_confirmation_required (other device)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn verify_magic_link(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<MagicLinkVerify>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let web = client.kind() == ClientKind::Web;
    let binding = if web {
        single_cookie(&headers, MAGIC_LINK_BINDING_COOKIE)
    } else {
        None
    };
    let outcome = service
        .verify_magic_link(&ctx, body, client, binding)
        .await?;
    let mut response = pipeline_response(&service, outcome);
    if web {
        response
            .headers_mut()
            .append(SET_COOKIE, cookies::clear_magic_link_binding_cookie());
    }
    Ok(response)
}

/// SES-19: requests an e-mail login code (same answer for every address).
#[utoipa::path(
    post,
    path = "/v1/login/email-code",
    tag = "login",
    request_body = MagicLinkRequest,
    responses(
        (status = 202, description = "Accepted (also for unknown addresses)", body = PasswordlessStarted),
        (status = 403, description = "csrf_failed", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn request_email_code(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<MagicLinkRequest>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?.kind();
    let start = service.request_email_code(&ctx, body, client).await?;
    Ok(passwordless_started(
        start.challenge_token,
        start.expires_in,
        client,
        cookies::challenge_cookie,
    ))
}

/// SES-19: signs in with the e-mailed code.
#[utoipa::path(
    post,
    path = "/v1/login/email-code/verify",
    tag = "login",
    request_body = EmailCodeVerify,
    responses(
        (status = 200, description = "Signed in (`authenticated`) or more steps needed (`challenge_required`)", body = LoginResponse),
        (status = 400, description = "invalid_code (uniform)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn verify_email_code(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<EmailCodeVerify>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let token = challenge_token(&headers, client.kind())
        .map_err(|_| AuthError::new(codes::common::INVALID_CODE))?;
    let outcome = service
        .verify_email_code(&ctx, token.expose(), &body.code, client)
        .await?;
    Ok(pipeline_response(&service, outcome))
}

/// SES-02: verifies the second factor of a pending login.
#[utoipa::path(
    post,
    path = "/v1/login/challenge/verify",
    tag = "login",
    request_body = FactorSubmission,
    responses(
        (status = 200, description = "Signed in (`authenticated`), or the next step (`challenge_required`)", body = ChallengeStepResponse),
        (status = 400, description = "invalid_code", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "challenge_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "challenge_step_not_allowed / csrf_failed", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "too_many_attempts", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn challenge_verify(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<FactorSubmission>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let token = challenge_token(&headers, client.kind())?;
    let web = client.kind() == ClientKind::Web;
    let binding = if web {
        single_cookie(&headers, PASSKEY_BINDING_COOKIE)
    } else {
        None
    };
    let passkey = matches!(body, FactorSubmission::Passkey { .. });
    let outcome = service
        .verify_challenge_factor(&ctx, token.expose(), body, client, binding)
        .await?;
    let mut response = challenge_outcome_response(&service, outcome);
    if web && passkey {
        response
            .headers_mut()
            .append(SET_COOKIE, cookies::clear_passkey_binding_cookie());
    }
    Ok(response)
}

/// SES-02, RSK-03: sends a code for the current factor step.
#[utoipa::path(
    post,
    path = "/v1/login/challenge/send-code",
    tag = "login",
    request_body = SendCodeChannel,
    responses(
        (status = 202, description = "Code sent (masked destination)", body = Object),
        (status = 401, description = "challenge_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "challenge_step_not_allowed", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "cooldown / budget", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn challenge_send_code(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<SendCodeChannel>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?.kind();
    let token = challenge_token(&headers, client)?;
    let delivery = service
        .send_challenge_code(&ctx, token.expose(), body, client)
        .await?;
    Ok(no_store(
        (StatusCode::ACCEPTED, axum::Json(delivery)).into_response(),
    ))
}

/// SES-02: starts a passkey ceremony for the second-factor step.
#[utoipa::path(
    post,
    path = "/v1/login/challenge/passkey/options",
    tag = "login",
    responses(
        (status = 200, description = "Ceremony started", body = LoginPasskeyOptionsResponse),
        (status = 401, description = "challenge_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "challenge_step_not_allowed", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn challenge_passkey_options(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?.kind();
    let token = challenge_token(&headers, client)?;
    let start = service
        .start_challenge_passkey(&ctx, token.expose(), client)
        .await?;
    Ok(passkey_options_response(&service, start, client))
}

/// `POST /v1/login/challenge/passkey/register/options` response.
#[derive(Clone, Serialize, ToSchema)]
pub struct LoginPasskeyRegistrationOptionsResponse {
    /// Ceremony id.
    pub ceremony_id: authn_core::id::CeremonyId,
    /// `CredentialCreationOptions` for `navigator.credentials.create()` /
    /// the platform passkey APIs: `{"publicKey": {...}}`.
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

impl std::fmt::Debug for LoginPasskeyRegistrationOptionsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginPasskeyRegistrationOptionsResponse")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

/// SES-22, MFA-07 (K-112): starts registering a passkey for the
/// `enroll_mfa` step of a pending login (`allowed_factors` contains
/// `webauthn`; no `verify_mfa` step outstanding).
#[utoipa::path(
    post,
    path = "/v1/login/challenge/passkey/register/options",
    tag = "login",
    responses(
        (status = 200, description = "Ceremony started (web: binding cookie)", body = LoginPasskeyRegistrationOptionsResponse),
        (status = 401, description = "challenge_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "challenge_step_not_allowed / csrf_failed / passkey_not_allowed (organization AAGUID policy) / passkey_not_available", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "passkey_limit_reached", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "rate_limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn challenge_passkey_register_options(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?.kind();
    let token = challenge_token(&headers, client)?;
    let start = service
        .start_challenge_passkey_enrollment(&ctx, token.expose(), client)
        .await?;
    let web = client == ClientKind::Web;
    let max_age = remaining(service.now(), start.expires_at);
    let cookie =
        web.then(|| cookies::passkey_binding_cookie(start.binding_token.expose(), max_age));
    let body = LoginPasskeyRegistrationOptionsResponse {
        ceremony_id: start.ceremony_id,
        options: start.options,
        binding_token: (!web).then_some(start.binding_token),
        expires_at: start.expires_at,
    };
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    Ok(no_store(response))
}

/// SES-22, MFA-07 (K-112): finishes the passkey registration of the
/// `enroll_mfa` step; the passkey becomes the second factor of this login.
#[utoipa::path(
    post,
    path = "/v1/login/challenge/passkey/register/verify",
    tag = "login",
    request_body = PasskeyEnrollmentVerify,
    responses(
        (status = 200, description = "Signed in (`authenticated`), or the next step (`challenge_required`); `data.passkey` is the new passkey", body = ChallengeStepResponse),
        (status = 400, description = "passkey_ceremony_invalid / passkey_registration_failed / validation_failed (name)", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "challenge_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "challenge_step_not_allowed / csrf_failed / passkey_not_allowed (organization AAGUID policy)", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "passkey_already_registered / passkey_limit_reached", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn challenge_passkey_register_verify(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<PasskeyEnrollmentVerify>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let token = challenge_token(&headers, client.kind())?;
    let web = client.kind() == ClientKind::Web;
    let binding = if web {
        single_cookie(&headers, PASSKEY_BINDING_COOKIE)
    } else {
        None
    };
    let outcome = service
        .complete_challenge_passkey_enrollment(&ctx, token.expose(), body, client, binding)
        .await?;
    let mut response = challenge_outcome_response(&service, outcome);
    if web {
        response
            .headers_mut()
            .append(SET_COOKIE, cookies::clear_passkey_binding_cookie());
    }
    Ok(response)
}

/// SES-22: performs a required action of a pending login.
#[utoipa::path(
    post,
    path = "/v1/login/challenge/step",
    tag = "login",
    request_body = ChallengeStep,
    responses(
        (status = 200, description = "Signed in (`authenticated`), or the next step (`challenge_required`)", body = ChallengeStepResponse),
        (status = 401, description = "challenge_invalid", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "challenge_step_not_allowed", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "password policy / validation", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn challenge_step(
    State(service): State<SessionService>,
    ctx: RequestContext,
    headers: HeaderMap,
    current: Option<CurrentSession>,
    SecretJson(body): SecretJson<ChallengeStep>,
) -> Result<Response, AuthError> {
    let client = channel(&service, &headers, current.as_ref())?;
    let token = challenge_token(&headers, client.kind())?;
    let outcome = service
        .complete_challenge_step(&ctx, token.expose(), body, client)
        .await?;
    Ok(challenge_outcome_response(&service, outcome))
}

/// `POST /v1/login/not-me` response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct NotMeResponse {
    /// `secured`.
    pub status: &'static str,
    /// Sessions ended.
    pub sessions_revoked: u64,
}

/// RSK-04: "this wasn't me" — ends every session and trusted device and
/// forces a password reset.
#[utoipa::path(
    post,
    path = "/v1/login/not-me",
    tag = "login",
    request_body = NotMeRequest,
    responses(
        (status = 200, description = "Account secured", body = NotMeResponse),
        (status = 400, description = "invalid_or_expired_token", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn not_me(
    State(service): State<SessionService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<NotMeRequest>,
) -> Result<Response, AuthError> {
    let revoked = service.report_not_me(&ctx, body).await?;
    Ok(no_store(
        axum::Json(NotMeResponse {
            status: "secured",
            sessions_revoked: revoked,
        })
        .into_response(),
    ))
}
