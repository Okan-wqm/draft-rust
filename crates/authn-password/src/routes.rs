//! HTTP endpoints of authn-password (ARC-03, ARC-09).
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `POST` | `/v1/password/check` | — | PWD-01…05 |
//! | `POST` | `/v1/password/forgot` | — | PWD-07, PWD-08 |
//! | `POST` | `/v1/password/reset` | — (link token or e-mail + code) | PWD-08, PWD-09 |
//! | `POST` | `/v1/me/password/change` | session | PWD-06 |
//! | `POST` | `/v1/me/password` | session + step-up | PWD-10 |
//! | `DELETE` | `/v1/me/password` | session + step-up | PWD-11 |
//!
//! Bodies are read with [`SecretJson`] (rejections never echo content) and
//! every request type has a redacted `Debug` (`SecretString`).

use authn_core::domain::{EmailAddress, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::{Json, RequestContext};
use authn_core::ports::{PasswordCheck, PasswordViolation};
use authn_core::secret::SecretString;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::extract::SecretJson;
use crate::service::{PasswordService, ResetProof};

/// Longest display name accepted by the check endpoint (characters).
const MAX_DISPLAY_NAME_CHARS: usize = 256;

/// The module router. Requires [`PasswordService`] from the state; the
/// `/v1/me/*` routes additionally require the session middleware to insert
/// a [`Principal`].
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    PasswordService: FromRef<S>,
{
    Router::new()
        .route("/v1/password/check", post(check_password))
        .route("/v1/password/forgot", post(forgot_password))
        .route("/v1/password/reset", post(reset_password))
        .route("/v1/me/password/change", post(change_password))
        .route(
            "/v1/me/password",
            post(add_password).delete(remove_password),
        )
}

/// OpenAPI document of this crate's endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(
        check_password,
        forgot_password,
        reset_password,
        change_password,
        add_password,
        remove_password
    ),
    components(schemas(
        CheckPasswordRequest,
        PasswordCheckResponse,
        Violation,
        ForgotPasswordRequest,
        ResetPasswordRequest,
        ChangePasswordRequest,
        AddPasswordRequest,
        StatusResponse,
    )),
    tags((name = "password", description = "Password policy, change and reset"))
)]
pub struct PasswordApi;

// --- request / response types ------------------------------------------------

/// Body of `POST /v1/password/check`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckPasswordRequest {
    /// Candidate password (never logged or stored).
    #[schema(value_type = String, format = Password)]
    pub password: SecretString,
    /// E-mail address typed in the form, used as a strength input. Invalid
    /// addresses are ignored.
    #[schema(value_type = Option<String>)]
    pub email: Option<String>,
    /// Display name typed in the form, used as a strength input.
    pub display_name: Option<String>,
}

/// A policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Violation {
    /// Shorter than the minimum.
    TooShort {
        /// Minimum length in characters.
        min: u32,
    },
    /// Longer than the maximum.
    TooLong {
        /// Maximum length in characters.
        max: u32,
    },
    /// Found in breach corpora.
    Breached,
    /// Too easy to guess.
    TooWeak {
        /// zxcvbn score 0–4.
        score: u8,
        /// Required score.
        min_score: u8,
    },
}

impl From<PasswordViolation> for Violation {
    fn from(v: PasswordViolation) -> Self {
        match v {
            PasswordViolation::TooShort { min } => Self::TooShort { min },
            PasswordViolation::TooLong { max } => Self::TooLong { max },
            PasswordViolation::Breached => Self::Breached,
            PasswordViolation::TooWeak { score, min_score } => Self::TooWeak { score, min_score },
        }
    }
}

/// Result of `POST /v1/password/check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PasswordCheckResponse {
    /// Whether the password satisfies the policy.
    pub acceptable: bool,
    /// zxcvbn score 0–4.
    pub score: u8,
    /// Violations (empty when acceptable).
    pub violations: Vec<Violation>,
    /// Localized feedback (TR/EN, `Accept-Language`).
    pub feedback: Vec<String>,
    /// The breach lookup could not run (fail-open).
    pub breach_check_skipped: bool,
}

impl From<PasswordCheck> for PasswordCheckResponse {
    fn from(check: PasswordCheck) -> Self {
        Self {
            acceptable: check.is_acceptable(),
            score: check.score,
            violations: check.violations.into_iter().map(Violation::from).collect(),
            feedback: check.feedback,
            breach_check_skipped: check.breach_check_skipped,
        }
    }
}

/// Body of `POST /v1/password/forgot`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ForgotPasswordRequest {
    /// The account's e-mail address.
    pub email: EmailAddress,
}

/// Body of `POST /v1/password/reset`: either `token` (link) or `email` +
/// `code` (mobile), plus `new_password`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResetPasswordRequest {
    /// Token from the reset link.
    #[schema(value_type = Option<String>)]
    pub token: Option<SecretString>,
    /// Address the code was sent to (code flow).
    pub email: Option<EmailAddress>,
    /// Six-digit code (code flow).
    #[schema(value_type = Option<String>)]
    pub code: Option<SecretString>,
    /// The new password.
    #[schema(value_type = String, format = Password)]
    pub new_password: SecretString,
}

/// Body of `POST /v1/me/password/change`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    /// The current password; may be omitted right after a step-up
    /// (re-authentication within `session.step_up_max_age`).
    #[schema(value_type = Option<String>, format = Password)]
    pub current_password: Option<SecretString>,
    /// The new password.
    #[schema(value_type = String, format = Password)]
    pub new_password: SecretString,
}

/// Body of `POST /v1/me/password`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddPasswordRequest {
    /// The password to add.
    #[schema(value_type = String, format = Password)]
    pub new_password: SecretString,
}

/// Fixed acknowledgement body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct StatusResponse {
    /// `accepted` (forgot) or `password_reset` (reset).
    pub status: &'static str,
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// --- handlers ------------------------------------------------------------------

/// Live password policy check for registration and change forms (PWD-05).
/// Rate limited per IP; the password is never logged or stored.
#[utoipa::path(
    post,
    path = "/v1/password/check",
    tag = "password",
    request_body = CheckPasswordRequest,
    responses(
        (status = 200, description = "Policy verdict with localized feedback", body = PasswordCheckResponse),
        (status = 422, description = "Malformed body", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited (Retry-After)", body = authn_core::error::ErrorEnvelope),
        (status = 503, description = "Breach check unavailable (fail-closed)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn check_password(
    State(service): State<PasswordService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<CheckPasswordRequest>,
) -> Result<Response, AuthError> {
    if body
        .display_name
        .as_deref()
        .is_some_and(|n| n.chars().count() > MAX_DISPLAY_NAME_CHARS)
    {
        return Err(AuthError::new(codes::common::VALIDATION_FAILED));
    }
    let email = body
        .email
        .as_deref()
        .and_then(|e| EmailAddress::parse(e).ok());
    let check = service
        .check_password(&ctx, &body.password, email, body.display_name)
        .await?;
    Ok(no_store(
        Json(PasswordCheckResponse::from(check)).into_response(),
    ))
}

/// Requests a password reset (PWD-07, PWD-08). The answer is identical —
/// status, body and timing — whether or not an account exists; if one does,
/// a link and (for mobile) a 6-digit code are e-mailed.
#[utoipa::path(
    post,
    path = "/v1/password/forgot",
    tag = "password",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 202, description = "Accepted (always, for any well-formed address)", body = StatusResponse),
        (status = 422, description = "Malformed e-mail address", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited per IP or per address (Retry-After)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn forgot_password(
    State(service): State<PasswordService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<ForgotPasswordRequest>,
) -> Result<Response, AuthError> {
    service.request_reset(&ctx, &body.email).await?;
    Ok(no_store(
        (
            StatusCode::ACCEPTED,
            Json(StatusResponse { status: "accepted" }),
        )
            .into_response(),
    ))
}

/// Completes a password reset with the link token or with e-mail + code
/// (PWD-08, PWD-09). Revokes every session, refresh token and trusted
/// device; no session is issued — the next login (with MFA if enabled)
/// follows.
#[utoipa::path(
    post,
    path = "/v1/password/reset",
    tag = "password",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password replaced", body = StatusResponse),
        (status = 400, description = "invalid_or_expired_token / invalid_code", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "password_policy_violation or malformed body", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited (Retry-After)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn reset_password(
    State(service): State<PasswordService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<ResetPasswordRequest>,
) -> Result<Response, AuthError> {
    let proof = match (body.token, body.email, body.code) {
        (Some(token), None, None) => ResetProof::Link { token },
        (None, Some(email), Some(code)) => ResetProof::Code { email, code },
        _ => return Err(AuthError::new(codes::common::VALIDATION_FAILED)),
    };
    service
        .complete_reset(&ctx, proof, &body.new_password)
        .await?;
    Ok(no_store(
        Json(StatusResponse {
            status: "password_reset",
        })
        .into_response(),
    ))
}

/// Changes the caller's password (PWD-06): requires the current password or
/// a recent step-up; other sessions are signed out.
#[utoipa::path(
    post,
    path = "/v1/me/password/change",
    tag = "password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed"),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "current_password_incorrect / forbidden", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "password_not_set", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "password_policy_violation / password_unchanged", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited (Retry-After)", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn change_password(
    State(service): State<PasswordService>,
    ctx: RequestContext,
    principal: Principal,
    SecretJson(body): SecretJson<ChangePasswordRequest>,
) -> Result<StatusCode, AuthError> {
    service
        .change_password(
            &ctx,
            &principal,
            body.current_password.as_ref(),
            &body.new_password,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Adds a password to a passwordless account (PWD-10). Requires step-up.
#[utoipa::path(
    post,
    path = "/v1/me/password",
    tag = "password",
    request_body = AddPasswordRequest,
    responses(
        (status = 204, description = "Password added"),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "password_already_set", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "password_policy_violation", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn add_password(
    State(service): State<PasswordService>,
    ctx: RequestContext,
    principal: Principal,
    SecretJson(body): SecretJson<AddPasswordRequest>,
) -> Result<StatusCode, AuthError> {
    service
        .add_password(&ctx, &principal, &body.new_password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes the caller's password (PWD-11): requires step-up and another
/// strong sign-in method (passkey or linked identity).
#[utoipa::path(
    delete,
    path = "/v1/me/password",
    tag = "password",
    responses(
        (status = 204, description = "Password removed"),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "password_not_set / password_removal_not_allowed", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn remove_password(
    State(service): State<PasswordService>,
    ctx: RequestContext,
    principal: Principal,
) -> Result<StatusCode, AuthError> {
    service.remove_password(&ctx, &principal).await?;
    Ok(StatusCode::NO_CONTENT)
}
