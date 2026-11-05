//! HTTP endpoints of authn-account (ARC-03, ARC-09).
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `POST` | `/v1/signup` | — (sets the registration handle cookie) | ACC-01, 02, 03, 12, 13 |
//! | `POST` | `/v1/email/verification/resend` | — | ACC-04 |
//! | `POST` | `/v1/email/verify` | — (link token + handle / password / new password, or code + handle) | ACC-04, ADR 0002 |
//! | `POST` | `/v1/email/change/confirm` | session (link token) | ACC-07, ADR 0002 |
//! | `POST` | `/v1/email/change/revert` | — (link token) | ACC-07 |
//! | `POST` | `/v1/account/deletion/cancel` | — (link token) | ACC-09 |
//! | `GET` | `/v1/terms` | — | ACC-11 |
//! | `GET`, `PATCH` | `/v1/me/profile` | session | ACC-08 |
//! | `POST` | `/v1/me/email/verification` | session | ACC-04 |
//! | `POST` | `/v1/me/email/verify` | session | ACC-04, ACC-05 |
//! | `POST` | `/v1/me/email` | session + step-up | ACC-07 |
//! | `POST` | `/v1/me/email/confirm` | session | ACC-07 |
//! | `DELETE` | `/v1/me` | session + step-up | ACC-09 |
//! | `GET` | `/v1/me/deletion` | session | ACC-09 |
//! | `POST` | `/v1/me/deletion/cancel` | session | ACC-09 |
//! | `POST` | `/v1/me/export` | session + step-up | ACC-10 |
//! | `GET`, `POST` | `/v1/me/consents` | session | ACC-11 |
//!
//! Link tokens are always submitted with `POST` (frontends render a page
//! for the e-mailed link and post the token): link-preview bots that fetch
//! URLs must not consume them. Every body is read with [`SecretJson`]:
//! parse errors never copy submitted values (passwords, tokens, codes,
//! addresses, names) into logs.
//!
//! Registration handle (ADR 0002): `POST /v1/signup` answers with a random
//! `registration` handle in the body and in the [`REGISTRATION_COOKIE`]
//! (`HttpOnly; Secure; SameSite=Strict; Path=/`). `POST /v1/email/verify`
//! and `POST /v1/email/verification/resend` read it from the body
//! (`registration`, native clients) or from that cookie (browsers).

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::{Json, RequestContext};
use authn_core::secret::SecretString;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::extract::SecretJson;
use crate::model::{
    ConsentView, DeletionView, LastOwnerDetails, ProfileUpdate, ProfileView, RevertOutcome,
    SignupInput, TermsAcceptance, TermsVersionView,
};
use crate::service::{
    AccountService, CredentialConfirmation, LinkConfirmation, REGISTRATION_COOKIE,
    RegistrationReceipt, VerificationProof,
};

/// The module router. Requires [`AccountService`] from the state; the
/// `/v1/me*` routes additionally require the session middleware to insert a
/// [`Principal`].
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AccountService: FromRef<S>,
{
    Router::new()
        .route("/v1/signup", post(signup))
        .route("/v1/email/verification/resend", post(resend_verification))
        .route("/v1/email/verify", post(verify_email))
        .route("/v1/email/change/confirm", post(confirm_email_change))
        .route("/v1/email/change/revert", post(revert_email_change))
        .route(
            "/v1/account/deletion/cancel",
            post(cancel_deletion_with_link),
        )
        .route("/v1/terms", get(current_terms))
        .route("/v1/me", delete(request_deletion))
        .route("/v1/me/profile", get(get_profile).patch(update_profile))
        .route("/v1/me/email", post(request_email_change))
        .route("/v1/me/email/confirm", post(confirm_email_change_code))
        .route("/v1/me/email/verification", post(resend_own_verification))
        .route("/v1/me/email/verify", post(verify_own_email))
        .route("/v1/me/deletion", get(deletion_status))
        .route("/v1/me/deletion/cancel", post(cancel_deletion))
        .route("/v1/me/export", post(export_data))
        .route("/v1/me/consents", get(list_consents).post(record_consent))
}

/// OpenAPI document of this crate's endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(
        signup,
        resend_verification,
        verify_email,
        confirm_email_change,
        revert_email_change,
        cancel_deletion_with_link,
        current_terms,
        request_deletion,
        get_profile,
        update_profile,
        request_email_change,
        confirm_email_change_code,
        resend_own_verification,
        verify_own_email,
        deletion_status,
        cancel_deletion,
        export_data,
        list_consents,
        record_consent,
    ),
    components(schemas(
        SignupInput,
        SignupResponse,
        TermsAcceptance,
        StatusResponse,
        EmailRequest,
        VerifyEmailRequest,
        TokenRequest,
        CodeRequest,
        EmailChangeRequest,
        ConsentRequest,
        TermsListResponse,
        ConsentListResponse,
        ProfileView,
        ProfileUpdate,
        DeletionView,
        RevertOutcome,
        TermsVersionView,
        ConsentView,
        LastOwnerDetails,
    )),
    tags((name = "account", description = "Registration, verification, profile, e-mail change, deletion, export, consents"))
)]
pub struct AccountApi;

// --- request / response types ------------------------------------------------

/// Generic acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StatusResponse {
    /// `accepted`, `verified`, `email_changed`, `deletion_cancelled`…
    pub status: String,
}

impl StatusResponse {
    fn new(status: &str) -> Json<Self> {
        Json(Self {
            status: status.to_owned(),
        })
    }
}

/// Answer of `POST /v1/signup` — identical in shape for every address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SignupResponse {
    /// Always `accepted`.
    pub status: String,
    /// The registration handle (256 random bits): send it back as
    /// `registration` with the e-mailed code (native clients). Browsers get
    /// the same value in the `__Host-authn_registration` cookie. Keep it
    /// secret; it is useless without the e-mailed link or code.
    pub registration: String,
}

/// Body of `POST /v1/email/verification/resend`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailRequest {
    /// The address the verification was sent to.
    #[schema(format = Email)]
    pub email: String,
    /// The registration handle (native clients; browsers send the cookie).
    #[schema(value_type = Option<String>)]
    pub registration: Option<SecretString>,
}

/// Body of `POST /v1/email/verify`: either the link `token` (plus, when the
/// link is opened outside the registering browser, `password` or
/// `new_password`), or the `code` with the registration handle.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmailRequest {
    /// Token from the verification link.
    #[schema(value_type = Option<String>)]
    pub token: Option<SecretString>,
    /// Six-digit code (code flow, together with `registration`).
    #[schema(value_type = Option<String>)]
    pub code: Option<SecretString>,
    /// Registration handle (native clients; browsers send the cookie).
    #[schema(value_type = Option<String>)]
    pub registration: Option<SecretString>,
    /// Address (code flow, optional; must be the registration's).
    #[schema(format = Email)]
    pub email: Option<String>,
    /// Link flow on another device: the password chosen at registration.
    #[schema(value_type = Option<String>, format = Password)]
    pub password: Option<SecretString>,
    /// Link flow by the mailbox owner who did not (or no longer can)
    /// confirm the registration's password: a new password.
    #[schema(value_type = Option<String>, format = Password)]
    pub new_password: Option<SecretString>,
    /// With `new_password`: accepted current terms versions (ACC-11).
    #[serde(default)]
    pub accepted_terms: Vec<TermsAcceptance>,
}

/// Body carrying a link token.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    /// Token from the e-mailed link.
    #[schema(value_type = String)]
    pub token: SecretString,
}

/// Body carrying a six-digit code.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRequest {
    /// The e-mailed code.
    #[schema(value_type = String)]
    pub code: SecretString,
}

/// Body of `POST /v1/me/email`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailChangeRequest {
    /// The new address.
    #[schema(format = Email)]
    pub new_email: String,
}

/// Body of `POST /v1/me/consents`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequest {
    /// Accepted current document versions (1–8).
    pub accepted: Vec<TermsAcceptance>,
}

/// Response of `GET /v1/terms`.
#[derive(Debug, Serialize, ToSchema)]
pub struct TermsListResponse {
    /// Current version of every published document.
    pub documents: Vec<TermsVersionView>,
}

/// Response of `GET /v1/me/consents`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentListResponse {
    /// Recorded acceptances, newest first.
    pub consents: Vec<ConsentView>,
}

// --- handlers ----------------------------------------------------------------

/// Registers an account (ACC-01). The answer is identical whether or not
/// the address is already registered (ACC-02); the verification (or a
/// "someone tried to register" notice) arrives by e-mail. The answer carries
/// a fresh registration handle (body and cookie) that binds the e-mailed
/// link and code to this client (ADR 0002).
#[utoipa::path(
    post,
    path = "/v1/signup",
    tag = "account",
    request_body = SignupInput,
    responses(
        (status = 202, description = "Accepted; check the mailbox. Sets the `__Host-authn_registration` cookie.", body = SignupResponse),
        (status = 400, description = "Malformed body", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "`captcha_required` / `captcha_failed` (challenge in `details`)", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "`terms_version_not_current`", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "`invalid_email`, `email_domain_not_allowed`, `invalid_display_name`, `invalid_time_zone`, `terms_acceptance_required`, `password_policy_violation`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
        (status = 503, description = "Busy or CAPTCHA provider unavailable", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn signup(
    State(svc): State<AccountService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<SignupInput>,
) -> Result<Response, AuthError> {
    let receipt = svc.signup(&ctx, body).await?;
    let cookie = registration_cookie(&receipt)?;
    let mut response = (
        StatusCode::ACCEPTED,
        Json(SignupResponse {
            status: "accepted".to_owned(),
            registration: receipt.handle().expose().to_owned(),
        }),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(header::SET_COOKIE, cookie);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// `Set-Cookie` value of the registration handle.
fn registration_cookie(receipt: &RegistrationReceipt) -> Result<HeaderValue, AuthError> {
    HeaderValue::from_str(&format!(
        "{REGISTRATION_COOKIE}={}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
        receipt.handle().expose(),
        receipt.max_age().as_secs()
    ))
    .map_err(|_| AuthError::internal("registration cookie is not a valid header value"))
}

/// The registration handle of the request: the body field when present,
/// otherwise the [`REGISTRATION_COOKIE`] (only well-formed values).
fn registration_handle(body: Option<SecretString>, headers: &HeaderMap) -> Option<SecretString> {
    body.or_else(|| {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|cookies| cookies.split(';').take(64))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, value)| *name == REGISTRATION_COOKIE && is_handle_shaped(value))
            .map(|(_, value)| SecretString::from(value.to_owned()))
    })
}

/// 43 URL-safe base64 characters (256 bits, no padding).
fn is_handle_shaped(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Re-sends the verification e-mail (ACC-04). Same answer for every
/// address.
#[utoipa::path(
    post,
    path = "/v1/email/verification/resend",
    tag = "account",
    request_body = EmailRequest,
    responses(
        (status = 202, description = "Accepted", body = StatusResponse),
        (status = 422, description = "`invalid_email`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn resend_verification(
    State(svc): State<AccountService>,
    ctx: RequestContext,
    headers: HeaderMap,
    SecretJson(body): SecretJson<EmailRequest>,
) -> Result<(StatusCode, Json<StatusResponse>), AuthError> {
    let handle = registration_handle(body.registration, &headers);
    svc.resend_verification(&ctx, &body.email, handle.as_ref())
        .await?;
    Ok((StatusCode::ACCEPTED, StatusResponse::new("accepted")))
}

/// Verifies an address (ACC-04) with the e-mailed link or code. A link
/// completes a registration only for the client that submitted it (cookie
/// or `registration`), or with the password chosen in it (`password`), or
/// with a new password chosen now (`new_password`); a code only together
/// with the registration handle (ADR 0002).
#[utoipa::path(
    post,
    path = "/v1/email/verify",
    tag = "account",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Verified; the account is active", body = StatusResponse),
        (status = 400, description = "`invalid_or_expired_token` / `invalid_code` (unknown handles and addresses answer the same)", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "`registration_confirmation_required` (offer `password` or `new_password`) / `registration_password_mismatch`", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "`terms_version_not_current`", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "`validation_failed`, `password_policy_violation`, `terms_acceptance_required`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn verify_email(
    State(svc): State<AccountService>,
    principal: Option<Principal>,
    ctx: RequestContext,
    headers: HeaderMap,
    SecretJson(body): SecretJson<VerifyEmailRequest>,
) -> Result<Json<StatusResponse>, AuthError> {
    let malformed = || {
        AuthError::new(codes::common::VALIDATION_FAILED)
            .with_context("expected token (+ password | new_password) or code (+ registration)")
    };
    let registration = registration_handle(body.registration, &headers);
    let proof = match (body.token, body.code) {
        (Some(token), None) => {
            if body.email.is_some() {
                return Err(malformed());
            }
            let credentials = match (body.password, body.new_password) {
                (Some(password), None) if body.accepted_terms.is_empty() => {
                    Some(CredentialConfirmation::ChosenPassword(password))
                }
                (None, Some(password)) => Some(CredentialConfirmation::NewPassword {
                    password,
                    accepted_terms: body.accepted_terms,
                }),
                (None, None) if body.accepted_terms.is_empty() => None,
                _ => return Err(malformed()),
            };
            VerificationProof::Link {
                token,
                confirmation: LinkConfirmation {
                    registration,
                    // A session of the account holder (not an API key, not
                    // impersonation).
                    signed_in_user: principal
                        .as_ref()
                        .filter(|p| !p.is_impersonated() && p.session_id().is_some())
                        .and_then(Principal::user_id),
                    credentials,
                },
            }
        }
        (None, Some(code))
            if body.password.is_none()
                && body.new_password.is_none()
                && body.accepted_terms.is_empty() =>
        {
            VerificationProof::Code {
                code,
                registration,
                email: body.email,
            }
        }
        _ => return Err(malformed()),
    };
    svc.verify_email(&ctx, proof).await?;
    Ok(StatusResponse::new("verified"))
}

/// Confirms an e-mail change with the link sent to the new address
/// (ACC-07). The account holder must be signed in (any session of theirs):
/// the link alone would let whoever clicks it attach their mailbox to the
/// requester's account (ADR 0002).
#[utoipa::path(
    post,
    path = "/v1/email/change/confirm",
    tag = "account",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Address changed", body = StatusResponse),
        (status = 400, description = "`invalid_or_expired_token` (also another user's link)", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "`unauthenticated`: sign in as the account holder first", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Impersonation or API key", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn confirm_email_change(
    State(svc): State<AccountService>,
    principal: Option<Principal>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<TokenRequest>,
) -> Result<Json<StatusResponse>, AuthError> {
    svc.confirm_email_change_link(principal.as_ref(), &ctx, &body.token)
        .await?;
    Ok(StatusResponse::new("email_changed"))
}

/// Reverts an e-mail change with the link sent to the old address
/// (ACC-07): restores it, signs out everywhere and forces a password reset.
#[utoipa::path(
    post,
    path = "/v1/email/change/revert",
    tag = "account",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Reverted", body = RevertOutcome),
        (status = 400, description = "`invalid_or_expired_token`", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "`email_change_revert_conflict`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn revert_email_change(
    State(svc): State<AccountService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<TokenRequest>,
) -> Result<Json<RevertOutcome>, AuthError> {
    Ok(Json(svc.revert_email_change(&ctx, &body.token).await?))
}

/// Cancels a scheduled deletion with the e-mailed link (ACC-09).
#[utoipa::path(
    post,
    path = "/v1/account/deletion/cancel",
    tag = "account",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Deletion cancelled", body = StatusResponse),
        (status = 400, description = "`invalid_or_expired_token`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn cancel_deletion_with_link(
    State(svc): State<AccountService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<TokenRequest>,
) -> Result<Json<StatusResponse>, AuthError> {
    svc.cancel_deletion_with_link(&ctx, &body.token).await?;
    Ok(StatusResponse::new("deletion_cancelled"))
}

/// Current terms of service / privacy policy versions (ACC-11).
#[utoipa::path(
    get,
    path = "/v1/terms",
    tag = "account",
    responses((status = 200, description = "Current versions", body = TermsListResponse))
)]
pub async fn current_terms(
    State(svc): State<AccountService>,
) -> Result<Json<TermsListResponse>, AuthError> {
    Ok(Json(TermsListResponse {
        documents: svc.current_terms().await?,
    }))
}

/// Schedules the deletion of the signed-in user's account (ACC-09).
#[utoipa::path(
    delete,
    path = "/v1/me",
    tag = "account",
    responses(
        (status = 202, description = "Deletion scheduled (idempotent)", body = DeletionView),
        (status = 401, description = "`unauthenticated` / `step_up_required`", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "Impersonation or API key", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "`account_deletion_blocked_last_owner` (organizations in `details`)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn request_deletion(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
) -> Result<(StatusCode, Json<DeletionView>), AuthError> {
    let view = svc.request_deletion(&principal, &ctx).await?;
    Ok((StatusCode::ACCEPTED, Json(view)))
}

/// The signed-in user's profile (ACC-08).
#[utoipa::path(
    get,
    path = "/v1/me/profile",
    tag = "account",
    responses(
        (status = 200, description = "Profile", body = ProfileView),
        (status = 401, description = "`unauthenticated`", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn get_profile(
    State(svc): State<AccountService>,
    principal: Principal,
) -> Result<Json<ProfileView>, AuthError> {
    Ok(Json(svc.profile(&principal).await?))
}

/// Updates display name, language and time zone (ACC-08).
#[utoipa::path(
    patch,
    path = "/v1/me/profile",
    tag = "account",
    request_body = ProfileUpdate,
    responses(
        (status = 200, description = "Updated profile", body = ProfileView),
        (status = 422, description = "`invalid_display_name` / `invalid_time_zone` / `validation_failed`", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn update_profile(
    State(svc): State<AccountService>,
    principal: Principal,
    SecretJson(body): SecretJson<ProfileUpdate>,
) -> Result<Json<ProfileView>, AuthError> {
    Ok(Json(svc.update_profile(&principal, body).await?))
}

/// Requests an e-mail change (ACC-07). Same answer whether or not the new
/// address is available.
#[utoipa::path(
    post,
    path = "/v1/me/email",
    tag = "account",
    request_body = EmailChangeRequest,
    responses(
        (status = 202, description = "Verification sent to the new address (if it can be used)", body = StatusResponse),
        (status = 401, description = "`step_up_required`", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "`invalid_email`, `email_unchanged`, `email_domain_not_allowed`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn request_email_change(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
    SecretJson(body): SecretJson<EmailChangeRequest>,
) -> Result<(StatusCode, Json<StatusResponse>), AuthError> {
    svc.request_email_change(&principal, &ctx, &body.new_email)
        .await?;
    Ok((StatusCode::ACCEPTED, StatusResponse::new("accepted")))
}

/// Confirms an e-mail change with the code sent to the new address
/// (ACC-07).
#[utoipa::path(
    post,
    path = "/v1/me/email/confirm",
    tag = "account",
    request_body = CodeRequest,
    responses(
        (status = 200, description = "Address changed", body = StatusResponse),
        (status = 400, description = "`invalid_code`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "`too_many_attempts` / rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn confirm_email_change_code(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
    SecretJson(body): SecretJson<CodeRequest>,
) -> Result<Json<StatusResponse>, AuthError> {
    svc.confirm_email_change_code(&principal, &ctx, &body.code)
        .await?;
    Ok(StatusResponse::new("email_changed"))
}

/// Re-sends the verification e-mail to the signed-in user (ACC-04).
#[utoipa::path(
    post,
    path = "/v1/me/email/verification",
    tag = "account",
    responses(
        (status = 202, description = "Sent", body = StatusResponse),
        (status = 409, description = "`email_already_verified`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Cooldown / hourly limit (`Retry-After`)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn resend_own_verification(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
) -> Result<(StatusCode, Json<StatusResponse>), AuthError> {
    svc.resend_own_verification(&principal, &ctx).await?;
    Ok((StatusCode::ACCEPTED, StatusResponse::new("accepted")))
}

/// Verifies the signed-in user's address with the code (ACC-04, ACC-05
/// limited mode).
#[utoipa::path(
    post,
    path = "/v1/me/email/verify",
    tag = "account",
    request_body = CodeRequest,
    responses(
        (status = 200, description = "Verified", body = StatusResponse),
        (status = 400, description = "`invalid_code`", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "`email_already_verified`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "`too_many_attempts` / rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn verify_own_email(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
    SecretJson(body): SecretJson<CodeRequest>,
) -> Result<Json<StatusResponse>, AuthError> {
    svc.verify_own_email_code(&principal, &ctx, &body.code)
        .await?;
    Ok(StatusResponse::new("verified"))
}

/// The scheduled deletion of the signed-in user (ACC-09).
#[utoipa::path(
    get,
    path = "/v1/me/deletion",
    tag = "account",
    responses(
        (status = 200, description = "Scheduled deletion", body = DeletionView),
        (status = 404, description = "Nothing scheduled", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn deletion_status(
    State(svc): State<AccountService>,
    principal: Principal,
) -> Result<Json<DeletionView>, AuthError> {
    svc.deletion_status(&principal)
        .await?
        .map(Json)
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}

/// Cancels the signed-in user's scheduled deletion (ACC-09).
#[utoipa::path(
    post,
    path = "/v1/me/deletion/cancel",
    tag = "account",
    responses(
        (status = 200, description = "Cancelled", body = StatusResponse),
        (status = 409, description = "`account_deletion_not_scheduled`", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn cancel_deletion(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
) -> Result<Json<StatusResponse>, AuthError> {
    svc.cancel_deletion(&principal, &ctx).await?;
    Ok(StatusResponse::new("deletion_cancelled"))
}

/// Machine-readable export of all personal data (ACC-10, KVKK/GDPR).
///
/// **`POST` since the wave 4B audit (K-58, client note K-79); it used to be
/// a `GET`, which now answers `405 Method Not Allowed`.** A safe method
/// would skip the CSRF checks and be sent cross-site with the session
/// cookie, letting any page spend the user's daily export quota.
///
/// No request body. Web clients send the session cookie, the
/// `X-CSRF-Token` header and a same-origin `Origin`; native clients a
/// bearer access token. Requires a recent re-authentication
/// (`401 step_up_required` → `POST /v1/reauth`, then retry); never under
/// impersonation; rate limited per user (`account.export_per_user`,
/// default 2 per day). The response is a JSON attachment
/// (`personal-data-export.json`, `Cache-Control: no-store`).
#[utoipa::path(
    post,
    path = "/v1/me/export",
    tag = "account",
    responses(
        (status = 200, description = "Export document (JSON attachment, `format` = `rust-authentication/personal-data-export/v1`)", body = serde_json::Value),
        (status = 401, description = "`unauthenticated` / `step_up_required`", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "`csrf_failed` (web request without the CSRF header or same-origin `Origin`) / `forbidden` (impersonation)", body = authn_core::error::ErrorEnvelope),
        (status = 405, description = "`GET` (the method before K-58/K-79) is not allowed"),
        (status = 429, description = "Rate limited (`Retry-After`)", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn export_data(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
) -> Result<Response, AuthError> {
    let document = svc.export_data(&principal, &ctx).await?;
    let mut response = Json(document).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"personal-data-export.json\""),
    );
    Ok(response)
}

/// The signed-in user's recorded acceptances (ACC-11).
#[utoipa::path(
    get,
    path = "/v1/me/consents",
    tag = "account",
    responses((status = 200, description = "Acceptances", body = ConsentListResponse))
)]
pub async fn list_consents(
    State(svc): State<AccountService>,
    principal: Principal,
) -> Result<Json<ConsentListResponse>, AuthError> {
    Ok(Json(ConsentListResponse {
        consents: svc.consents(&principal).await?,
    }))
}

/// Accepts current document versions (ACC-11); IP and user agent are
/// recorded.
#[utoipa::path(
    post,
    path = "/v1/me/consents",
    tag = "account",
    request_body = ConsentRequest,
    responses(
        (status = 204, description = "Recorded"),
        (status = 409, description = "`terms_version_not_current`", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "`validation_failed`", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn record_consent(
    State(svc): State<AccountService>,
    principal: Principal,
    ctx: RequestContext,
    SecretJson(body): SecretJson<ConsentRequest>,
) -> Result<StatusCode, AuthError> {
    svc.record_consent(&principal, &ctx, &body.accepted).await?;
    Ok(StatusCode::NO_CONTENT)
}
