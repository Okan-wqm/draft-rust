//! HTTP endpoints of authn-account (ARC-03, ARC-09).
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `POST` | `/v1/signup` | — | ACC-01, 02, 03, 12, 13 |
//! | `POST` | `/v1/email/verification/resend` | — | ACC-04 |
//! | `POST` | `/v1/email/verify` | — (link token or e-mail + code) | ACC-04 |
//! | `POST` | `/v1/email/change/confirm` | — (link token) | ACC-07 |
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
//! | `GET` | `/v1/me/export` | session + step-up | ACC-10 |
//! | `GET`, `POST` | `/v1/me/consents` | session | ACC-11 |
//!
//! Link tokens are always submitted with `POST` (frontends render a page
//! for the e-mailed link and post the token): link-preview bots that fetch
//! URLs must not consume them. Every body is read with [`SecretJson`]:
//! parse errors never copy submitted values (passwords, tokens, codes,
//! addresses, names) into logs.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::{Json, RequestContext};
use authn_core::secret::SecretString;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::extract::SecretJson;
use crate::model::{
    ConsentView, DeletionView, LastOwnerDetails, ProfileUpdate, ProfileView, RevertOutcome,
    SignupInput, TermsAcceptance, TermsVersionView,
};
use crate::service::{AccountService, VerificationProof};

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
        .route("/v1/me/export", get(export_data))
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

/// Body of `POST /v1/email/verification/resend`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailRequest {
    /// The address the verification was sent to.
    #[schema(format = Email)]
    pub email: String,
}

/// Body of `POST /v1/email/verify`: either `token` (link) or `email` +
/// `code`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmailRequest {
    /// Token from the verification link.
    #[schema(value_type = Option<String>)]
    pub token: Option<SecretString>,
    /// Address (code flow).
    #[schema(format = Email)]
    pub email: Option<String>,
    /// Six-digit code (code flow).
    #[schema(value_type = Option<String>)]
    pub code: Option<SecretString>,
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
/// "someone tried to register" notice) arrives by e-mail.
#[utoipa::path(
    post,
    path = "/v1/signup",
    tag = "account",
    request_body = SignupInput,
    responses(
        (status = 202, description = "Accepted; check the mailbox", body = StatusResponse),
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
) -> Result<(StatusCode, Json<StatusResponse>), AuthError> {
    svc.signup(&ctx, body).await?;
    Ok((StatusCode::ACCEPTED, StatusResponse::new("accepted")))
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
    SecretJson(body): SecretJson<EmailRequest>,
) -> Result<(StatusCode, Json<StatusResponse>), AuthError> {
    svc.resend_verification(&ctx, &body.email).await?;
    Ok((StatusCode::ACCEPTED, StatusResponse::new("accepted")))
}

/// Verifies an address with the link token or the e-mail + code (ACC-04).
#[utoipa::path(
    post,
    path = "/v1/email/verify",
    tag = "account",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Verified", body = StatusResponse),
        (status = 400, description = "`invalid_or_expired_token` / `invalid_code` (unknown addresses answer the same)", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn verify_email(
    State(svc): State<AccountService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<VerifyEmailRequest>,
) -> Result<Json<StatusResponse>, AuthError> {
    let proof = match (body.token, body.email, body.code) {
        (Some(token), None, None) => VerificationProof::Link { token },
        (None, Some(email), Some(code)) => VerificationProof::Code { email, code },
        _ => {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("expected either token or email + code"));
        }
    };
    svc.verify_email(&ctx, proof).await?;
    Ok(StatusResponse::new("verified"))
}

/// Confirms an e-mail change with the link sent to the new address
/// (ACC-07).
#[utoipa::path(
    post,
    path = "/v1/email/change/confirm",
    tag = "account",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Address changed", body = StatusResponse),
        (status = 400, description = "`invalid_or_expired_token`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn confirm_email_change(
    State(svc): State<AccountService>,
    ctx: RequestContext,
    SecretJson(body): SecretJson<TokenRequest>,
) -> Result<Json<StatusResponse>, AuthError> {
    svc.confirm_email_change_link(&ctx, &body.token).await?;
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
#[utoipa::path(
    get,
    path = "/v1/me/export",
    tag = "account",
    responses(
        (status = 200, description = "Export document (JSON attachment)", body = serde_json::Value),
        (status = 401, description = "`step_up_required`", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Rate limited", body = authn_core::error::ErrorEnvelope),
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
