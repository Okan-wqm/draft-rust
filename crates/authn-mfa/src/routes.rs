//! HTTP endpoints of authn-mfa (MFA-07, MFA-10, ARC-03, ARC-09).
//!
//! | Method | Path | Auth | Requirement |
//! |--------|------|------|-------------|
//! | `GET` | `/v1/me/mfa` | session (read-only impersonation ok) | MFA-10 |
//! | `POST` | `/v1/me/mfa/totp` | session + step-up | MFA-01, MFA-07 |
//! | `POST` | `/v1/me/mfa/email` | session + step-up | MFA-05, MFA-07 |
//! | `POST` | `/v1/me/mfa/sms` | session + step-up | MFA-06, MFA-07 |
//! | `POST` | `/v1/me/mfa/factors/{factor_id}/confirm` | session + step-up | MFA-01/05/06 |
//! | `POST` | `/v1/me/mfa/factors/{factor_id}/resend` | session + step-up | MFA-05/06 |
//! | `DELETE` | `/v1/me/mfa/factors/{factor_id}` | session + step-up | MFA-07 |
//! | `GET` | `/v1/me/mfa/recovery-codes` | session | MFA-04 |
//! | `POST` | `/v1/me/mfa/recovery-codes` | session + step-up | MFA-04 |
//! | `GET` | `/v1/me/mfa/trusted-devices` | session | MFA-09 |
//! | `DELETE` | `/v1/me/mfa/trusted-devices` | session | MFA-09 |
//! | `DELETE` | `/v1/me/mfa/trusted-devices/{device_id}` | session | MFA-09 |
//!
//! Every response carries `Cache-Control: no-store`; secrets (TOTP secret,
//! recovery codes) appear only in the response of the request that created
//! them. Bodies are read with [`SecretJson`] (rejections never echo codes).
//! Unknown or foreign ids answer `404` (ORG-10 style).

use authn_core::domain::Principal;
use authn_core::error::AuthError;
use authn_core::http::{Json, Path, RequestContext};
use authn_core::id::{FactorId, TrustedDeviceId};
use authn_core::secret::SecretString;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize, Serializer};
use time::OffsetDateTime;
use utoipa::{OpenApi, ToSchema};
use zeroize::Zeroizing;

use crate::extract::SecretJson;
use crate::service::{
    CodeChannel, CodeDelivery, ConfirmedFactor, FactorState, FactorSummary, GeneratedRecoveryCodes,
    MfaService, MfaStatus, RecoveryCodesStatus, TrustedDeviceSummary,
};

/// Cookie carrying the trusted-device token for browsers (set by
/// authn-session after a successful MFA with "remember this device").
pub const TRUSTED_DEVICE_COOKIE: &str = "__Host-authn_trusted_device";
/// Header carrying the trusted-device token for native clients.
pub const TRUSTED_DEVICE_HEADER: &str = "x-trusted-device";

/// The module router. Requires [`MfaService`] from the state and the
/// session middleware to insert a [`Principal`].
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    MfaService: FromRef<S>,
{
    Router::new()
        .route("/v1/me/mfa", get(get_status))
        .route("/v1/me/mfa/totp", post(begin_totp))
        .route("/v1/me/mfa/email", post(begin_email))
        .route("/v1/me/mfa/sms", post(begin_sms))
        .route("/v1/me/mfa/factors/{factor_id}", delete(remove_factor))
        .route(
            "/v1/me/mfa/factors/{factor_id}/confirm",
            post(confirm_factor),
        )
        .route("/v1/me/mfa/factors/{factor_id}/resend", post(resend_code))
        .route(
            "/v1/me/mfa/recovery-codes",
            get(recovery_codes_status).post(regenerate_recovery_codes),
        )
        .route(
            "/v1/me/mfa/trusted-devices",
            get(list_trusted_devices).delete(revoke_all_trusted_devices),
        )
        .route(
            "/v1/me/mfa/trusted-devices/{device_id}",
            delete(revoke_trusted_device),
        )
}

/// OpenAPI document of this crate's endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(
        get_status,
        begin_totp,
        begin_email,
        begin_sms,
        confirm_factor,
        resend_code,
        remove_factor,
        recovery_codes_status,
        regenerate_recovery_codes,
        list_trusted_devices,
        revoke_all_trusted_devices,
        revoke_trusted_device
    ),
    components(schemas(
        MfaStatus,
        FactorSummary,
        FactorState,
        RecoveryCodesStatus,
        BeginTotpRequest,
        TotpEnrollmentResponse,
        BeginSmsRequest,
        CodeDelivery,
        CodeChannel,
        ConfirmFactorRequest,
        ConfirmedFactor,
        GeneratedRecoveryCodes,
        TrustedDeviceSummary,
        TrustedDeviceList,
        RevokedCount,
    )),
    tags((name = "mfa", description = "Second factors, recovery codes and trusted devices"))
)]
pub struct MfaApi;

// --- request / response types ------------------------------------------------

/// Body of `POST /v1/me/mfa/totp` (optional).
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BeginTotpRequest {
    /// Label shown in the factor list (1–64 characters).
    pub label: Option<String>,
}

/// A started TOTP enrollment. Contains the shared secret: shown once.
#[derive(Serialize, ToSchema)]
pub struct TotpEnrollmentResponse {
    /// The pending factor.
    pub factor: FactorSummary,
    /// Base32 secret for manual entry.
    #[serde(serialize_with = "secret_str")]
    #[schema(value_type = String)]
    pub secret: Zeroizing<String>,
    /// `otpauth://totp/...` Key URI.
    #[serde(serialize_with = "secret_str")]
    #[schema(value_type = String)]
    pub otpauth_uri: Zeroizing<String>,
    /// The URI as a QR code (SVG document).
    #[serde(serialize_with = "secret_str")]
    #[schema(value_type = String)]
    pub qr_code_svg: Zeroizing<String>,
    /// Confirm before this time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for TotpEnrollmentResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrollmentResponse")
            .field("factor", &self.factor)
            .finish_non_exhaustive()
    }
}

fn secret_str<S: Serializer>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

/// Body of `POST /v1/me/mfa/sms`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BeginSmsRequest {
    /// Phone number in E.164 format (`+905551112233`).
    pub phone_number: String,
    /// Label shown in the factor list (1–64 characters).
    pub label: Option<String>,
}

/// Body of `POST /v1/me/mfa/factors/{factor_id}/confirm`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmFactorRequest {
    /// TOTP code from the app, or the code sent by e-mail / SMS.
    #[schema(value_type = String)]
    pub code: SecretString,
}

/// List of trusted devices.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrustedDeviceList {
    /// Active devices, newest first.
    pub devices: Vec<TrustedDeviceSummary>,
}

/// Number of revoked items.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokedCount {
    /// How many were revoked.
    pub revoked: u64,
}

/// JSON with `Cache-Control: no-store`.
fn no_store<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// --- handlers ------------------------------------------------------------------

/// The caller's MFA state: factors (no secrets, masked contact data),
/// recovery-code counters and trusted-device count (MFA-10).
#[utoipa::path(
    get,
    path = "/v1/me/mfa",
    tag = "mfa",
    responses(
        (status = 200, description = "MFA state", body = MfaStatus),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn get_status(
    State(service): State<MfaService>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let status = service.status(&principal).await?;
    Ok(no_store(StatusCode::OK, status))
}

/// Starts a TOTP enrollment (MFA-01): returns the secret, the `otpauth://`
/// URI and a QR code once; the factor stays pending until confirmed with a
/// valid code. Requires step-up.
#[utoipa::path(
    post,
    path = "/v1/me/mfa/totp",
    tag = "mfa",
    request_body(content = BeginTotpRequest, description = "Optional label"),
    responses(
        (status = 201, description = "Pending TOTP factor", body = TotpEnrollmentResponse),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "mfa_factor_limit_reached", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "validation_failed (label)", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn begin_totp(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
    SecretJson(body): SecretJson<BeginTotpRequest>,
) -> Result<Response, AuthError> {
    let enrollment = service
        .begin_totp_enrollment(&ctx, &principal, body.label)
        .await?;
    Ok(no_store(
        StatusCode::CREATED,
        TotpEnrollmentResponse {
            factor: enrollment.factor,
            secret: enrollment.provisioning.secret_base32,
            otpauth_uri: enrollment.provisioning.otpauth_uri,
            qr_code_svg: enrollment.provisioning.qr_svg,
            expires_at: enrollment.expires_at,
        },
    ))
}

/// Starts the e-mail OTP factor on the account address (MFA-05) and sends a
/// confirmation code. Requires step-up.
#[utoipa::path(
    post,
    path = "/v1/me/mfa/email",
    tag = "mfa",
    responses(
        (status = 202, description = "Code sent", body = CodeDelivery),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "mfa_factor_not_available", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "mfa_factor_already_enrolled / mfa_factor_limit_reached", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Resend cooldown / budget (Retry-After)", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn begin_email(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
) -> Result<Response, AuthError> {
    let delivery = service.begin_email_enrollment(&ctx, &principal).await?;
    Ok(no_store(StatusCode::ACCEPTED, delivery))
}

/// Starts an SMS factor (MFA-06): the E.164 number must be in an allowed
/// country; a verification code is sent and the number becomes a factor
/// only after confirmation. SMS is a weak factor. Requires step-up.
#[utoipa::path(
    post,
    path = "/v1/me/mfa/sms",
    tag = "mfa",
    request_body = BeginSmsRequest,
    responses(
        (status = 202, description = "Verification code sent", body = CodeDelivery),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "mfa_factor_not_available", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "mfa_factor_already_enrolled / mfa_factor_limit_reached", body = authn_core::error::ErrorEnvelope),
        (status = 422, description = "mfa_invalid_phone_number / mfa_phone_country_not_allowed", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Cooldown / pumping protection (Retry-After)", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn begin_sms(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
    SecretJson(body): SecretJson<BeginSmsRequest>,
) -> Result<Response, AuthError> {
    let delivery = service
        .begin_sms_enrollment(&ctx, &principal, &body.phone_number, body.label)
        .await?;
    Ok(no_store(StatusCode::ACCEPTED, delivery))
}

/// Confirms a pending factor with a code and activates it. The first factor
/// also returns freshly generated recovery codes (once). Requires step-up.
#[utoipa::path(
    post,
    path = "/v1/me/mfa/factors/{factor_id}/confirm",
    tag = "mfa",
    params(("factor_id" = String, Path, description = "Factor id")),
    request_body = ConfirmFactorRequest,
    responses(
        (status = 200, description = "Factor active", body = ConfirmedFactor),
        (status = 400, description = "invalid_code", body = authn_core::error::ErrorEnvelope),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "not_found", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "mfa_enrollment_not_pending", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "too_many_attempts (Retry-After)", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn confirm_factor(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
    Path(factor_id): Path<FactorId>,
    SecretJson(body): SecretJson<ConfirmFactorRequest>,
) -> Result<Response, AuthError> {
    let confirmed = service
        .confirm_enrollment(&ctx, &principal, factor_id, &body.code)
        .await?;
    Ok(no_store(StatusCode::OK, confirmed))
}

/// Sends a new confirmation code for a pending e-mail / SMS factor.
/// Requires step-up.
#[utoipa::path(
    post,
    path = "/v1/me/mfa/factors/{factor_id}/resend",
    tag = "mfa",
    params(("factor_id" = String, Path, description = "Factor id")),
    responses(
        (status = 202, description = "Code sent", body = CodeDelivery),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "not_found", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "mfa_enrollment_not_pending", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Cooldown / pumping protection (Retry-After)", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn resend_code(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
    Path(factor_id): Path<FactorId>,
) -> Result<Response, AuthError> {
    let delivery = service
        .resend_enrollment_code(&ctx, &principal, factor_id)
        .await?;
    Ok(no_store(StatusCode::ACCEPTED, delivery))
}

/// Removes a factor (MFA-07). Blocked for the last usable factor while MFA
/// is required by policy. Sends a notification and revokes trusted devices.
/// Requires step-up.
#[utoipa::path(
    delete,
    path = "/v1/me/mfa/factors/{factor_id}",
    tag = "mfa",
    params(("factor_id" = String, Path, description = "Factor id")),
    responses(
        (status = 204, description = "Factor removed"),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "not_found", body = authn_core::error::ErrorEnvelope),
        (status = 409, description = "mfa_last_factor_required", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn remove_factor(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
    Path(factor_id): Path<FactorId>,
) -> Result<StatusCode, AuthError> {
    service.remove_factor(&ctx, &principal, factor_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Recovery-code counters (MFA-04).
#[utoipa::path(
    get,
    path = "/v1/me/mfa/recovery-codes",
    tag = "mfa",
    responses(
        (status = 200, description = "Counters", body = RecoveryCodesStatus),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn recovery_codes_status(
    State(service): State<MfaService>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let status = service.recovery_codes_status(&principal).await?;
    Ok(no_store(StatusCode::OK, status))
}

/// Generates new recovery codes, invalidating all old ones (MFA-04). The
/// codes are shown once. Requires step-up.
#[utoipa::path(
    post,
    path = "/v1/me/mfa/recovery-codes",
    tag = "mfa",
    responses(
        (status = 201, description = "New codes (shown once)", body = GeneratedRecoveryCodes),
        (status = 401, description = "unauthenticated / step_up_required", body = authn_core::error::ErrorEnvelope),
        (status = 403, description = "mfa_factor_not_available (no active factor)", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn regenerate_recovery_codes(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
) -> Result<Response, AuthError> {
    let codes = service.regenerate_recovery_codes(&ctx, &principal).await?;
    Ok(no_store(StatusCode::CREATED, codes))
}

/// The caller's trusted devices (MFA-09).
#[utoipa::path(
    get,
    path = "/v1/me/mfa/trusted-devices",
    tag = "mfa",
    responses(
        (status = 200, description = "Active trusted devices", body = TrustedDeviceList),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn list_trusted_devices(
    State(service): State<MfaService>,
    principal: Principal,
) -> Result<Response, AuthError> {
    let devices = service.list_trusted_devices(&principal).await?;
    Ok(no_store(StatusCode::OK, TrustedDeviceList { devices }))
}

/// Revokes all of the caller's trusted devices (MFA-09).
#[utoipa::path(
    delete,
    path = "/v1/me/mfa/trusted-devices",
    tag = "mfa",
    responses(
        (status = 200, description = "Devices revoked", body = RevokedCount),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn revoke_all_trusted_devices(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
) -> Result<Response, AuthError> {
    let revoked = service.revoke_all_trusted_devices(&ctx, &principal).await?;
    Ok(no_store(StatusCode::OK, RevokedCount { revoked }))
}

/// Revokes one trusted device (MFA-09).
#[utoipa::path(
    delete,
    path = "/v1/me/mfa/trusted-devices/{device_id}",
    tag = "mfa",
    params(("device_id" = String, Path, description = "Trusted device id")),
    responses(
        (status = 204, description = "Device revoked"),
        (status = 401, description = "unauthenticated", body = authn_core::error::ErrorEnvelope),
        (status = 404, description = "not_found", body = authn_core::error::ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn revoke_trusted_device(
    State(service): State<MfaService>,
    ctx: RequestContext,
    principal: Principal,
    Path(device_id): Path<TrustedDeviceId>,
) -> Result<StatusCode, AuthError> {
    service
        .revoke_trusted_device(&ctx, &principal, device_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
