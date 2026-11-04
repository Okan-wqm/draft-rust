//! HTTP endpoints of the platform admin API (ADM-01 … ADM-08).
//!
//! Every handler takes [`AdminCaller`], so every route — reads included —
//! passes the ADM-01 guard (platform admin re-checked in the database,
//! passkey MFA session, step-up within `admin.step_up_max_age`, optional IP
//! allow-list, never under impersonation) before its body is parsed.
//! Responses carry `Cache-Control: no-store` (they contain personal data).
//!
//! | Method | Path | Requirement |
//! |--------|------|-------------|
//! | `GET` | `/v1/admin/users` | ADM-02 |
//! | `GET` | `/v1/admin/users/{user_id}` | ADM-02 |
//! | `POST` | `/v1/admin/users/{user_id}/suspend` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/unsuspend` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/unlock` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/revoke-sessions` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/force-password-reset` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/must-change-password` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/reset-mfa` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/mark-email-verified` | ADM-03 |
//! | `POST` | `/v1/admin/users/{user_id}/impersonate` | ADM-04 |
//! | `POST` | `/v1/admin/emergency/revoke-all-sessions` | ADM-06 |
//! | `POST` | `/v1/admin/emergency/rotate-signing-key` | ADM-06 |
//! | `POST` | `/v1/admin/emergency/force-password-change` | ADM-06 |
//! | `GET` | `/v1/admin/audit-events` | ADM-07 |
//! | `POST` | `/v1/admin/audit-events/export` | ADM-07 |
//! | `POST` | `/v1/admin/audit-events/verify` | ADM-07 |

use authn_core::domain::{ClientKind, Page};
use authn_core::error::{AuthError, ErrorEnvelope, codes};
use authn_core::http::{Json, Path, Query, RequestContext};
use authn_core::id::UserId;
use authn_core::ports::LoginOutcome;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};

use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::service::{
    ActionOutcome, AdminAuditEvent, AdminAuditFilter, AdminService, AdminUserDetail,
    AdminUserSummary, AuditExport, BulkResetOutcome, ChainVerification, EmergencyOutcome,
    ForcedReset, ImpersonationOptions, KeyRotationOutcome, PasswordState, UserSearch,
    UserStatusFilter, VerifiedAnchor,
};

/// The admin router. Requires [`AdminService`] from the state and the
/// session middleware to insert a `Principal`; the server mounts it behind
/// the session authentication and CSRF layers.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AdminService: FromRef<S>,
{
    Router::new()
        .route("/v1/admin/users", get(list_users))
        .route("/v1/admin/users/{user_id}", get(get_user))
        .route("/v1/admin/users/{user_id}/suspend", post(suspend_user))
        .route("/v1/admin/users/{user_id}/unsuspend", post(unsuspend_user))
        .route("/v1/admin/users/{user_id}/unlock", post(unlock_user))
        .route(
            "/v1/admin/users/{user_id}/revoke-sessions",
            post(revoke_user_sessions),
        )
        .route(
            "/v1/admin/users/{user_id}/force-password-reset",
            post(force_password_reset),
        )
        .route(
            "/v1/admin/users/{user_id}/must-change-password",
            post(set_must_change_password),
        )
        .route("/v1/admin/users/{user_id}/reset-mfa", post(reset_mfa))
        .route(
            "/v1/admin/users/{user_id}/mark-email-verified",
            post(mark_email_verified),
        )
        .route("/v1/admin/users/{user_id}/impersonate", post(impersonate))
        .route(
            "/v1/admin/emergency/revoke-all-sessions",
            post(emergency_revoke_all_sessions),
        )
        .route(
            "/v1/admin/emergency/rotate-signing-key",
            post(emergency_rotate_signing_key),
        )
        .route(
            "/v1/admin/emergency/force-password-change",
            post(emergency_force_password_change),
        )
        .route("/v1/admin/audit-events", get(list_audit_events))
        .route("/v1/admin/audit-events/export", post(export_audit_events))
        .route("/v1/admin/audit-events/verify", post(verify_audit_chain))
}

/// OpenAPI document of the admin API.
#[derive(OpenApi)]
#[openapi(
    paths(
        list_users,
        get_user,
        suspend_user,
        unsuspend_user,
        unlock_user,
        revoke_user_sessions,
        force_password_reset,
        set_must_change_password,
        reset_mfa,
        mark_email_verified,
        impersonate,
        emergency_revoke_all_sessions,
        emergency_rotate_signing_key,
        emergency_force_password_change,
        list_audit_events,
        export_audit_events,
        verify_audit_chain
    ),
    components(schemas(
        AdminUserSummary,
        AdminUserPage,
        AdminUserDetail,
        PasswordState,
        UserStatusFilter,
        ReasonRequest,
        MustChangePasswordRequest,
        ForcePasswordResetRequest,
        ImpersonateRequest,
        ImpersonationClient,
        EmergencyRequest,
        ForcePasswordChangeRequest,
        ExportRequest,
        VerifyChainRequest,
        VerifiedAnchor,
        ActionOutcome,
        ForcedReset,
        EmergencyOutcome,
        KeyRotationOutcome,
        BulkResetOutcome,
        AdminAuditEvent,
        AdminAuditPage,
        AuditExport,
        ChainVerification,
    )),
    tags((name = "admin", description = "Platform admin API (passkey session + step-up)"))
)]
pub struct AdminApi;

// --- request / response types ------------------------------------------------

/// Body of an action that only needs a justification.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReasonRequest {
    /// Mandatory justification, 1–1000 printable characters (ADM-08).
    pub reason: Option<String>,
}

/// Body of `POST /v1/admin/users/{user_id}/must-change-password`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MustChangePasswordRequest {
    /// Mandatory justification.
    pub reason: Option<String>,
    /// Set (`true`) or clear (`false`) the flag.
    pub must_change: bool,
}

/// Body of `POST /v1/admin/users/{user_id}/force-password-reset`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ForcePasswordResetRequest {
    /// Mandatory justification.
    pub reason: Option<String>,
    /// E-mail a reset link to the account address (default `true`).
    pub send_reset_email: Option<bool>,
}

/// Client of an impersonation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImpersonationClient {
    /// Cookie session (the admin's browser switches to the user).
    Web,
    /// Native tokens; access tokens carry the RFC 8693 `act` claim.
    Native,
}

/// Body of `POST /v1/admin/users/{user_id}/impersonate`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpersonateRequest {
    /// Mandatory justification (shown nowhere to the user; audited).
    pub reason: Option<String>,
    /// Duration in minutes, 1–60 (default 15).
    pub ttl_minutes: Option<u32>,
    /// Read-only mode (default `true`).
    pub read_only: Option<bool>,
    /// `web` (default) or `native`.
    pub client: Option<ImpersonationClient>,
}

/// Body of an emergency operation.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmergencyRequest {
    /// Mandatory justification.
    pub reason: Option<String>,
    /// The operation's name, repeated: `revoke_all_sessions` /
    /// `rotate_signing_key`.
    pub confirm: Option<String>,
}

/// Body of `POST /v1/admin/emergency/force-password-change`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ForcePasswordChangeRequest {
    /// Mandatory justification.
    pub reason: Option<String>,
    /// Must be `force_password_change`.
    pub confirm: Option<String>,
    /// Passwords last changed before this instant (RFC 3339, not in the
    /// future) must be changed at the next login.
    pub changed_before: String,
    /// Also revoke the affected accounts' sessions (default `true`).
    pub revoke_sessions: Option<bool>,
}

/// Body of `POST /v1/admin/audit-events/export`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    /// Mandatory justification.
    pub reason: Option<String>,
    /// Filters (same as the listing; `limit` is ignored).
    #[serde(default)]
    #[schema(value_type = Object)]
    pub filter: AdminAuditFilter,
}

/// Body of `POST /v1/admin/audit-events/verify` (optional).
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyChainRequest {
    /// Externally kept anchor to verify from; default: retention start.
    pub anchor: Option<VerifiedAnchor>,
}

/// A page of accounts.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminUserPage {
    /// Accounts, newest first.
    pub items: Vec<AdminUserSummary>,
    /// Cursor of the next page.
    pub next_cursor: Option<String>,
}

/// A page of audit events.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminAuditPage {
    /// Events, newest first.
    pub items: Vec<AdminAuditEvent>,
    /// Cursor of the next page.
    pub next_cursor: Option<String>,
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn ok<T: Serialize>(body: T) -> Response {
    no_store((StatusCode::OK, Json(body)))
}

fn require_confirmation(confirm: Option<&str>, expected: &str) -> Result<(), AuthError> {
    if confirm == Some(expected) {
        Ok(())
    } else {
        Err(AuthError::new(codes::admin::CONFIRMATION_REQUIRED))
    }
}

// --- users (ADM-02) --------------------------------------------------------------

/// Searches accounts (ADM-02): keyset pages, newest first, no secrets.
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    tag = "admin",
    params(UserSearch),
    responses(
        (status = 200, description = "Accounts", body = AdminUserPage),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_phishing_resistant_mfa_required", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn list_users(
    State(service): State<AdminService>,
    caller: AdminCaller,
    Query(query): Query<UserSearch>,
) -> Result<Response, AuthError> {
    let page: Page<AdminUserSummary> = service.search_users(&caller, query).await?;
    Ok(ok(AdminUserPage {
        items: page.items,
        next_cursor: page.next_cursor,
    }))
}

/// Details of one account (ADM-02); the access is audited.
#[utoipa::path(
    get,
    path = "/v1/admin/users/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "User id")),
    responses(
        (status = 200, description = "Account", body = AdminUserDetail),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_phishing_resistant_mfa_required", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn get_user(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Path(user_id): Path<UserId>,
) -> Result<Response, AuthError> {
    Ok(ok(service.user_detail(&caller, &ctx, user_id).await?))
}

// --- actions (ADM-03) ------------------------------------------------------------

macro_rules! reason_action {
    ($(#[$doc:meta])* $name:ident, $path:literal, $method:ident) => {
        $(#[$doc])*
        #[utoipa::path(
            post,
            path = $path,
            tag = "admin",
            params(("user_id" = String, Path, description = "User id")),
            request_body = ReasonRequest,
            responses(
                (status = 200, description = "Done", body = ActionOutcome),
                (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
                (status = 403, description = "forbidden / admin_phishing_resistant_mfa_required / admin_target_not_allowed", body = ErrorEnvelope),
                (status = 404, description = "not_found", body = ErrorEnvelope),
                (status = 409, description = "account_status_transition_not_allowed", body = ErrorEnvelope),
                (status = 422, description = "admin_reason_required", body = ErrorEnvelope),
            )
        )]
        pub async fn $name(
            State(service): State<AdminService>,
            caller: AdminCaller,
            ctx: RequestContext,
            Path(user_id): Path<UserId>,
            Json(body): Json<ReasonRequest>,
        ) -> Result<Response, AuthError> {
            let reason = Justification::parse(body.reason.as_deref())?;
            Ok(ok(service.$method(&caller, &ctx, user_id, &reason).await?))
        }
    };
}

reason_action!(
    /// Suspends the account and revokes its sessions and trusted devices.
    suspend_user,
    "/v1/admin/users/{user_id}/suspend",
    suspend_user
);
reason_action!(
    /// Lifts a suspension (regular users only).
    unsuspend_user,
    "/v1/admin/users/{user_id}/unsuspend",
    unsuspend_user
);
reason_action!(
    /// Ends a temporary lock and clears the login soft lock.
    unlock_user,
    "/v1/admin/users/{user_id}/unlock",
    unlock_user
);
reason_action!(
    /// Revokes every session and trusted device of the account.
    revoke_user_sessions,
    "/v1/admin/users/{user_id}/revoke-sessions",
    revoke_user_sessions
);
reason_action!(
    /// Resets the account's MFA and notifies the user (regular users only).
    reset_mfa,
    "/v1/admin/users/{user_id}/reset-mfa",
    reset_user_mfa
);
reason_action!(
    /// Marks the address verified (regular users only).
    mark_email_verified,
    "/v1/admin/users/{user_id}/mark-email-verified",
    mark_email_verified
);

/// Forces a password reset: the password stops working, sessions are
/// revoked and a reset link is e-mailed (regular users only).
#[utoipa::path(
    post,
    path = "/v1/admin/users/{user_id}/force-password-reset",
    tag = "admin",
    params(("user_id" = String, Path, description = "User id")),
    request_body = ForcePasswordResetRequest,
    responses(
        (status = 200, description = "Done", body = ForcedReset),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_target_not_allowed", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "password_not_set", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required", body = ErrorEnvelope),
    )
)]
pub async fn force_password_reset(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Path(user_id): Path<UserId>,
    Json(body): Json<ForcePasswordResetRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    let send = body.send_reset_email.unwrap_or(true);
    Ok(ok(service
        .force_password_reset(&caller, &ctx, user_id, &reason, send)
        .await?))
}

/// Sets or clears `must_change_password` (regular users only).
#[utoipa::path(
    post,
    path = "/v1/admin/users/{user_id}/must-change-password",
    tag = "admin",
    params(("user_id" = String, Path, description = "User id")),
    request_body = MustChangePasswordRequest,
    responses(
        (status = 200, description = "Done", body = ActionOutcome),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_target_not_allowed", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "password_not_set", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required", body = ErrorEnvelope),
    )
)]
pub async fn set_must_change_password(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Path(user_id): Path<UserId>,
    Json(body): Json<MustChangePasswordRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    Ok(ok(service
        .set_must_change_password(&caller, &ctx, user_id, body.must_change, &reason)
        .await?))
}

// --- impersonation (ADM-04) --------------------------------------------------------

/// Starts impersonating the user (ADM-04): read-only by default, 15 minutes
/// by default and at most 60. Web: the response sets the impersonation
/// session cookie; native: tokens whose access tokens carry the `act` claim.
#[utoipa::path(
    post,
    path = "/v1/admin/users/{user_id}/impersonate",
    tag = "admin",
    params(("user_id" = String, Path, description = "User id")),
    request_body = ImpersonateRequest,
    responses(
        (status = 200, description = "Impersonation session issued"),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_target_not_allowed / impersonation_not_allowed", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / validation_failed (ttl_minutes)", body = ErrorEnvelope),
    )
)]
pub async fn impersonate(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Path(user_id): Path<UserId>,
    Json(body): Json<ImpersonateRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    let options = ImpersonationOptions {
        ttl_minutes: body.ttl_minutes,
        read_only: body.read_only.unwrap_or(true),
        client: match body.client.unwrap_or(ImpersonationClient::Web) {
            ImpersonationClient::Web => ClientKind::Web,
            ImpersonationClient::Native => ClientKind::Native,
        },
    };
    let issued = service
        .impersonate(&caller, &ctx, user_id, &reason, &options)
        .await?;
    let response = service
        .deps()
        .issuer
        .login_response(LoginOutcome::Authenticated(issued), None);
    Ok(no_store(response))
}

// --- emergency (ADM-06) ------------------------------------------------------------

/// Revokes every session of every user, the caller's included. Confirm with
/// `"confirm": "revoke_all_sessions"`.
#[utoipa::path(
    post,
    path = "/v1/admin/emergency/revoke-all-sessions",
    tag = "admin",
    request_body = EmergencyRequest,
    responses(
        (status = 200, description = "Done", body = EmergencyOutcome),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / admin_confirmation_required", body = ErrorEnvelope),
    )
)]
pub async fn emergency_revoke_all_sessions(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Json(body): Json<EmergencyRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    require_confirmation(body.confirm.as_deref(), "revoke_all_sessions")?;
    Ok(ok(service
        .revoke_all_sessions(&caller, &ctx, &reason)
        .await?))
}

/// Emergency signing key rotation: the active key is revoked and a new one
/// activated. Confirm with `"confirm": "rotate_signing_key"`.
#[utoipa::path(
    post,
    path = "/v1/admin/emergency/rotate-signing-key",
    tag = "admin",
    request_body = EmergencyRequest,
    responses(
        (status = 200, description = "Done", body = KeyRotationOutcome),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / admin_confirmation_required", body = ErrorEnvelope),
    )
)]
pub async fn emergency_rotate_signing_key(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Json(body): Json<EmergencyRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    require_confirmation(body.confirm.as_deref(), "rotate_signing_key")?;
    Ok(ok(service
        .rotate_signing_key(&caller, &ctx, &reason)
        .await?))
}

/// Requires a password change at the next login from every account whose
/// password was last changed before `changed_before`. Confirm with
/// `"confirm": "force_password_change"`.
#[utoipa::path(
    post,
    path = "/v1/admin/emergency/force-password-change",
    tag = "admin",
    request_body = ForcePasswordChangeRequest,
    responses(
        (status = 200, description = "Done", body = BulkResetOutcome),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / admin_confirmation_required / validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn emergency_force_password_change(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Json(body): Json<ForcePasswordChangeRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    require_confirmation(body.confirm.as_deref(), "force_password_change")?;
    let before = if body.changed_before.len() <= 64 {
        OffsetDateTime::parse(&body.changed_before, &Rfc3339).ok()
    } else {
        None
    }
    .ok_or_else(|| {
        AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(serde_json::json!({ "field": "changed_before" }))
    })?;
    Ok(ok(service
        .force_password_change_before(
            &caller,
            &ctx,
            before,
            body.revoke_sessions.unwrap_or(true),
            &reason,
        )
        .await?))
}

// --- audit (ADM-07) -------------------------------------------------------------------

/// Lists audit events platform-wide with the justification of admin
/// actions (ADM-07).
#[utoipa::path(
    get,
    path = "/v1/admin/audit-events",
    tag = "admin",
    params(AdminAuditFilter),
    responses(
        (status = 200, description = "Events", body = AdminAuditPage),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn list_audit_events(
    State(service): State<AdminService>,
    caller: AdminCaller,
    Query(query): Query<AdminAuditFilter>,
) -> Result<Response, AuthError> {
    let page = service.query_audit(&caller, query).await?;
    Ok(ok(AdminAuditPage {
        items: page.items,
        next_cursor: page.next_cursor,
    }))
}

/// Exports matching audit events (bounded; continue with `next_cursor`).
/// Needs a justification; the export is audited.
#[utoipa::path(
    post,
    path = "/v1/admin/audit-events/export",
    tag = "admin",
    request_body = ExportRequest,
    responses(
        (status = 200, description = "Export", body = AuditExport),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn export_audit_events(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Json(body): Json<ExportRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    let export = service
        .export_audit(&caller, &ctx, body.filter, &reason)
        .await?;
    let mut response = ok(export);
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"audit-events.json\""),
    );
    Ok(response)
}

/// Verifies the audit hash chain (AUD-02, ADM-07).
#[utoipa::path(
    post,
    path = "/v1/admin/audit-events/verify",
    tag = "admin",
    request_body = VerifyChainRequest,
    responses(
        (status = 200, description = "Verification report", body = ChainVerification),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 422, description = "validation_failed (anchor)", body = ErrorEnvelope),
    )
)]
pub async fn verify_audit_chain(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Json(body): Json<VerifyChainRequest>,
) -> Result<Response, AuthError> {
    Ok(ok(service
        .verify_audit_chain(&caller, &ctx, body.anchor)
        .await?))
}
