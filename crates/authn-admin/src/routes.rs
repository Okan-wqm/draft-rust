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
//! | `GET`, `POST` | `/v1/admin/approvals` | K-66 (four-eyes requests) |
//! | `POST` | `/v1/admin/approvals/{approval_id}/approve`, `…/deny` | K-66 |
//! | `POST` | `/v1/admin/emergency/revoke-all-sessions` | ADM-06 |
//! | `POST` | `/v1/admin/emergency/rotate-signing-key` | ADM-06 |
//! | `POST` | `/v1/admin/emergency/force-password-change` | ADM-06 |
//! | `GET` | `/v1/admin/audit-events` | ADM-07 |
//! | `POST` | `/v1/admin/audit-events/export` | ADM-07 |
//! | `POST` | `/v1/admin/audit-events/verify` | ADM-07, K-09 |
//! | `POST` | `/v1/admin/audit-events/{event_id}/restrict` | ADM-08, K-39, K-62 |
//! | `POST` | `/v1/admin/audit-events/{event_id}/restrict/extend` | ADM-08, K-62 |
//! | `POST` | `/v1/admin/enrollment/options`, `/v1/admin/enrollment/verify` | ADM-05, K-11 ([`enrollment_router`], no session) |

use authn_core::domain::{ClientKind, Page};
use authn_core::error::{AuthError, ErrorEnvelope, codes};
use authn_core::http::{Json, Path, Query, RequestContext};
use authn_core::id::{EventId, UserId};
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
    AdminUserSummary, ApprovalView, AuditExport, BulkResetOutcome, ChainVerification,
    CriticalOperation, EmergencyOutcome, ForcedReset, ImpersonationOptions, KeyRotationOutcome,
    PasswordState, UserSearch, UserStatusFilter, VerifiedAnchor,
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
            "/v1/admin/approvals",
            get(list_approvals).post(request_approval),
        )
        .route(
            "/v1/admin/approvals/{approval_id}/approve",
            post(approve_approval),
        )
        .route(
            "/v1/admin/approvals/{approval_id}/deny",
            post(deny_approval),
        )
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
        .route(
            "/v1/admin/audit-events/{event_id}/restrict",
            post(restrict_justification),
        )
        .route(
            "/v1/admin/audit-events/{event_id}/restrict/extend",
            post(extend_restriction),
        )
}

/// The public break-glass passkey enrollment endpoints (ADM-05, K-11). No
/// session: the single-use link token in the body is the authorization.
/// Mount next to [`router`] (same IP allow-list applies; per-IP limit).
#[cfg(feature = "passkey")]
pub fn enrollment_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AdminService: FromRef<S>,
{
    Router::new()
        .route("/v1/admin/enrollment/options", post(enrollment_options))
        .route("/v1/admin/enrollment/verify", post(enrollment_verify))
}

/// OpenAPI document of the enrollment endpoints (K-11).
#[cfg(feature = "passkey")]
#[derive(OpenApi)]
#[openapi(
    paths(enrollment_options, enrollment_verify),
    components(schemas(EnrollmentOptionsRequest, EnrollmentVerifyRequest)),
    tags((name = "admin", description = "Platform admin API (passkey session + step-up)"))
)]
pub struct AdminEnrollmentApi;

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
        list_approvals,
        request_approval,
        approve_approval,
        deny_approval,
        emergency_revoke_all_sessions,
        emergency_rotate_signing_key,
        emergency_force_password_change,
        list_audit_events,
        export_audit_events,
        verify_audit_chain,
        restrict_justification,
        extend_restriction
    ),
    components(schemas(
        AdminUserSummary,
        AdminUserPage,
        AdminUserDetail,
        PasswordState,
        UserStatusFilter,
        ReasonRequest,
        ApprovalRequest,
        DecisionRequest,
        ApprovalView,
        MustChangePasswordRequest,
        ForcePasswordResetRequest,
        ImpersonateRequest,
        ImpersonationClient,
        EmergencyRequest,
        RevokeAllRequest,
        ForcePasswordChangeRequest,
        ExportRequest,
        VerifyChainRequest,
        RestrictRequest,
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
    /// Four-eyes approval (K-66) — only for suspend, unlock and
    /// revoke-sessions (used when the target is another platform admin and
    /// `admin.four_eyes` is on); refused (`validation_failed`) on the other
    /// actions.
    #[schema(value_type = Option<String>)]
    pub approval_id: Option<uuid::Uuid>,
}

/// Body of `POST /v1/admin/approvals` (K-66): the exact operation to be
/// approved. Parameters not used by the operation are refused.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    /// `revoke_all_sessions`, `rotate_signing_key`,
    /// `force_password_change_before`, `suspend_user`, `unlock_user` or
    /// `revoke_user_sessions`.
    pub action: String,
    /// Target platform admin (`suspend_user`, `unlock_user`,
    /// `revoke_user_sessions` only).
    pub target_user_id: Option<UserId>,
    /// `revoke_all_sessions` only (default `false`).
    pub include_own_session: Option<bool>,
    /// `force_password_change_before` only (RFC 3339, required).
    pub changed_before: Option<String>,
    /// `force_password_change_before` only (default `true`).
    pub revoke_sessions: Option<bool>,
    /// Mandatory justification (ADM-08).
    pub reason: Option<String>,
}

/// Body of `POST /v1/admin/approvals/{approval_id}/approve` and `…/deny`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    /// Mandatory justification of the decision (ADM-08).
    pub reason: Option<String>,
}

fn invalid_field(field: &'static str) -> AuthError {
    AuthError::new(codes::common::VALIDATION_FAILED)
        .with_details(serde_json::json!({ "field": field }))
}

fn parse_instant(value: &str, field: &'static str) -> Result<OffsetDateTime, AuthError> {
    if value.len() > 64 {
        return Err(invalid_field(field));
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid_field(field))
}

impl ApprovalRequest {
    /// The operation, strictly validated: unknown actions, a missing or
    /// superfluous target and parameters of another operation are refused.
    fn operation(&self) -> Result<CriticalOperation, AuthError> {
        let emergency_params = (
            self.include_own_session.is_some(),
            self.changed_before.is_some() || self.revoke_sessions.is_some(),
        );
        let targeted = matches!(
            self.action.as_str(),
            "suspend_user" | "unlock_user" | "revoke_user_sessions"
        );
        if targeted != self.target_user_id.is_some() {
            return Err(invalid_field("target_user_id"));
        }
        let operation = match (self.action.as_str(), self.target_user_id) {
            ("suspend_user", Some(u)) => CriticalOperation::SuspendAdmin(u),
            ("unlock_user", Some(u)) => CriticalOperation::UnlockAdmin(u),
            ("revoke_user_sessions", Some(u)) => CriticalOperation::RevokeAdminSessions(u),
            ("revoke_all_sessions", None) => CriticalOperation::RevokeAllSessions {
                include_own_session: self.include_own_session.unwrap_or(false),
            },
            ("rotate_signing_key", None) => CriticalOperation::RotateSigningKey,
            ("force_password_change_before", None) => CriticalOperation::ForcePasswordChange {
                changed_before: self
                    .changed_before
                    .as_deref()
                    .ok_or_else(|| invalid_field("changed_before"))
                    .and_then(|v| parse_instant(v, "changed_before"))?,
                revoke_sessions: self.revoke_sessions.unwrap_or(true),
            },
            _ => return Err(invalid_field("action")),
        };
        let allowed = match operation {
            CriticalOperation::RevokeAllSessions { .. } => (true, false),
            CriticalOperation::ForcePasswordChange { .. } => (false, true),
            _ => (false, false),
        };
        if (emergency_params.0 && !allowed.0) || (emergency_params.1 && !allowed.1) {
            return Err(invalid_field("action"));
        }
        Ok(operation)
    }
}

/// Body of `POST /v1/admin/audit-events/{event_id}/restrict` and
/// `…/restrict/extend` (K-62).
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RestrictRequest {
    /// Mandatory restriction note / extension justification (ADM-08).
    pub reason: Option<String>,
    /// Review date (RFC 3339): the restriction ends then unless extended;
    /// after now and at most 180 days ahead.
    pub review_at: Option<String>,
}

fn parse_review_at(value: Option<&str>) -> Result<OffsetDateTime, AuthError> {
    value
        .filter(|v| v.len() <= 64)
        .and_then(|v| OffsetDateTime::parse(v, &Rfc3339).ok())
        .ok_or_else(|| {
            AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(serde_json::json!({ "field": "review_at" }))
        })
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
    /// Web session whose token is returned in the body and sent back in
    /// the `x-impersonation-session` header (the admin's own cookie stays).
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
    /// Four-eyes approval (K-66), when `admin.four_eyes` is on.
    #[schema(value_type = Option<String>)]
    pub approval_id: Option<uuid::Uuid>,
}

/// Body of `POST /v1/admin/emergency/revoke-all-sessions`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeAllRequest {
    /// Mandatory justification.
    pub reason: Option<String>,
    /// Must be `revoke_all_sessions`.
    pub confirm: Option<String>,
    /// Also revoke the caller's own session (default `false`: the caller's
    /// session is kept, K-10).
    pub include_own_session: Option<bool>,
    /// Four-eyes approval (K-66), when `admin.four_eyes` is on.
    #[schema(value_type = Option<String>)]
    pub approval_id: Option<uuid::Uuid>,
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
    /// Four-eyes approval (K-66), when `admin.four_eyes` is on.
    #[schema(value_type = Option<String>)]
    pub approval_id: Option<uuid::Uuid>,
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
                (status = 403, description = "forbidden / admin_phishing_resistant_mfa_required / admin_target_not_allowed / admin_approval_required / admin_approval_invalid (K-66)", body = ErrorEnvelope),
                (status = 404, description = "not_found", body = ErrorEnvelope),
                (status = 409, description = "account_status_transition_not_allowed", body = ErrorEnvelope),
                (status = 422, description = "admin_reason_required", body = ErrorEnvelope),
            ),
            security(("session_cookie" = []), ("bearer_jwt" = []))
        )]
        pub async fn $name(
            State(service): State<AdminService>,
            caller: AdminCaller,
            ctx: RequestContext,
            Path(user_id): Path<UserId>,
            Json(body): Json<ReasonRequest>,
        ) -> Result<Response, AuthError> {
            let reason = Justification::parse(body.reason.as_deref())?;
            if body.approval_id.is_some() {
                return Err(invalid_field("approval_id"));
            }
            Ok(ok(service.$method(&caller, &ctx, user_id, &reason).await?))
        }
    };

    ($(#[$doc:meta])* $name:ident, $path:literal, $method:ident, approved) => {
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
                (status = 403, description = "forbidden / admin_phishing_resistant_mfa_required / admin_target_not_allowed / admin_approval_required / admin_approval_invalid (K-66)", body = ErrorEnvelope),
                (status = 404, description = "not_found", body = ErrorEnvelope),
                (status = 409, description = "account_status_transition_not_allowed", body = ErrorEnvelope),
                (status = 422, description = "admin_reason_required", body = ErrorEnvelope),
            ),
            security(("session_cookie" = []), ("bearer_jwt" = []))
        )]
        pub async fn $name(
            State(service): State<AdminService>,
            caller: AdminCaller,
            ctx: RequestContext,
            Path(user_id): Path<UserId>,
            Json(body): Json<ReasonRequest>,
        ) -> Result<Response, AuthError> {
            let reason = Justification::parse(body.reason.as_deref())?;
            Ok(ok(service
                .$method(&caller, &ctx, user_id, &reason, body.approval_id)
                .await?))
        }
    };

}

reason_action!(
    /// Suspends the account and revokes its sessions and trusted devices.
    suspend_user,
    "/v1/admin/users/{user_id}/suspend",
    suspend_user_approved,
    approved
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
    unlock_user_approved,
    approved
);
reason_action!(
    /// Revokes every session and trusted device of the account.
    revoke_user_sessions,
    "/v1/admin/users/{user_id}/revoke-sessions",
    revoke_user_sessions_approved,
    approved
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
/// by default and at most 60. The admin's session cookie is never replaced
/// (K-12). Web: the body carries `impersonation_token`, to be sent in the
/// `x-impersonation-session` request header; native: tokens whose access
/// tokens carry the `act` claim.
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
    // K-12: never a `Set-Cookie` — the admin's own session cookie survives.
    // Web: the impersonation token is in the body, to be sent in the
    // `x-impersonation-session` header; native: tokens in the body.
    let response = service.deps().issuer.impersonation_response(issued);
    Ok(no_store(response))
}

// --- four-eyes approvals (K-66) ---------------------------------------------------

/// Recent four-eyes approval requests (last 7 days, newest first).
#[utoipa::path(
    get,
    path = "/v1/admin/approvals",
    tag = "admin",
    responses(
        (status = 200, description = "Approval requests", body = [ApprovalView]),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_phishing_resistant_mfa_required", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn list_approvals(
    State(service): State<AdminService>,
    caller: AdminCaller,
) -> Result<Response, AuthError> {
    Ok(ok(service.list_approvals(&caller).await?))
}

/// Requests a second platform admin's approval of a critical operation
/// (K-66): an emergency operation or an action on another platform admin,
/// with its exact parameters. Expires after `admin.four_eyes_approval_ttl`.
#[utoipa::path(
    post,
    path = "/v1/admin/approvals",
    tag = "admin",
    request_body = ApprovalRequest,
    responses(
        (status = 200, description = "Pending approval request", body = ApprovalView),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_target_not_allowed", body = ErrorEnvelope),
        (status = 404, description = "not_found (target)", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / validation_failed", body = ErrorEnvelope),
        (status = 429, description = "rate_limited: more than 3 pending or 10 per hour requests of this admin (K-66)", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn request_approval(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Json(body): Json<ApprovalRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    let operation = body.operation()?;
    Ok(ok(service
        .request_approval(&caller, &ctx, operation, &reason)
        .await?))
}

macro_rules! decision {
    ($(#[$doc:meta])* $name:ident, $path:literal, $approve:literal) => {
        $(#[$doc])*
        #[utoipa::path(
            post,
            path = $path,
            tag = "admin",
            params(("approval_id" = String, Path, description = "Approval request id")),
            request_body = DecisionRequest,
            responses(
                (status = 200, description = "Decided", body = ApprovalView),
                (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
                (status = 403, description = "forbidden / admin_phishing_resistant_mfa_required / admin_self_approval_not_allowed / admin_target_not_allowed / admin_approval_invalid (decided or expired)", body = ErrorEnvelope),
                (status = 404, description = "not_found", body = ErrorEnvelope),
                (status = 422, description = "admin_reason_required", body = ErrorEnvelope),
            ),
            security(("session_cookie" = []), ("bearer_jwt" = []))
        )]
        pub async fn $name(
            State(service): State<AdminService>,
            caller: AdminCaller,
            ctx: RequestContext,
            Path(approval_id): Path<uuid::Uuid>,
            Json(body): Json<DecisionRequest>,
        ) -> Result<Response, AuthError> {
            let reason = Justification::parse(body.reason.as_deref())?;
            Ok(ok(service
                .decide_approval(&caller, &ctx, approval_id, $approve, &reason)
                .await?))
        }
    };
}

decision!(
    /// Approves another admin's pending request (K-66). The approver passes
    /// the full admin guard (passkey session, step-up) and is neither the
    /// requester nor the target.
    approve_approval,
    "/v1/admin/approvals/{approval_id}/approve",
    true
);
decision!(
    /// Denies another admin's pending request (K-66). Final.
    deny_approval,
    "/v1/admin/approvals/{approval_id}/deny",
    false
);

// --- emergency (ADM-06) ------------------------------------------------------------

/// Revokes every session of every user — except the caller's own session
/// unless `include_own_session` is `true` (K-10). Confirm with
/// `"confirm": "revoke_all_sessions"`.
#[utoipa::path(
    post,
    path = "/v1/admin/emergency/revoke-all-sessions",
    tag = "admin",
    request_body = RevokeAllRequest,
    responses(
        (status = 200, description = "Done", body = EmergencyOutcome),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_approval_required / admin_approval_invalid (K-66)", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / admin_confirmation_required", body = ErrorEnvelope),
        (status = 429, description = "rate_limited (K-08: per-admin / global budget, cool-down)", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn emergency_revoke_all_sessions(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Json(body): Json<RevokeAllRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    require_confirmation(body.confirm.as_deref(), "revoke_all_sessions")?;
    Ok(ok(service
        .revoke_all_sessions_approved(
            &caller,
            &ctx,
            &reason,
            body.include_own_session.unwrap_or(false),
            body.approval_id,
        )
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
        (status = 403, description = "forbidden / admin_approval_required / admin_approval_invalid (K-66)", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / admin_confirmation_required", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
        .rotate_signing_key_approved(&caller, &ctx, &reason, body.approval_id)
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
        (status = 403, description = "forbidden / admin_approval_required / admin_approval_invalid (K-66)", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / admin_confirmation_required / validation_failed", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
        .force_password_change_before_approved(
            &caller,
            &ctx,
            before,
            body.revoke_sessions.unwrap_or(true),
            &reason,
            body.approval_id,
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
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

/// Withholds the justification of an admin action from the subject's data
/// export under a legal restriction until `review_at` (K-39, K-62; KVKK
/// art. 28 / GDPR art. 23). The restriction note (`reason`) and the review
/// date (at most 180 days ahead) are mandatory; the restriction is itself
/// audited, hidden from the subject while active, and cannot be lifted
/// early through the API.
#[utoipa::path(
    post,
    path = "/v1/admin/audit-events/{event_id}/restrict",
    tag = "admin",
    params(("event_id" = String, Path, description = "Audit event of the admin action")),
    request_body = RestrictRequest,
    responses(
        (status = 200, description = "Restricted", body = ActionOutcome),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_target_not_allowed", body = ErrorEnvelope),
        (status = 404, description = "not_found (no justification about a user)", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / validation_failed (review_at)", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn restrict_justification(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Path(event_id): Path<EventId>,
    Json(body): Json<RestrictRequest>,
) -> Result<Response, AuthError> {
    let note = Justification::parse(body.reason.as_deref())?;
    let review_at = parse_review_at(body.review_at.as_deref())?;
    Ok(ok(service
        .restrict_justification(&caller, &ctx, event_id, &note, review_at)
        .await?))
}

/// Extends an active restriction to a later review date (K-62): mandatory
/// justification, new date at most 180 days ahead; audited and hidden from
/// the subject like the restriction.
#[utoipa::path(
    post,
    path = "/v1/admin/audit-events/{event_id}/restrict/extend",
    tag = "admin",
    params(("event_id" = String, Path, description = "Audit event of the restricted admin action")),
    request_body = RestrictRequest,
    responses(
        (status = 200, description = "Extended", body = ActionOutcome),
        (status = 401, description = "unauthenticated / step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / admin_target_not_allowed", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "conflict (no active restriction)", body = ErrorEnvelope),
        (status = 422, description = "admin_reason_required / validation_failed (review_at)", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn extend_restriction(
    State(service): State<AdminService>,
    caller: AdminCaller,
    ctx: RequestContext,
    Path(event_id): Path<EventId>,
    Json(body): Json<RestrictRequest>,
) -> Result<Response, AuthError> {
    let reason = Justification::parse(body.reason.as_deref())?;
    let review_at = parse_review_at(body.review_at.as_deref())?;
    Ok(ok(service
        .extend_restriction(&caller, &ctx, event_id, &reason, review_at)
        .await?))
}

// --- break-glass passkey enrollment (K-11) -------------------------------------

/// Body of `POST /v1/admin/enrollment/options`.
#[cfg(feature = "passkey")]
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentOptionsRequest {
    /// The link token (from the URL fragment of the enrollment link).
    #[schema(value_type = String)]
    pub token: authn_core::secret::SensitiveString,
}

#[cfg(feature = "passkey")]
impl std::fmt::Debug for EnrollmentOptionsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentOptionsRequest")
            .finish_non_exhaustive()
    }
}

/// Body of `POST /v1/admin/enrollment/verify`.
#[cfg(feature = "passkey")]
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentVerifyRequest {
    /// The link token.
    #[schema(value_type = String)]
    pub token: authn_core::secret::SensitiveString,
    /// The ceremony id from the options response.
    #[schema(value_type = String)]
    pub ceremony_id: authn_core::id::CeremonyId,
    /// The `PublicKeyCredential` of `navigator.credentials.create()`.
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
}

#[cfg(feature = "passkey")]
impl std::fmt::Debug for EnrollmentVerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentVerifyRequest")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

/// Registration options for the account of a break-glass enrollment link
/// (K-11).
#[cfg(feature = "passkey")]
#[utoipa::path(
    post,
    path = "/v1/admin/enrollment/options",
    tag = "admin",
    request_body = EnrollmentOptionsRequest,
    responses(
        (status = 200, description = "WebAuthn creation options and ceremony id"),
        (status = 400, description = "invalid_or_expired_token", body = ErrorEnvelope),
        (status = 403, description = "forbidden (IP allow-list)", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn enrollment_options(
    State(service): State<AdminService>,
    ctx: RequestContext,
    Json(body): Json<EnrollmentOptionsRequest>,
) -> Result<Response, AuthError> {
    Ok(ok(service
        .start_break_glass_enrollment(&ctx, body.token.expose())
        .await?))
}

/// Stores the passkey and consumes the enrollment link (K-11).
#[cfg(feature = "passkey")]
#[utoipa::path(
    post,
    path = "/v1/admin/enrollment/verify",
    tag = "admin",
    request_body = EnrollmentVerifyRequest,
    responses(
        (status = 200, description = "The enrolled passkey"),
        (status = 400, description = "invalid_or_expired_token / passkey_ceremony_invalid / passkey_registration_failed", body = ErrorEnvelope),
        (status = 403, description = "forbidden (IP allow-list)", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn enrollment_verify(
    State(service): State<AdminService>,
    ctx: RequestContext,
    Json(body): Json<EnrollmentVerifyRequest>,
) -> Result<Response, AuthError> {
    let request = authn_webauthn::RegistrationVerifyRequest {
        ceremony_id: body.ceremony_id,
        credential: body.credential,
        name: None,
    };
    Ok(ok(service
        .finish_break_glass_enrollment(&ctx, body.token.expose(), request)
        .await?))
}
