//! HTTP endpoints (AUD-04, AUD-07, ARC-03, ARC-09).
//!
//! | Method | Path | Permission |
//! |--------|------|------------|
//! | GET | `/v1/me/security-events` | authenticated user |
//! | GET | `/v1/orgs/{org_id}/audit-events` | `audit:read` |
//! | GET | `/v1/orgs/{org_id}/webhooks` | `webhooks:read` |
//! | POST | `/v1/orgs/{org_id}/webhooks` | `webhooks:manage` + step-up |
//! | GET | `/v1/orgs/{org_id}/webhooks/{endpoint_id}` | `webhooks:read` |
//! | PATCH | `/v1/orgs/{org_id}/webhooks/{endpoint_id}` | `webhooks:manage` (+ step-up for URL / subscriptions / enabling) |
//! | DELETE | `/v1/orgs/{org_id}/webhooks/{endpoint_id}` | `webhooks:manage` + step-up |
//! | POST | `/v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret` | `webhooks:manage` + step-up |
//! | GET | `/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries` | `webhooks:read` |
//! | POST | `/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver` | `webhooks:manage` |
//!
//! Organization endpoints answer `404 not_found` for every authorization
//! failure (other tenant, not a member, missing permission) — the same as
//! for an unknown organization (ORG-10). Order of checks: authentication →
//! authorization → read-only impersonation → step-up → rate limit.

use authn_core::domain::{Page, PageRequest, Principal};
use authn_core::error::{AuthError, ErrorEnvelope};
use authn_core::http::{Json, Path, Query, RequestContext};
use authn_core::id::{OrgId, WebhookDeliveryId, WebhookEndpointId};
use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::policy::{AuditPermission, actor_of, authorize};
use crate::query::{
    AuditEventQuery, OrgAuditEventView, SecurityEventView, list_org_events,
    list_user_security_events,
};
use crate::service::AuditService;
use crate::webhooks::{
    ActingPrincipal, CreateWebhookEndpoint, UpdateWebhookEndpoint, WebhookDeliveryView,
    WebhookEndpointView, WebhookEndpointWithSecret,
};

/// The module router.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AuditService: FromRef<S>,
{
    Router::new()
        .route("/v1/me/security-events", get(list_my_security_events))
        .route("/v1/orgs/{org_id}/audit-events", get(list_org_audit_events))
        .route(
            "/v1/orgs/{org_id}/webhooks",
            get(list_webhooks).post(create_webhook),
        )
        .route(
            "/v1/orgs/{org_id}/webhooks/{endpoint_id}",
            get(get_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route(
            "/v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret",
            post(rotate_webhook_secret),
        )
        .route(
            "/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries",
            get(list_webhook_deliveries),
        )
        .route(
            "/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver",
            post(redeliver_webhook),
        )
}

/// A page of the user's security events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecurityEventPage {
    /// Events, newest first.
    pub items: Vec<SecurityEventView>,
    /// Cursor of the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A page of an organization's audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrgAuditEventPage {
    /// Events, newest first.
    pub items: Vec<OrgAuditEventView>,
    /// Cursor of the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A page of webhook deliveries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookDeliveryPage {
    /// Deliveries, newest first.
    pub items: Vec<WebhookDeliveryView>,
    /// Cursor of the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The endpoints of an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookEndpointList {
    /// Endpoints, oldest first.
    pub items: Vec<WebhookEndpointView>,
}

/// Query of `rotate-secret`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct RotateSecretQuery {
    /// Discard the previous secret immediately (suspected leak) instead of
    /// keeping it valid during the overlap period.
    #[serde(default)]
    pub immediate: bool,
}

fn no_store<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn acting(principal: &Principal, ctx: RequestContext) -> ActingPrincipal {
    let (actor, impersonator) = actor_of(principal);
    ActingPrincipal {
        actor,
        impersonator,
        context: Some(ctx),
    }
}

async fn authorize_read(
    service: &AuditService,
    principal: &Principal,
    ctx: &RequestContext,
    org: OrgId,
    permission: AuditPermission,
) -> Result<(), AuthError> {
    authorize(
        service.policy(),
        principal,
        org,
        permission,
        Some(ctx.client_ip),
    )
    .await?;
    service
        .rate_limit(
            AuditService::principal_key("audit_read", principal),
            service.config().rate_limits.events_read,
        )
        .await
}

async fn authorize_write(
    service: &AuditService,
    principal: &Principal,
    ctx: &RequestContext,
    org: OrgId,
    step_up: bool,
) -> Result<(), AuthError> {
    authorize(
        service.policy(),
        principal,
        org,
        AuditPermission::WebhooksManage,
        Some(ctx.client_ip),
    )
    .await?;
    principal.require_writable()?;
    if step_up {
        service.require_step_up(principal)?;
    }
    service
        .rate_limit(
            authn_core::ports::RateLimitKey::org("webhook_write", org),
            service.config().rate_limits.webhook_write,
        )
        .await
}

/// The caller's own security events of the last 90 days (AUD-04).
#[utoipa::path(
    get,
    path = "/v1/me/security-events",
    tag = "audit",
    params(PageRequest),
    responses(
        (status = 200, description = "Own security events, newest first", body = SecurityEventPage),
        (status = 401, description = "Not authenticated", body = ErrorEnvelope),
        (status = 403, description = "Not a user principal", body = ErrorEnvelope),
        (status = 422, description = "Invalid cursor", body = ErrorEnvelope),
        (status = 429, description = "Rate limited", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []))
)]
pub async fn list_my_security_events(
    State(service): State<AuditService>,
    principal: Principal,
    Query(page): Query<PageRequest>,
) -> Result<Json<SecurityEventPage>, AuthError> {
    let user = principal.require_user()?;
    page.cursor()?;
    service
        .rate_limit(
            AuditService::principal_key("security_events_read", &principal),
            service.config().rate_limits.events_read,
        )
        .await?;
    let Page { items, next_cursor } = list_user_security_events(
        service.pool(),
        user,
        service.clock().now(),
        service.config().user_visible_window,
        &page,
    )
    .await?;
    Ok(Json(SecurityEventPage { items, next_cursor }))
}

/// An organization's audit log with filters (AUD-04).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/audit-events",
    tag = "audit",
    params(("org_id" = OrgId, Path, description = "Organization"), AuditEventQuery),
    responses(
        (status = 200, description = "Audit events, newest first", body = OrgAuditEventPage),
        (status = 401, description = "Not authenticated", body = ErrorEnvelope),
        (status = 404, description = "Unknown organization or no access", body = ErrorEnvelope),
        (status = 422, description = "Invalid filter", body = ErrorEnvelope),
        (status = 429, description = "Rate limited", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn list_org_audit_events(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path(org): Path<OrgId>,
    Query(query): Query<AuditEventQuery>,
) -> Result<Json<OrgAuditEventPage>, AuthError> {
    authorize_read(&service, &principal, &ctx, org, AuditPermission::AuditRead).await?;
    let (filter, page) = query.into_filter()?;
    let Page { items, next_cursor } = list_org_events(service.pool(), org, &filter, &page).await?;
    Ok(Json(OrgAuditEventPage { items, next_cursor }))
}

/// Lists an organization's webhook endpoints (AUD-07).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/webhooks",
    tag = "webhooks",
    params(("org_id" = OrgId, Path, description = "Organization")),
    responses(
        (status = 200, description = "Endpoints", body = WebhookEndpointList),
        (status = 404, description = "Unknown organization or no access", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn list_webhooks(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path(org): Path<OrgId>,
) -> Result<Json<WebhookEndpointList>, AuthError> {
    authorize_read(
        &service,
        &principal,
        &ctx,
        org,
        AuditPermission::WebhooksRead,
    )
    .await?;
    let items = service.webhooks().list(org).await?;
    Ok(Json(WebhookEndpointList { items }))
}

/// Creates a webhook endpoint; the signing secret is returned once
/// (AUD-07).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/webhooks",
    tag = "webhooks",
    params(("org_id" = OrgId, Path, description = "Organization")),
    request_body = CreateWebhookEndpoint,
    responses(
        (status = 201, description = "Created; store the secret now", body = WebhookEndpointWithSecret),
        (status = 401, description = "Step-up required", body = ErrorEnvelope),
        (status = 403, description = "Read-only impersonation", body = ErrorEnvelope),
        (status = 404, description = "Unknown organization or no access", body = ErrorEnvelope),
        (status = 409, description = "Endpoint limit reached", body = ErrorEnvelope),
        (status = 422, description = "Invalid URL or event types", body = ErrorEnvelope),
        (status = 429, description = "Rate limited", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn create_webhook(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path(org): Path<OrgId>,
    Json(body): Json<CreateWebhookEndpoint>,
) -> Result<Response, AuthError> {
    authorize_write(&service, &principal, &ctx, org, true).await?;
    let created = service
        .webhooks()
        .create(org, body, &acting(&principal, ctx))
        .await?;
    Ok(no_store(StatusCode::CREATED, created))
}

/// One webhook endpoint (AUD-07).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/webhooks/{endpoint_id}",
    tag = "webhooks",
    params(
        ("org_id" = OrgId, Path, description = "Organization"),
        ("endpoint_id" = WebhookEndpointId, Path, description = "Endpoint"),
    ),
    responses(
        (status = 200, description = "The endpoint", body = WebhookEndpointView),
        (status = 404, description = "Unknown endpoint or no access", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn get_webhook(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path((org, id)): Path<(OrgId, WebhookEndpointId)>,
) -> Result<Json<WebhookEndpointView>, AuthError> {
    authorize_read(
        &service,
        &principal,
        &ctx,
        org,
        AuditPermission::WebhooksRead,
    )
    .await?;
    Ok(Json(service.webhooks().get(org, id).await?))
}

/// Changes a webhook endpoint (AUD-07).
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}/webhooks/{endpoint_id}",
    tag = "webhooks",
    params(
        ("org_id" = OrgId, Path, description = "Organization"),
        ("endpoint_id" = WebhookEndpointId, Path, description = "Endpoint"),
    ),
    request_body = UpdateWebhookEndpoint,
    responses(
        (status = 200, description = "Updated endpoint", body = WebhookEndpointView),
        (status = 401, description = "Step-up required", body = ErrorEnvelope),
        (status = 403, description = "Read-only impersonation", body = ErrorEnvelope),
        (status = 404, description = "Unknown endpoint or no access", body = ErrorEnvelope),
        (status = 422, description = "Invalid values", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn update_webhook(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path((org, id)): Path<(OrgId, WebhookEndpointId)>,
    Json(body): Json<UpdateWebhookEndpoint>,
) -> Result<Json<WebhookEndpointView>, AuthError> {
    authorize_write(&service, &principal, &ctx, org, body.is_sensitive()).await?;
    Ok(Json(
        service
            .webhooks()
            .update(org, id, body, &acting(&principal, ctx))
            .await?,
    ))
}

/// Deletes a webhook endpoint and its delivery history (AUD-07).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/webhooks/{endpoint_id}",
    tag = "webhooks",
    params(
        ("org_id" = OrgId, Path, description = "Organization"),
        ("endpoint_id" = WebhookEndpointId, Path, description = "Endpoint"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Step-up required", body = ErrorEnvelope),
        (status = 404, description = "Unknown endpoint or no access", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn delete_webhook(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path((org, id)): Path<(OrgId, WebhookEndpointId)>,
) -> Result<StatusCode, AuthError> {
    authorize_write(&service, &principal, &ctx, org, true).await?;
    service
        .webhooks()
        .delete(org, id, &acting(&principal, ctx))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Rotates the signing secret; the new secret is returned once (AUD-07).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret",
    tag = "webhooks",
    params(
        ("org_id" = OrgId, Path, description = "Organization"),
        ("endpoint_id" = WebhookEndpointId, Path, description = "Endpoint"),
        RotateSecretQuery,
    ),
    responses(
        (status = 200, description = "Rotated; store the secret now", body = WebhookEndpointWithSecret),
        (status = 401, description = "Step-up required", body = ErrorEnvelope),
        (status = 404, description = "Unknown endpoint or no access", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn rotate_webhook_secret(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path((org, id)): Path<(OrgId, WebhookEndpointId)>,
    Query(query): Query<RotateSecretQuery>,
) -> Result<Response, AuthError> {
    authorize_write(&service, &principal, &ctx, org, true).await?;
    let rotated = service
        .webhooks()
        .rotate_secret(org, id, query.immediate, &acting(&principal, ctx))
        .await?;
    Ok(no_store(StatusCode::OK, rotated))
}

/// Delivery history of an endpoint (AUD-07).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries",
    tag = "webhooks",
    params(
        ("org_id" = OrgId, Path, description = "Organization"),
        ("endpoint_id" = WebhookEndpointId, Path, description = "Endpoint"),
        PageRequest,
    ),
    responses(
        (status = 200, description = "Deliveries, newest first", body = WebhookDeliveryPage),
        (status = 404, description = "Unknown endpoint or no access", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn list_webhook_deliveries(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path((org, id)): Path<(OrgId, WebhookEndpointId)>,
    Query(page): Query<PageRequest>,
) -> Result<Json<WebhookDeliveryPage>, AuthError> {
    authorize_read(
        &service,
        &principal,
        &ctx,
        org,
        AuditPermission::WebhooksRead,
    )
    .await?;
    let Page { items, next_cursor } = service.webhooks().deliveries(org, id, &page).await?;
    Ok(Json(WebhookDeliveryPage { items, next_cursor }))
}

/// Schedules a finished delivery again (AUD-07).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver",
    tag = "webhooks",
    params(
        ("org_id" = OrgId, Path, description = "Organization"),
        ("endpoint_id" = WebhookEndpointId, Path, description = "Endpoint"),
        ("delivery_id" = WebhookDeliveryId, Path, description = "Delivery"),
    ),
    responses(
        (status = 202, description = "Scheduled", body = WebhookDeliveryView),
        (status = 404, description = "Unknown delivery or no access", body = ErrorEnvelope),
        (status = 409, description = "Still scheduled or endpoint disabled", body = ErrorEnvelope),
        (status = 429, description = "Rate limited", body = ErrorEnvelope),
    ),
    security(("session_cookie" = []), ("bearer_jwt" = []), ("api_key" = []), ("api_key_bearer" = []))
)]
pub async fn redeliver_webhook(
    State(service): State<AuditService>,
    principal: Principal,
    ctx: RequestContext,
    Path((org, endpoint, delivery)): Path<(OrgId, WebhookEndpointId, WebhookDeliveryId)>,
) -> Result<(StatusCode, Json<WebhookDeliveryView>), AuthError> {
    authorize(
        service.policy(),
        &principal,
        org,
        AuditPermission::WebhooksManage,
        Some(ctx.client_ip),
    )
    .await?;
    principal.require_writable()?;
    service
        .rate_limit(
            authn_core::ports::RateLimitKey::org("webhook_redeliver", org),
            service.config().rate_limits.webhook_redeliver,
        )
        .await?;
    let view = service
        .webhooks()
        .redeliver(org, endpoint, delivery, &acting(&principal, ctx))
        .await?;
    Ok((StatusCode::ACCEPTED, Json(view)))
}

/// OpenAPI document of this crate (merged by the server).
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_my_security_events,
        list_org_audit_events,
        list_webhooks,
        create_webhook,
        get_webhook,
        update_webhook,
        delete_webhook,
        rotate_webhook_secret,
        list_webhook_deliveries,
        redeliver_webhook,
    ),
    components(schemas(
        SecurityEventPage,
        SecurityEventView,
        crate::query::ActorView,
        OrgAuditEventPage,
        OrgAuditEventView,
        WebhookEndpointList,
        WebhookEndpointView,
        WebhookEndpointWithSecret,
        CreateWebhookEndpoint,
        UpdateWebhookEndpoint,
        WebhookDeliveryPage,
        WebhookDeliveryView,
        ErrorEnvelope,
    )),
    tags(
        (name = "audit", description = "Security events and organization audit log (AUD-04)"),
        (name = "webhooks", description = "Signed organization webhooks (AUD-07)"),
    )
)]
pub struct AuditApi;
