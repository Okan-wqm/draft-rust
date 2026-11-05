//! HTTP endpoints of authn-org (ARC-03, ARC-09).
//!
//! Every endpoint needs an authenticated [`Principal`] (session middleware
//! or [`crate::middleware::api_key_middleware`]). Organization-scoped
//! endpoints run [`OrgService::authorize`]: a resource of another
//! organization — whether addressed through another `{org_id}` or through
//! a foreign resource id under the caller's own organization — is
//! `404 not_found` (ORG-10). Every response carries
//! `Cache-Control: no-store`.
//!
//! | Method | Path | Permission | Requirement |
//! |--------|------|------------|-------------|
//! | `GET` / `POST` | `/v1/orgs` | own memberships / any verified user | ORG-01 |
//! | `GET` | `/v1/org-permissions` | authenticated | ORG-03 |
//! | `GET` / `PATCH` | `/v1/orgs/{org_id}` | `org:read` / `org:update` | ORG-01 |
//! | `DELETE` | `/v1/orgs/{org_id}` | owner + step-up | ORG-12 |
//! | `POST` | `/v1/orgs/{org_id}/deletion/cancel` | owner + step-up | ORG-12 |
//! | `POST` | `/v1/orgs/{org_id}/leave` | active member | ORG-02 |
//! | `GET` | `/v1/orgs/{org_id}/members[/{member_id}]` | `members:read` | ORG-02 |
//! | `PATCH` | `/v1/orgs/{org_id}/members/{member_id}` | `members:update` | ORG-02, ORG-04 |
//! | `DELETE` | `/v1/orgs/{org_id}/members/{member_id}` | `members:remove` | ORG-02 |
//! | `GET` / `POST` | `/v1/orgs/{org_id}/roles` | `roles:read` / `roles:manage` | ORG-03, ORG-04 |
//! | `PATCH` / `DELETE` | `/v1/orgs/{org_id}/roles/{role_id}` | `roles:manage` | ORG-03, ORG-04 |
//! | `GET` / `POST` | `/v1/orgs/{org_id}/invitations` | `members:invite` | ORG-05 |
//! | `DELETE` | `/v1/orgs/{org_id}/invitations/{invitation_id}` | `members:invite` | ORG-05 |
//! | `POST` | `/v1/orgs/{org_id}/invitations/{invitation_id}/resend` | `members:invite` | ORG-05 |
//! | `POST` | `/v1/invitations/preview`, `/v1/invitations/accept` | signed-in user | ORG-05 |
//! | `GET` / `POST` | `/v1/orgs/{org_id}/domains` | `domains:read` / `domains:manage` | ORG-06 |
//! | `PATCH` / `DELETE` | `/v1/orgs/{org_id}/domains/{domain_id}` | `domains:manage` | ORG-06 |
//! | `POST` | `/v1/orgs/{org_id}/domains/{domain_id}/verify` | `domains:manage` | ORG-06 |
//! | `GET` / `PUT` | `/v1/orgs/{org_id}/policy` | `policies:read` / `policies:manage` + step-up | ORG-07 |
//! | `GET` / `POST` | `/v1/orgs/{org_id}/api-keys` | `api_keys:read` / `api_keys:manage` + step-up | ORG-08 |
//! | `GET` / `DELETE` | `/v1/orgs/{org_id}/api-keys/{key_id}` | `api_keys:read` / `api_keys:manage` | ORG-08 |
//! | `POST` | `/v1/orgs/{org_id}/api-keys/{key_id}/rotate` | `api_keys:manage` + step-up | ORG-08 |
//! | `GET` / `POST` | `/v1/orgs/{org_id}/service-accounts` | `service_accounts:read` / `:manage` | ORG-09 |
//! | `GET` / `PATCH` / `DELETE` | `/v1/orgs/{org_id}/service-accounts/{service_account_id}` | `service_accounts:read` / `:manage` | ORG-09 |
//! | `POST` / `DELETE` | `/v1/orgs/{org_id}/ownership-transfer` | owner (+ step-up to request) | ORG-11 |
//! | `POST` | `/v1/ownership-transfers/accept` | target user + step-up | ORG-11 |

use authn_core::domain::{PageRequest, Principal};
use authn_core::error::{AuthError, ErrorEnvelope};
use authn_core::http::{Json, Path, Query, RequestContext};
use authn_core::id::{
    ApiKeyId, InvitationId, MembershipId, OrgDomainId, OrgId, RoleId, ServiceAccountId,
};
use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};

use crate::extract::SecretJson;
use crate::model::{
    ApiKeyOwner, ApiKeyPage, ApiKeyState, ApiKeySummary, CreatedApiKey, DomainStatus, Invitation,
    InvitationPage, InvitationPreview, InvitationStatus, Member, MemberPage, MemberStatus,
    MyOrganization, MyOrganizationPage, OrgDomain, OrgStatus, Organization, OwnershipTransfer,
    OwnershipTransferred, Role, RoleRef, ServiceAccount, ServiceAccountPage, ServiceAccountStatus,
};
use crate::permission::Permission;
use crate::policy::{OrgPolicy, OrgPolicyInput};
use crate::service::OrgService;
use crate::service::api_keys::{CreateApiKey, RotateApiKey};
use crate::service::domains::{AddDomain, UpdateDomain};
use crate::service::invitations::{CreateInvitation, InvitationToken};
use crate::service::members::UpdateMember;
use crate::service::orgs::{CreateOrganization, UpdateOrganization};
use crate::service::roles::{CreateRole, UpdateRole};
use crate::service::service_accounts::{CreateServiceAccount, UpdateServiceAccount};
use crate::service::transfer::{AcceptOwnershipTransfer, RequestOwnershipTransfer};

/// The module router. Requires [`OrgService`] from the state and an
/// authentication layer that inserts a [`Principal`].
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    OrgService: FromRef<S>,
{
    Router::new()
        .route(
            "/v1/orgs",
            get(list_my_organizations).post(create_organization),
        )
        .route("/v1/org-permissions", get(list_permissions))
        .route(
            "/v1/orgs/{org_id}",
            get(get_organization)
                .patch(update_organization)
                .delete(delete_organization),
        )
        .route("/v1/orgs/{org_id}/deletion/cancel", post(cancel_deletion))
        .route("/v1/orgs/{org_id}/leave", post(leave_organization))
        .route("/v1/orgs/{org_id}/members", get(list_members))
        .route(
            "/v1/orgs/{org_id}/members/{member_id}",
            get(get_member).patch(update_member).delete(remove_member),
        )
        .route("/v1/orgs/{org_id}/roles", get(list_roles).post(create_role))
        .route(
            "/v1/orgs/{org_id}/roles/{role_id}",
            patch(update_role).delete(delete_role),
        )
        .route(
            "/v1/orgs/{org_id}/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/v1/orgs/{org_id}/invitations/{invitation_id}",
            axum::routing::delete(revoke_invitation),
        )
        .route(
            "/v1/orgs/{org_id}/invitations/{invitation_id}/resend",
            post(resend_invitation),
        )
        .route("/v1/invitations/preview", post(preview_invitation))
        .route("/v1/invitations/accept", post(accept_invitation))
        .route(
            "/v1/orgs/{org_id}/domains",
            get(list_domains).post(add_domain),
        )
        .route(
            "/v1/orgs/{org_id}/domains/{domain_id}",
            patch(update_domain).delete(delete_domain),
        )
        .route(
            "/v1/orgs/{org_id}/domains/{domain_id}/verify",
            post(verify_domain),
        )
        .route(
            "/v1/orgs/{org_id}/policy",
            get(get_policy).put(update_policy),
        )
        .route(
            "/v1/orgs/{org_id}/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route(
            "/v1/orgs/{org_id}/api-keys/{key_id}",
            get(get_api_key).delete(revoke_api_key),
        )
        .route(
            "/v1/orgs/{org_id}/api-keys/{key_id}/rotate",
            post(rotate_api_key),
        )
        .route(
            "/v1/orgs/{org_id}/service-accounts",
            get(list_service_accounts).post(create_service_account),
        )
        .route(
            "/v1/orgs/{org_id}/service-accounts/{service_account_id}",
            get(get_service_account)
                .patch(update_service_account)
                .delete(delete_service_account),
        )
        .route(
            "/v1/orgs/{org_id}/ownership-transfer",
            post(request_ownership_transfer).delete(cancel_ownership_transfer),
        )
        .route(
            "/v1/ownership-transfers/accept",
            post(accept_ownership_transfer),
        )
}

/// OpenAPI document of this crate's endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(
        list_my_organizations,
        create_organization,
        list_permissions,
        get_organization,
        update_organization,
        delete_organization,
        cancel_deletion,
        leave_organization,
        list_members,
        get_member,
        update_member,
        remove_member,
        list_roles,
        create_role,
        update_role,
        delete_role,
        list_invitations,
        create_invitation,
        revoke_invitation,
        resend_invitation,
        preview_invitation,
        accept_invitation,
        list_domains,
        add_domain,
        update_domain,
        delete_domain,
        verify_domain,
        get_policy,
        update_policy,
        list_api_keys,
        create_api_key,
        get_api_key,
        revoke_api_key,
        rotate_api_key,
        list_service_accounts,
        create_service_account,
        get_service_account,
        update_service_account,
        delete_service_account,
        request_ownership_transfer,
        cancel_ownership_transfer,
        accept_ownership_transfer
    ),
    components(schemas(
        Organization,
        OrgStatus,
        MyOrganization,
        MyOrganizationPage,
        CreateOrganization,
        UpdateOrganization,
        Member,
        MemberPage,
        MemberStatus,
        UpdateMember,
        Role,
        RoleRef,
        RoleList,
        CreateRole,
        UpdateRole,
        Permission,
        PermissionCatalog,
        PermissionInfo,
        Invitation,
        InvitationPage,
        InvitationStatus,
        InvitationPreview,
        CreateInvitation,
        InvitationToken,
        OrgDomain,
        DomainStatus,
        DomainList,
        AddDomain,
        UpdateDomain,
        OrgPolicy,
        OrgPolicyInput,
        ApiKeySummary,
        ApiKeyPage,
        ApiKeyOwner,
        ApiKeyState,
        CreatedApiKey,
        CreateApiKey,
        RotateApiKey,
        ServiceAccount,
        ServiceAccountPage,
        ServiceAccountStatus,
        CreateServiceAccount,
        UpdateServiceAccount,
        OwnershipTransfer,
        OwnershipTransferred,
        RequestOwnershipTransfer,
        AcceptOwnershipTransfer,
    )),
    tags((name = "organizations", description = "Organizations, members, RBAC, invitations, domains, policies, API keys and service accounts"))
)]
pub struct OrgApi;

/// Custom and built-in roles.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleList {
    /// Built-in roles first, then custom roles by creation.
    pub roles: Vec<Role>,
}

/// Domains of an organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct DomainList {
    /// Oldest first.
    pub domains: Vec<OrgDomain>,
}

/// One catalog entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionInfo {
    /// `resource:action`.
    pub permission: Permission,
    /// Only the built-in owner role has it; never on custom roles / keys.
    pub owner_only: bool,
    /// Read-only permission.
    pub read_only: bool,
}

/// The permission catalog (ORG-03).
#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionCatalog {
    /// Every permission, in catalog order.
    pub permissions: Vec<PermissionInfo>,
}

/// JSON with `Cache-Control: no-store`.
fn no_store<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn no_content() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// --- organizations -------------------------------------------------------------

/// The caller's organizations (ORG-01, ORG-02).
#[utoipa::path(
    get,
    path = "/v1/orgs",
    tag = "organizations",
    params(PageRequest),
    responses(
        (status = 200, description = "Memberships, oldest first", body = MyOrganizationPage),
        (status = 401, description = "unauthenticated", body = ErrorEnvelope),
        (status = 403, description = "API keys cannot list memberships", body = ErrorEnvelope),
    )
)]
pub async fn list_my_organizations(
    State(service): State<OrgService>,
    principal: Principal,
    Query(page): Query<PageRequest>,
) -> Result<Response, AuthError> {
    let page = service.list_my_organizations(&principal, &page).await?;
    Ok(no_store(StatusCode::OK, page))
}

/// Creates an organization; the caller becomes `owner` (ORG-01).
#[utoipa::path(
    post,
    path = "/v1/orgs",
    tag = "organizations",
    request_body = CreateOrganization,
    responses(
        (status = 201, description = "Created", body = Organization),
        (status = 401, description = "unauthenticated", body = ErrorEnvelope),
        (status = 403, description = "org_email_verification_required / forbidden", body = ErrorEnvelope),
        (status = 409, description = "org_slug_taken", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn create_organization(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Json(body): Json<CreateOrganization>,
) -> Result<Response, AuthError> {
    let org = service.create_organization(&ctx, &principal, body).await?;
    Ok(no_store(StatusCode::CREATED, org))
}

/// The permission catalog (ORG-03).
#[utoipa::path(
    get,
    path = "/v1/org-permissions",
    tag = "organizations",
    responses(
        (status = 200, description = "Catalog", body = PermissionCatalog),
        (status = 401, description = "unauthenticated", body = ErrorEnvelope),
    )
)]
pub async fn list_permissions(_principal: Principal) -> Response {
    no_store(
        StatusCode::OK,
        PermissionCatalog {
            permissions: Permission::ALL
                .iter()
                .map(|p| PermissionInfo {
                    permission: *p,
                    owner_only: p.is_owner_only(),
                    read_only: p.is_read_only(),
                })
                .collect(),
        },
    )
}

/// Reads an organization (`org:read`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 200, description = "Organization", body = Organization),
        (status = 401, description = "unauthenticated / step_up_required (session lifetime cap)", body = ErrorEnvelope),
        (status = 403, description = "forbidden / org_policy_*", body = ErrorEnvelope),
        (status = 404, description = "not_found (unknown or other tenant)", body = ErrorEnvelope),
    )
)]
pub async fn get_organization(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    let org = service.get_organization(&ctx, &principal, org).await?;
    Ok(no_store(StatusCode::OK, org))
}

/// Renames the organization / changes its slug (`org:update`).
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = UpdateOrganization,
    responses(
        (status = 200, description = "Updated", body = Organization),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_slug_taken / org_pending_deletion", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn update_organization(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<UpdateOrganization>,
) -> Result<Response, AuthError> {
    let org = service
        .update_organization(&ctx, &principal, org, body)
        .await?;
    Ok(no_store(StatusCode::OK, org))
}

/// Schedules the organization's deletion (owner + step-up, ORG-12).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 202, description = "Deletion scheduled", body = Organization),
        (status = 401, description = "step_up_required", body = ErrorEnvelope),
        (status = 403, description = "org_owner_required", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_pending_deletion", body = ErrorEnvelope),
    )
)]
pub async fn delete_organization(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    let org = service.schedule_deletion(&ctx, &principal, org).await?;
    Ok(no_store(StatusCode::ACCEPTED, org))
}

/// Cancels a scheduled deletion (owner + step-up, ORG-12).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/deletion/cancel",
    operation_id = "cancel_org_deletion",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 200, description = "Deletion cancelled", body = Organization),
        (status = 401, description = "step_up_required", body = ErrorEnvelope),
        (status = 403, description = "org_owner_required", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_deletion_not_scheduled", body = ErrorEnvelope),
    )
)]
pub async fn cancel_deletion(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    let org = service.cancel_deletion(&ctx, &principal, org).await?;
    Ok(no_store(StatusCode::OK, org))
}

/// The caller leaves the organization (ORG-02; the last owner cannot).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/leave",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 204, description = "Left"),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_last_owner", body = ErrorEnvelope),
    )
)]
pub async fn leave_organization(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    service.leave_organization(&ctx, &principal, org).await?;
    Ok(no_content())
}

// --- members --------------------------------------------------------------------

/// Lists members (`members:read`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/members",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id"), PageRequest),
    responses(
        (status = 200, description = "Members, oldest first", body = MemberPage),
        (status = 403, description = "forbidden", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn list_members(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Query(page): Query<PageRequest>,
) -> Result<Response, AuthError> {
    let page = service.list_members(&ctx, &principal, org, &page).await?;
    Ok(no_store(StatusCode::OK, page))
}

/// Reads a member (`members:read`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/members/{member_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("member_id" = MembershipId, Path, description = "Membership id"),
    ),
    responses(
        (status = 200, description = "Member", body = Member),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn get_member(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, member)): Path<(OrgId, MembershipId)>,
) -> Result<Response, AuthError> {
    let member = service.get_member(&ctx, &principal, org, member).await?;
    Ok(no_store(StatusCode::OK, member))
}

/// Changes a member's role / status (`members:update`; escalation guard,
/// last-owner protection; granting `owner` needs step-up).
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}/members/{member_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("member_id" = MembershipId, Path, description = "Membership id"),
    ),
    request_body = UpdateMember,
    responses(
        (status = 200, description = "Updated", body = Member),
        (status = 401, description = "step_up_required (granting owner)", body = ErrorEnvelope),
        (status = 403, description = "forbidden / org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_last_owner", body = ErrorEnvelope),
    )
)]
pub async fn update_member(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, member)): Path<(OrgId, MembershipId)>,
    Json(body): Json<UpdateMember>,
) -> Result<Response, AuthError> {
    let member = service
        .update_member(&ctx, &principal, org, member, body)
        .await?;
    Ok(no_store(StatusCode::OK, member))
}

/// Removes a member (`members:remove`).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/members/{member_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("member_id" = MembershipId, Path, description = "Membership id"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 403, description = "forbidden / org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_last_owner", body = ErrorEnvelope),
    )
)]
pub async fn remove_member(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, member)): Path<(OrgId, MembershipId)>,
) -> Result<Response, AuthError> {
    service.remove_member(&ctx, &principal, org, member).await?;
    Ok(no_content())
}

// --- roles ------------------------------------------------------------------------

/// Built-in and custom roles (`roles:read`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/roles",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 200, description = "Roles", body = RoleList),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn list_roles(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    let roles = service.list_roles(&ctx, &principal, org).await?;
    Ok(no_store(StatusCode::OK, RoleList { roles }))
}

/// Creates a custom role (`roles:manage`).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/roles",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = CreateRole,
    responses(
        (status = 201, description = "Created", body = Role),
        (status = 403, description = "forbidden / org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_role_key_taken / org_limit_reached", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn create_role(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<CreateRole>,
) -> Result<Response, AuthError> {
    let role = service.create_role(&ctx, &principal, org, body).await?;
    Ok(no_store(StatusCode::CREATED, role))
}

/// Changes a custom role (`roles:manage`).
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}/roles/{role_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("role_id" = RoleId, Path, description = "Role id"),
    ),
    request_body = UpdateRole,
    responses(
        (status = 200, description = "Updated", body = Role),
        (status = 403, description = "forbidden / org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_builtin_role_immutable", body = ErrorEnvelope),
    )
)]
pub async fn update_role(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, role)): Path<(OrgId, RoleId)>,
    Json(body): Json<UpdateRole>,
) -> Result<Response, AuthError> {
    let role = service
        .update_role(&ctx, &principal, org, role, body)
        .await?;
    Ok(no_store(StatusCode::OK, role))
}

/// Deletes an unused custom role (`roles:manage`).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/roles/{role_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("role_id" = RoleId, Path, description = "Role id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_role_in_use / org_builtin_role_immutable", body = ErrorEnvelope),
    )
)]
pub async fn delete_role(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, role)): Path<(OrgId, RoleId)>,
) -> Result<Response, AuthError> {
    service.delete_role(&ctx, &principal, org, role).await?;
    Ok(no_content())
}

// --- invitations ----------------------------------------------------------------

/// Lists invitations (`members:invite`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/invitations",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id"), PageRequest),
    responses(
        (status = 200, description = "Invitations, oldest first", body = InvitationPage),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn list_invitations(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Query(page): Query<PageRequest>,
) -> Result<Response, AuthError> {
    let page = service
        .list_invitations(&ctx, &principal, org, &page)
        .await?;
    Ok(no_store(StatusCode::OK, page))
}

/// Invites an address (`members:invite`, ORG-05).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/invitations",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = CreateInvitation,
    responses(
        (status = 201, description = "Invitation sent", body = Invitation),
        (status = 403, description = "forbidden / org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_invitation_pending / org_already_member / org_limit_reached", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn create_invitation(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<CreateInvitation>,
) -> Result<Response, AuthError> {
    let invitation = service
        .create_invitation(&ctx, &principal, org, body)
        .await?;
    Ok(no_store(StatusCode::CREATED, invitation))
}

/// Revokes a pending invitation (`members:invite`).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/invitations/{invitation_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("invitation_id" = InvitationId, Path, description = "Invitation id"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "conflict (not pending)", body = ErrorEnvelope),
    )
)]
pub async fn revoke_invitation(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, invitation)): Path<(OrgId, InvitationId)>,
) -> Result<Response, AuthError> {
    service
        .revoke_invitation(&ctx, &principal, org, invitation)
        .await?;
    Ok(no_content())
}

/// Re-sends an invitation with a new token (`members:invite`).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/invitations/{invitation_id}/resend",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("invitation_id" = InvitationId, Path, description = "Invitation id"),
    ),
    responses(
        (status = 200, description = "Re-sent", body = Invitation),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "conflict (not pending)", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn resend_invitation(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, invitation)): Path<(OrgId, InvitationId)>,
) -> Result<Response, AuthError> {
    let invitation = service
        .resend_invitation(&ctx, &principal, org, invitation)
        .await?;
    Ok(no_store(StatusCode::OK, invitation))
}

/// Shows what an invitation grants (signed-in user).
#[utoipa::path(
    post,
    path = "/v1/invitations/preview",
    tag = "organizations",
    request_body = InvitationToken,
    responses(
        (status = 200, description = "Preview", body = InvitationPreview),
        (status = 400, description = "invalid_or_expired_token", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn preview_invitation(
    State(service): State<OrgService>,
    principal: Principal,
    SecretJson(body): SecretJson<InvitationToken>,
) -> Result<Response, AuthError> {
    let preview = service.preview_invitation(&principal, &body.token).await?;
    Ok(no_store(StatusCode::OK, preview))
}

/// Accepts an invitation (ORG-05).
#[utoipa::path(
    post,
    path = "/v1/invitations/accept",
    tag = "organizations",
    request_body = InvitationToken,
    responses(
        (status = 200, description = "Joined", body = MyOrganization),
        (status = 400, description = "invalid_or_expired_token", body = ErrorEnvelope),
        (status = 403, description = "org_invitation_email_mismatch / org_email_verification_required", body = ErrorEnvelope),
        (status = 409, description = "org_already_member", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn accept_invitation(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    SecretJson(body): SecretJson<InvitationToken>,
) -> Result<Response, AuthError> {
    let joined = service
        .accept_invitation(&ctx, &principal, &body.token)
        .await?;
    Ok(no_store(StatusCode::OK, joined))
}

// --- domains --------------------------------------------------------------------------

/// Lists domains (`domains:read`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/domains",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 200, description = "Domains", body = DomainList),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn list_domains(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    let domains = service.list_domains(&ctx, &principal, org).await?;
    Ok(no_store(StatusCode::OK, DomainList { domains }))
}

/// Adds a domain (`domains:manage`, ORG-06). The response names the TXT
/// record to publish.
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/domains",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = AddDomain,
    responses(
        (status = 201, description = "Added", body = OrgDomain),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_domain_exists / org_limit_reached", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn add_domain(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<AddDomain>,
) -> Result<Response, AuthError> {
    let domain = service.add_domain(&ctx, &principal, org, body).await?;
    Ok(no_store(StatusCode::CREATED, domain))
}

/// Turns auto-join on / off (`domains:manage`).
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}/domains/{domain_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("domain_id" = OrgDomainId, Path, description = "Domain id"),
    ),
    request_body = UpdateDomain,
    responses(
        (status = 200, description = "Updated", body = OrgDomain),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_domain_not_verified", body = ErrorEnvelope),
    )
)]
pub async fn update_domain(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, domain)): Path<(OrgId, OrgDomainId)>,
    Json(body): Json<UpdateDomain>,
) -> Result<Response, AuthError> {
    let domain = service
        .update_domain(&ctx, &principal, org, domain, body)
        .await?;
    Ok(no_store(StatusCode::OK, domain))
}

/// Removes a domain (`domains:manage`).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/domains/{domain_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("domain_id" = OrgDomainId, Path, description = "Domain id"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn delete_domain(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, domain)): Path<(OrgId, OrgDomainId)>,
) -> Result<Response, AuthError> {
    service.delete_domain(&ctx, &principal, org, domain).await?;
    Ok(no_content())
}

/// Checks the DNS TXT record (`domains:manage`, ORG-06).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/domains/{domain_id}/verify",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("domain_id" = OrgDomainId, Path, description = "Domain id"),
    ),
    responses(
        (status = 200, description = "Verified", body = OrgDomain),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_domain_claimed", body = ErrorEnvelope),
        (status = 422, description = "org_domain_verification_failed", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
        (status = 503, description = "service_unavailable (DNS)", body = ErrorEnvelope),
    )
)]
pub async fn verify_domain(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, domain)): Path<(OrgId, OrgDomainId)>,
) -> Result<Response, AuthError> {
    let domain = service.verify_domain(&ctx, &principal, org, domain).await?;
    Ok(no_store(StatusCode::OK, domain))
}

// --- policy ---------------------------------------------------------------------------

/// Reads the security policy (`policies:read`, ORG-07).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/policy",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 200, description = "Policy", body = OrgPolicy),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn get_policy(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    let policy = service.get_policy(&ctx, &principal, org).await?;
    Ok(no_store(StatusCode::OK, policy))
}

/// Replaces the security policy (`policies:manage` + step-up, ORG-07).
#[utoipa::path(
    put,
    path = "/v1/orgs/{org_id}/policy",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = OrgPolicyInput,
    responses(
        (status = 200, description = "Policy", body = OrgPolicy),
        (status = 401, description = "step_up_required", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 422, description = "validation_failed / org_policy_lockout", body = ErrorEnvelope),
    )
)]
pub async fn update_policy(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<OrgPolicyInput>,
) -> Result<Response, AuthError> {
    let policy = service.update_policy(&ctx, &principal, org, body).await?;
    Ok(no_store(StatusCode::OK, policy))
}

// --- API keys ---------------------------------------------------------------------------

/// Lists API keys (`api_keys:read`, ORG-08).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/api-keys",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id"), PageRequest),
    responses(
        (status = 200, description = "Keys (metadata only)", body = ApiKeyPage),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn list_api_keys(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Query(page): Query<PageRequest>,
) -> Result<Response, AuthError> {
    let page = service.list_api_keys(&ctx, &principal, org, &page).await?;
    Ok(no_store(StatusCode::OK, page))
}

/// Creates an API key (`api_keys:manage` + step-up). The key is shown once.
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/api-keys",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = CreateApiKey,
    responses(
        (status = 201, description = "Created; store the key now", body = CreatedApiKey),
        (status = 401, description = "step_up_required", body = ErrorEnvelope),
        (status = 403, description = "forbidden / org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "org_limit_reached / service_account_disabled", body = ErrorEnvelope),
        (status = 422, description = "api_key_scope_invalid / api_key_expiry_invalid", body = ErrorEnvelope),
    )
)]
pub async fn create_api_key(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<CreateApiKey>,
) -> Result<Response, AuthError> {
    let created = service.create_api_key(&ctx, &principal, org, body).await?;
    Ok(no_store(StatusCode::CREATED, created))
}

/// Reads an API key's metadata (`api_keys:read`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/api-keys/{key_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("key_id" = ApiKeyId, Path, description = "API key id"),
    ),
    responses(
        (status = 200, description = "Metadata", body = ApiKeySummary),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn get_api_key(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, key)): Path<(OrgId, ApiKeyId)>,
) -> Result<Response, AuthError> {
    let key = service.get_api_key(&ctx, &principal, org, key).await?;
    Ok(no_store(StatusCode::OK, key))
}

/// Revokes an API key (`api_keys:manage`).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/api-keys/{key_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("key_id" = ApiKeyId, Path, description = "API key id"),
    ),
    responses(
        (status = 200, description = "Revoked", body = ApiKeySummary),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn revoke_api_key(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, key)): Path<(OrgId, ApiKeyId)>,
) -> Result<Response, AuthError> {
    let key = service.revoke_api_key(&ctx, &principal, org, key).await?;
    Ok(no_store(StatusCode::OK, key))
}

/// Rotates an API key (`api_keys:manage` + step-up). The new key is shown
/// once; the old key works until the grace period ends.
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/api-keys/{key_id}/rotate",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("key_id" = ApiKeyId, Path, description = "API key id"),
    ),
    request_body = RotateApiKey,
    responses(
        (status = 201, description = "New key; store it now", body = CreatedApiKey),
        (status = 401, description = "step_up_required", body = ErrorEnvelope),
        (status = 403, description = "org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "api_key_inactive", body = ErrorEnvelope),
    )
)]
pub async fn rotate_api_key(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, key)): Path<(OrgId, ApiKeyId)>,
    SecretJson(body): SecretJson<RotateApiKey>,
) -> Result<Response, AuthError> {
    let created = service
        .rotate_api_key(&ctx, &principal, org, key, body)
        .await?;
    Ok(no_store(StatusCode::CREATED, created))
}

// --- service accounts ---------------------------------------------------------------

/// Lists service accounts (`service_accounts:read`, ORG-09).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/service-accounts",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id"), PageRequest),
    responses(
        (status = 200, description = "Service accounts", body = ServiceAccountPage),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn list_service_accounts(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Query(page): Query<PageRequest>,
) -> Result<Response, AuthError> {
    let page = service
        .list_service_accounts(&ctx, &principal, org, &page)
        .await?;
    Ok(no_store(StatusCode::OK, page))
}

/// Creates a service account (`service_accounts:manage`).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/service-accounts",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = CreateServiceAccount,
    responses(
        (status = 201, description = "Created", body = ServiceAccount),
        (status = 403, description = "forbidden / org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "service_account_name_taken / org_limit_reached", body = ErrorEnvelope),
        (status = 422, description = "validation_failed", body = ErrorEnvelope),
    )
)]
pub async fn create_service_account(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<CreateServiceAccount>,
) -> Result<Response, AuthError> {
    let sa = service
        .create_service_account(&ctx, &principal, org, body)
        .await?;
    Ok(no_store(StatusCode::CREATED, sa))
}

/// Reads a service account (`service_accounts:read`).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/service-accounts/{service_account_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("service_account_id" = ServiceAccountId, Path, description = "Service account id"),
    ),
    responses(
        (status = 200, description = "Service account", body = ServiceAccount),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn get_service_account(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, sa)): Path<(OrgId, ServiceAccountId)>,
) -> Result<Response, AuthError> {
    let sa = service
        .get_service_account(&ctx, &principal, org, sa)
        .await?;
    Ok(no_store(StatusCode::OK, sa))
}

/// Changes a service account (`service_accounts:manage`).
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}/service-accounts/{service_account_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("service_account_id" = ServiceAccountId, Path, description = "Service account id"),
    ),
    request_body = UpdateServiceAccount,
    responses(
        (status = 200, description = "Updated", body = ServiceAccount),
        (status = 403, description = "org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 409, description = "service_account_name_taken", body = ErrorEnvelope),
    )
)]
pub async fn update_service_account(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, sa)): Path<(OrgId, ServiceAccountId)>,
    Json(body): Json<UpdateServiceAccount>,
) -> Result<Response, AuthError> {
    let sa = service
        .update_service_account(&ctx, &principal, org, sa, body)
        .await?;
    Ok(no_store(StatusCode::OK, sa))
}

/// Deletes a service account and its keys (`service_accounts:manage`).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/service-accounts/{service_account_id}",
    tag = "organizations",
    params(
        ("org_id" = OrgId, Path, description = "Organization id"),
        ("service_account_id" = ServiceAccountId, Path, description = "Service account id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, description = "org_role_escalation", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn delete_service_account(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path((org, sa)): Path<(OrgId, ServiceAccountId)>,
) -> Result<Response, AuthError> {
    service
        .delete_service_account(&ctx, &principal, org, sa)
        .await?;
    Ok(no_content())
}

// --- ownership transfer --------------------------------------------------------------

/// Starts an ownership transfer (owner + step-up, ORG-11).
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/ownership-transfer",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    request_body = RequestOwnershipTransfer,
    responses(
        (status = 202, description = "Acceptance e-mail sent", body = OwnershipTransfer),
        (status = 401, description = "step_up_required", body = ErrorEnvelope),
        (status = 403, description = "org_owner_required", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
        (status = 422, description = "org_transfer_target_invalid", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn request_ownership_transfer(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
    Json(body): Json<RequestOwnershipTransfer>,
) -> Result<Response, AuthError> {
    let transfer = service
        .request_ownership_transfer(&ctx, &principal, org, body)
        .await?;
    Ok(no_store(StatusCode::ACCEPTED, transfer))
}

/// Cancels pending ownership transfers (owner).
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/ownership-transfer",
    tag = "organizations",
    params(("org_id" = OrgId, Path, description = "Organization id")),
    responses(
        (status = 204, description = "Cancelled"),
        (status = 403, description = "org_owner_required", body = ErrorEnvelope),
        (status = 404, description = "not_found", body = ErrorEnvelope),
    )
)]
pub async fn cancel_ownership_transfer(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    Path(org): Path<OrgId>,
) -> Result<Response, AuthError> {
    service
        .cancel_ownership_transfer(&ctx, &principal, org)
        .await?;
    Ok(no_content())
}

/// Accepts an ownership transfer (target user + step-up, ORG-11).
#[utoipa::path(
    post,
    path = "/v1/ownership-transfers/accept",
    tag = "organizations",
    request_body = AcceptOwnershipTransfer,
    responses(
        (status = 200, description = "Transferred", body = OwnershipTransferred),
        (status = 400, description = "invalid_or_expired_token", body = ErrorEnvelope),
        (status = 401, description = "step_up_required", body = ErrorEnvelope),
        (status = 429, description = "rate_limited", body = ErrorEnvelope),
    )
)]
pub async fn accept_ownership_transfer(
    State(service): State<OrgService>,
    ctx: RequestContext,
    principal: Principal,
    SecretJson(body): SecretJson<AcceptOwnershipTransfer>,
) -> Result<Response, AuthError> {
    let done = service
        .accept_ownership_transfer(&ctx, &principal, &body.token)
        .await?;
    Ok(no_store(StatusCode::OK, done))
}
