//! Public data types of authn-org (service results and HTTP bodies).
//!
//! None of these types carries a secret except [`CreatedApiKey`], whose key
//! is shown exactly once (ORG-08) and whose `Debug` is redacted.

use std::net::IpAddr;

use authn_core::id::{
    ApiKeyId, InvitationId, MembershipId, OrgDomainId, OrgId, RoleId, ServiceAccountId, UserId,
};
use authn_core::secret::SensitiveString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::permission::Permission;

org_text_enum! {
    /// Lifecycle of an organization.
    pub enum OrgStatus {
        /// Normal operation.
        Active => "active",
        /// Suspended by the platform: nothing is allowed.
        Suspended => "suspended",
        /// Deletion scheduled (ORG-12): read and cancel only.
        PendingDeletion => "pending_deletion",
    }
}

org_text_enum! {
    /// Status of a membership (ORG-02).
    pub enum MemberStatus {
        /// Full member.
        Active => "active",
        /// Suspended: no access, sessions revoked.
        Suspended => "suspended",
    }
}

org_text_enum! {
    /// Status of an invitation (ORG-05).
    pub enum InvitationStatus {
        /// Waiting for acceptance.
        Pending => "pending",
        /// Accepted.
        Accepted => "accepted",
        /// Revoked by an administrator.
        Revoked => "revoked",
        /// Expired (set by cleanup or when superseded).
        Expired => "expired",
    }
}

org_text_enum! {
    /// Status of a claimed domain (ORG-06).
    pub enum DomainStatus {
        /// Added, not verified yet.
        Pending => "pending",
        /// TXT record found.
        Verified => "verified",
        /// Last check did not find the record (can be retried).
        Failed => "failed",
    }
}

org_text_enum! {
    /// Status of a service account (ORG-09).
    pub enum ServiceAccountStatus {
        /// Its API keys authenticate.
        Active => "active",
        /// Its API keys are refused.
        Disabled => "disabled",
    }
}

org_text_enum! {
    /// Derived state of an API key (ORG-08).
    pub enum ApiKeyState {
        /// Usable.
        Active => "active",
        /// Replaced by a rotation; usable until `rotation_grace_until`.
        Rotating => "rotating",
        /// Revoked (or rotation grace ended).
        Revoked => "revoked",
        /// Past `expires_at`.
        Expired => "expired",
    }
}

/// An organization (ORG-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, sqlx::FromRow)]
pub struct Organization {
    /// Id.
    pub id: OrgId,
    /// Unique URL-safe slug.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// Lifecycle status.
    pub status: OrgStatus,
    /// When a scheduled deletion becomes final (ORG-12).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub deletion_scheduled_for: Option<OffsetDateTime>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Last change.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: OffsetDateTime,
}

/// A role reference inside other resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RoleRef {
    /// Role id.
    pub id: RoleId,
    /// Role key (`owner`, `admin`, custom keys…).
    pub key: String,
    /// Display name.
    pub name: String,
}

/// One of the caller's organizations (`GET /v1/orgs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MyOrganization {
    /// The organization.
    pub organization: Organization,
    /// The caller's membership.
    pub membership_id: MembershipId,
    /// The caller's role.
    pub role: RoleRef,
    /// The caller's membership status.
    pub member_status: MemberStatus,
}

/// A member of an organization (ORG-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Member {
    /// Membership id (path parameter of the member endpoints).
    pub id: MembershipId,
    /// The user.
    pub user_id: UserId,
    /// The user's e-mail address (`None` for anonymised accounts).
    pub email: Option<String>,
    /// Role.
    pub role: RoleRef,
    /// Status.
    pub status: MemberStatus,
    /// Who invited the member.
    pub invited_by: Option<UserId>,
    /// Joined.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Last change.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: OffsetDateTime,
}

/// A role with its permissions (ORG-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Role {
    /// Id (fixed for built-in roles).
    pub id: RoleId,
    /// Key, unique per organization.
    pub key: String,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Built-in roles cannot be changed.
    pub builtin: bool,
    /// Permissions, in catalog order.
    pub permissions: Vec<Permission>,
}

/// An invitation (ORG-05). The token is never returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Invitation {
    /// Id.
    pub id: InvitationId,
    /// Invited address.
    pub email: String,
    /// Role granted on acceptance.
    pub role: RoleRef,
    /// Status (`pending` invitations past `expires_at` are reported as
    /// `expired`).
    pub status: InvitationStatus,
    /// Inviter.
    pub invited_by: Option<UserId>,
    /// How often the invitation e-mail was sent.
    pub send_count: i32,
    /// Last send.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub last_sent_at: OffsetDateTime,
    /// Created.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// Acceptance time.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub accepted_at: Option<OffsetDateTime>,
    /// Revocation time.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub revoked_at: Option<OffsetDateTime>,
}

/// What an invited user sees before accepting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct InvitationPreview {
    /// Organization.
    pub org_id: OrgId,
    /// Organization name.
    pub org_name: String,
    /// Role granted on acceptance.
    pub role: RoleRef,
    /// Masked invited address (`a***@example.com`).
    pub email_masked: String,
    /// Whether the caller's verified address matches the invitation.
    pub email_matches: bool,
    /// Expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
}

/// A domain claimed by an organization (ORG-06).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct OrgDomain {
    /// Id.
    pub id: OrgDomainId,
    /// ASCII (punycode) lowercase domain.
    pub domain: String,
    /// Verification status.
    pub status: DomainStatus,
    /// Users with a verified address of this domain join automatically.
    pub auto_join: bool,
    /// Phase 2: SSO required for this domain (stored, not enforced yet).
    pub sso_required: bool,
    /// DNS name of the TXT record to create.
    pub verification_record_name: String,
    /// Exact TXT record value to publish (public by design).
    pub verification_value: String,
    /// Last DNS check.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_checked_at: Option<OffsetDateTime>,
    /// Verification time.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub verified_at: Option<OffsetDateTime>,
    /// Created.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Consecutive checks that found the TXT record definitively absent
    /// (periodic re-verification, ORG-13); reset by a successful check.
    pub consecutive_absent_checks: u32,
    /// Consecutive inconclusive checks (resolver error, timeout; ORG-13).
    pub consecutive_inconclusive_checks: u32,
    /// Outcome of the last check: `present`, `absent` or `inconclusive`.
    pub last_check_outcome: Option<String>,
    /// When periodic re-verification took the verification away (ORG-13);
    /// cleared by verifying again.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub unverified_at: Option<OffsetDateTime>,
}

/// Owner of an API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiKeyOwner {
    /// A service account of the organization (ORG-09).
    ServiceAccount {
        /// The service account.
        service_account_id: ServiceAccountId,
    },
    /// A member acting inside the organization.
    User {
        /// The member.
        user_id: UserId,
    },
}

/// API key metadata (ORG-08). Never contains the key or its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ApiKeySummary {
    /// Id.
    pub id: ApiKeyId,
    /// Name.
    pub name: String,
    /// Non-secret prefix (`ak_live_AbCd`) to recognise the key.
    pub display_prefix: String,
    /// Environment label.
    pub environment: String,
    /// Granted scopes (permissions); effective rights are the owner's
    /// current permissions intersected with these.
    pub scopes: Vec<Permission>,
    /// Who the key acts as.
    pub owner: ApiKeyOwner,
    /// Derived state.
    pub state: ApiKeyState,
    /// Creator.
    pub created_by: Option<UserId>,
    /// Created.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Mandatory expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// Last successful use (updated at most once per configured interval).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_used_at: Option<OffsetDateTime>,
    /// Client IP of the last recorded use.
    #[schema(value_type = Option<String>)]
    pub last_used_ip: Option<IpAddr>,
    /// Revocation time.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub revoked_at: Option<OffsetDateTime>,
    /// Revocation reason code.
    pub revoked_reason: Option<String>,
    /// The key this one replaced (rotation).
    pub rotated_from_id: Option<ApiKeyId>,
    /// After a rotation: the old key works until this time.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub rotation_grace_until: Option<OffsetDateTime>,
}

/// A newly created or rotated API key. `key` is shown **once**.
#[derive(Clone, Serialize, ToSchema)]
pub struct CreatedApiKey {
    /// The full key. Store it now; it cannot be retrieved again.
    #[schema(value_type = String, example = "ak_live_…")]
    pub key: SensitiveString,
    /// Metadata.
    pub api_key: ApiKeySummary,
}

impl std::fmt::Debug for CreatedApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedApiKey")
            .field("api_key", &self.api_key)
            .finish_non_exhaustive()
    }
}

/// A service account (ORG-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ServiceAccount {
    /// Id.
    pub id: ServiceAccountId,
    /// Name, unique per organization.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Role (never `owner`).
    pub role: RoleRef,
    /// Status.
    pub status: ServiceAccountStatus,
    /// Creator.
    pub created_by: Option<UserId>,
    /// Created.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Last change.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: OffsetDateTime,
}

/// A pending ownership transfer (ORG-11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct OwnershipTransfer {
    /// Organization.
    pub org_id: OrgId,
    /// The member who must accept.
    pub target_user_id: UserId,
    /// Acceptance deadline.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
}

/// Result of a completed ownership transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct OwnershipTransferred {
    /// Organization.
    pub org_id: OrgId,
    /// The new owner (the caller).
    pub new_owner: UserId,
    /// The previous owner, now `admin`.
    pub previous_owner: UserId,
}

macro_rules! page_type {
    ($(#[$meta:meta])* $name:ident, $item:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
        pub struct $name {
            /// Rows of this page.
            pub items: Vec<$item>,
            /// Cursor for the next page (`?cursor=`); absent on the last page.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub next_cursor: Option<String>,
        }

        impl From<authn_core::domain::Page<$item>> for $name {
            fn from(page: authn_core::domain::Page<$item>) -> Self {
                Self {
                    items: page.items,
                    next_cursor: page.next_cursor,
                }
            }
        }
    };
}

page_type!(
    /// A page of members.
    MemberPage,
    Member
);
page_type!(
    /// A page of invitations.
    InvitationPage,
    Invitation
);
page_type!(
    /// A page of API keys.
    ApiKeyPage,
    ApiKeySummary
);
page_type!(
    /// A page of service accounts.
    ServiceAccountPage,
    ServiceAccount
);
page_type!(
    /// A page of the caller's organizations.
    MyOrganizationPage,
    MyOrganization
);
