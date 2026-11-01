//! API keys (ORG-08) and their authentication.
//!
//! * Format, checksum and storage hash: [`crate::api_key`]. The key text is
//!   returned once (creation / rotation response); only SHA-256 is stored.
//! * Owner: a service account of the organization (ORG-09) or the creating
//!   member (personal key; deleted with the membership). Scopes are catalog
//!   permissions; the key's effective rights are the owner's **current**
//!   role permissions intersected with the scopes, re-evaluated on every
//!   request. Owner-only permissions can never be scopes.
//! * Escalation guard: the creator must hold every scope; rotating requires
//!   holding every scope too, and personal keys can only be rotated by
//!   their owner (otherwise an administrator could mint a credential that
//!   acts as another user).
//! * Expiry is mandatory and bounded (`org.api_keys.max_lifetime`).
//! * Creation and rotation require step-up — an API key can never create or
//!   rotate keys.
//! * Rotation: a new key, the old one stays valid for a short grace period
//!   (`org.api_keys.rotation_grace`, shortenable per call); revoking the new
//!   key also revokes every predecessor of its rotation chain.
//! * [`OrgService::authenticate_api_key`]: format + checksum + environment
//!   are checked without database work; one indexed lookup; the stored hash
//!   is compared again in constant time; every failure is the same
//!   `401 unauthenticated`. Failures with well-formed keys are
//!   rate-limited per IP and audited (bounded by that limit).
//!   `last_used_at` / `last_used_ip` are written at most once per
//!   `last_used_update_interval` per key.

use std::collections::BTreeSet;
use std::net::IpAddr;

use authn_core::domain::{
    AccountStatus, Page, PageRequest, Principal, PrincipalCredential, Subject,
};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{ApiKeyId, OrgId, ServiceAccountId, UserId};
use authn_core::ports::{Actor, DomainEventKind, RateLimitKey, SecurityEvent, SecurityEventKind};
use authn_core::secret::constant_time_eq;
use authn_crypto::token::TokenHash;
use authn_store::UserRepository;
use ipnet::IpNet;
use serde::Deserialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::{OrgService, actions, cursor_of, fetch_limit, page_after};
use crate::api_key::{GeneratedApiKey, parse_api_key};
use crate::model::{
    ApiKeyOwner, ApiKeyPage, ApiKeyState, ApiKeySummary, CreatedApiKey, MemberStatus, OrgStatus,
    ServiceAccountStatus,
};
use crate::permission::{Permission, PermissionSet};
use crate::policy::canonical_ip;
use crate::validate;

/// Most scopes on one key (matches the `api_keys_scope_check` constraint).
pub const MAX_SCOPES: usize = 64;
/// Minimum remaining lifetime of a new key.
const MIN_LIFETIME: time::Duration = time::Duration::minutes(5);

/// Body of `POST /v1/orgs/{org_id}/api-keys`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKey {
    /// Name (1–100 characters).
    pub name: String,
    /// Catalog permissions granted to the key (at least one).
    pub scopes: Vec<String>,
    /// Expiry (RFC 3339); default `now + org.api_keys.default_lifetime`,
    /// at most `now + org.api_keys.max_lifetime`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<OffsetDateTime>,
    /// Service account the key belongs to; omit for a personal key of the
    /// caller.
    pub service_account_id: Option<ServiceAccountId>,
}

/// Body of `POST /v1/orgs/{org_id}/api-keys/{key_id}/rotate` (optional).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RotateApiKey {
    /// Expiry of the new key (same rules as creation).
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<OffsetDateTime>,
    /// How long the old key keeps working, in seconds (0 = immediately
    /// revoked; capped by `org.api_keys.rotation_grace`).
    pub grace_period_seconds: Option<u64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct KeyRow {
    id: ApiKeyId,
    service_account_id: Option<ServiceAccountId>,
    user_id: Option<UserId>,
    name: String,
    environment: String,
    display_prefix: String,
    scopes: Vec<String>,
    created_by: Option<UserId>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    last_used_ip: Option<IpNet>,
    revoked_at: Option<OffsetDateTime>,
    revoked_reason: Option<String>,
    rotated_from_id: Option<ApiKeyId>,
    rotation_grace_until: Option<OffsetDateTime>,
}

macro_rules! key_columns {
    () => {
        "id, org_id, service_account_id, user_id, name, environment, display_prefix, scopes, \
         created_by, created_at, expires_at, last_used_at, last_used_ip, revoked_at, \
         revoked_reason, rotated_from_id, rotation_grace_until"
    };
}

impl KeyRow {
    fn state(&self, now: OffsetDateTime) -> ApiKeyState {
        if self.revoked_at.is_some() {
            ApiKeyState::Revoked
        } else if self.expires_at <= now {
            ApiKeyState::Expired
        } else {
            match self.rotation_grace_until {
                Some(until) if until <= now => ApiKeyState::Revoked,
                Some(_) => ApiKeyState::Rotating,
                None => ApiKeyState::Active,
            }
        }
    }

    fn owner(&self) -> Result<ApiKeyOwner, AuthError> {
        match (self.service_account_id, self.user_id) {
            (Some(service_account_id), None) => {
                Ok(ApiKeyOwner::ServiceAccount { service_account_id })
            }
            (None, Some(user_id)) => Ok(ApiKeyOwner::User { user_id }),
            _ => Err(AuthError::internal("api key without a single owner")),
        }
    }

    fn summary(self, now: OffsetDateTime) -> Result<ApiKeySummary, AuthError> {
        let state = self.state(now);
        let owner = self.owner()?;
        Ok(ApiKeySummary {
            id: self.id,
            name: self.name,
            display_prefix: self.display_prefix,
            environment: self.environment,
            scopes: PermissionSet::from_db(&self.scopes).iter().collect(),
            owner,
            state,
            created_by: self.created_by,
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            last_used_ip: self.last_used_ip.map(|n| n.addr()),
            revoked_at: self.revoked_at,
            revoked_reason: self.revoked_reason,
            rotated_from_id: self.rotated_from_id,
            rotation_grace_until: self.rotation_grace_until,
        })
    }
}

/// Lookup row of [`OrgService::authenticate_api_key`].
#[derive(sqlx::FromRow)]
struct AuthRow {
    id: ApiKeyId,
    org_id: OrgId,
    service_account_id: Option<ServiceAccountId>,
    user_id: Option<UserId>,
    secret_hash: Vec<u8>,
    scopes: Vec<String>,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    rotation_grace_until: Option<OffsetDateTime>,
    org_status: OrgStatus,
    sa_status: Option<ServiceAccountStatus>,
    member_status: Option<MemberStatus>,
    ip_allowlist: Option<Vec<IpNet>>,
}

/// Why an authentication with a well-formed key failed (audit reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailure {
    Unknown,
    Revoked,
    Expired,
    OwnerInactive,
    OrgInactive,
    IpNotAllowed,
}

impl AuthFailure {
    const fn reason(self) -> &'static str {
        match self {
            Self::Unknown => "unknown_key",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::OwnerInactive => "owner_inactive",
            Self::OrgInactive => "org_inactive",
            Self::IpNotAllowed => "ip_not_allowed",
        }
    }
}

fn unauthenticated() -> AuthError {
    AuthError::new(codes::common::UNAUTHENTICATED)
}

impl OrgService {
    /// Creates an API key (`api_keys:manage` + step-up). The key is in the
    /// response only.
    pub async fn create_api_key(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: CreateApiKey,
    ) -> Result<CreatedApiKey, AuthError> {
        self.require_step_up(principal)?;
        let name = validate::display_text(&input.name, validate::MAX_RESOURCE_NAME_CHARS, "name")?;
        let scopes = parse_scopes(&input.scopes)?;
        let now = self.now();
        let expires_at = self.expiry(input.expires_at, now)?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::ApiKeysManage, org)
            .await?;
        if !auth.permissions.is_superset(&scopes) {
            return Err(AuthError::new(codes::org::ORG_ROLE_ESCALATION)
                .with_context("api key scope the actor lacks"));
        }
        let (service_account, user) = match input.service_account_id {
            Some(sa) => {
                let (status, role_permissions) = service_account_for_key(&mut tx, org, sa).await?;
                if status != ServiceAccountStatus::Active {
                    return Err(AuthError::new(codes::org::SERVICE_ACCOUNT_DISABLED));
                }
                if !role_permissions.is_superset(&scopes) {
                    return Err(AuthError::new(codes::org::API_KEY_SCOPE_INVALID)
                        .with_context("scope outside the service account role"));
                }
                (Some(sa), None)
            }
            None => (None, Some(auth.require_user()?)),
        };
        self.ensure_key_capacity(&mut tx, org, now).await?;
        let created = self
            .insert_key(
                &mut tx,
                NewKey {
                    org,
                    service_account,
                    user,
                    name: &name,
                    scopes: &scopes,
                    created_by: auth.user_id(),
                    now,
                    expires_at,
                    rotated_from: None,
                },
            )
            .await?;
        self.publish(
            &mut tx,
            DomainEventKind::ApiKeyCreated,
            org,
            user,
            serde_json::json!({ "org_id": org, "api_key_id": created.api_key.id }),
        )
        .await?;
        let event = self
            .event(SecurityEventKind::ApiKeyCreated, ctx, principal, Some(org))
            .with_resource("api_key", created.api_key.id)
            .with_meta("scopes", scopes.to_strings())
            .with_meta("expires_at", expires_at.unix_timestamp());
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        crate::metrics::api_key_created();
        Ok(created)
    }

    /// Lists the organization's API keys (`api_keys:read`), oldest first.
    pub async fn list_api_keys(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        page: &PageRequest,
    ) -> Result<ApiKeyPage, AuthError> {
        self.authorize(ctx, principal, Permission::ApiKeysRead, org)
            .await?;
        let (after_at, after_id) = page_after(page)?;
        let sql = concat!(
            "SELECT ",
            key_columns!(),
            " FROM api_keys WHERE org_id = $1 \
             AND ($2::timestamptz IS NULL OR (created_at, id) > ($2, $3)) \
             ORDER BY created_at, id LIMIT $4"
        );
        let rows = sqlx::query_as::<_, KeyRow>(sql)
            .bind(org)
            .bind(after_at)
            .bind(after_id)
            .bind(fetch_limit(page))
            .fetch_all(self.pool())
            .await?;
        let now = self.now();
        let page = Page::from_overfetch(rows, page.limit(), |r| {
            cursor_of(r.created_at, r.id.as_uuid())
        });
        let items = page
            .items
            .into_iter()
            .map(|r| r.summary(now))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ApiKeyPage {
            items,
            next_cursor: page.next_cursor,
        })
    }

    /// Reads one API key's metadata (`api_keys:read`).
    pub async fn get_api_key(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        key: ApiKeyId,
    ) -> Result<ApiKeySummary, AuthError> {
        self.authorize(ctx, principal, Permission::ApiKeysRead, org)
            .await?;
        let sql = concat!(
            "SELECT ",
            key_columns!(),
            " FROM api_keys WHERE org_id = $1 AND id = $2"
        );
        sqlx::query_as::<_, KeyRow>(sql)
            .bind(org)
            .bind(key)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?
            .summary(self.now())
    }

    /// Revokes a key (`api_keys:manage`; idempotent). Every key this one
    /// (directly or transitively) replaced and that is still in its rotation
    /// grace period is revoked too.
    pub async fn revoke_api_key(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        key: ApiKeyId,
    ) -> Result<ApiKeySummary, AuthError> {
        let (mut tx, _auth) = self
            .begin_write(ctx, principal, Permission::ApiKeysManage, org)
            .await?;
        let row = lock_key(&mut tx, org, key).await?;
        let now = self.now();
        if row.revoked_at.is_none() {
            // The key and its whole rotation ancestry (A → B → C: revoking
            // C also ends A and B if they are still in their grace period).
            sqlx::query(
                "WITH RECURSIVE chain (id) AS ( \
                     SELECT id FROM api_keys WHERE org_id = $1 AND id = $2 \
                     UNION \
                     SELECT k.rotated_from_id FROM api_keys k JOIN chain c ON k.id = c.id \
                     WHERE k.org_id = $1 AND k.rotated_from_id IS NOT NULL) \
                 UPDATE api_keys SET revoked_at = $3, revoked_reason = 'revoked' \
                 WHERE org_id = $1 AND revoked_at IS NULL AND id IN (SELECT id FROM chain)",
            )
            .bind(org)
            .bind(key)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            self.publish(
                &mut tx,
                DomainEventKind::ApiKeyRevoked,
                org,
                row.user_id,
                serde_json::json!({ "org_id": org, "api_key_id": key }),
            )
            .await?;
            let event = self
                .event(SecurityEventKind::ApiKeyRevoked, ctx, principal, Some(org))
                .with_resource("api_key", key);
            self.audit_in_tx(&mut tx, event).await?;
        }
        let updated = lock_key(&mut tx, org, key).await?;
        authn_store::commit(tx).await?;
        updated.summary(now)
    }

    /// Rotates a key (`api_keys:manage` + step-up): a new key with the same
    /// name, owner and scopes; the old key works until the grace period
    /// ends.
    pub async fn rotate_api_key(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        key: ApiKeyId,
        input: RotateApiKey,
    ) -> Result<CreatedApiKey, AuthError> {
        self.require_step_up(principal)?;
        let now = self.now();
        let expires_at = self.expiry(input.expires_at, now)?;
        let max_grace = self.config().api_keys.rotation_grace;
        let grace = input.grace_period_seconds.map_or(max_grace, |s| {
            std::time::Duration::from_secs(s).min(max_grace)
        });
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::ApiKeysManage, org)
            .await?;
        let old = lock_key(&mut tx, org, key).await?;
        if old.state(now) != ApiKeyState::Active {
            return Err(AuthError::new(codes::org::API_KEY_INACTIVE));
        }
        let scopes = PermissionSet::from_db(&old.scopes);
        if !auth.permissions.is_superset(&scopes) {
            return Err(AuthError::new(codes::org::ORG_ROLE_ESCALATION)
                .with_context("rotating a key with scopes the actor lacks"));
        }
        match old.owner()? {
            ApiKeyOwner::User { user_id } => {
                if auth.user_id() != Some(user_id) {
                    return Err(AuthError::new(codes::org::ORG_ROLE_ESCALATION)
                        .with_context("personal keys are rotated by their owner only"));
                }
            }
            ApiKeyOwner::ServiceAccount { service_account_id } => {
                let (status, _) = service_account_for_key(&mut tx, org, service_account_id).await?;
                if status != ServiceAccountStatus::Active {
                    return Err(AuthError::new(codes::org::SERVICE_ACCOUNT_DISABLED));
                }
            }
        }
        let grace_until = now + grace;
        if grace.is_zero() {
            sqlx::query(
                "UPDATE api_keys SET revoked_at = $3, revoked_reason = 'rotated' \
                 WHERE org_id = $1 AND id = $2",
            )
            .bind(org)
            .bind(key)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE api_keys SET rotation_grace_until = $3 WHERE org_id = $1 AND id = $2",
            )
            .bind(org)
            .bind(key)
            .bind(grace_until)
            .execute(&mut *tx)
            .await?;
        }
        let created = self
            .insert_key(
                &mut tx,
                NewKey {
                    org,
                    service_account: old.service_account_id,
                    user: old.user_id,
                    name: &old.name,
                    scopes: &scopes,
                    created_by: auth.user_id(),
                    now,
                    expires_at,
                    rotated_from: Some(key),
                },
            )
            .await?;
        let event = self
            .event(SecurityEventKind::ApiKeyRotated, ctx, principal, Some(org))
            .with_resource("api_key", created.api_key.id)
            .with_meta("rotated_from", key.to_string())
            .with_meta("grace_seconds", grace.as_secs());
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(created)
    }

    /// Authenticates a presented API key and returns the principal it acts
    /// as (for the server / session middleware). Every failure is
    /// `401 unauthenticated`, except `429` once a client IP has failed too
    /// often with well-formed keys.
    pub async fn authenticate_api_key(
        &self,
        ctx: &RequestContext,
        raw: &str,
    ) -> Result<Principal, AuthError> {
        let Ok(parsed) = parse_api_key(raw) else {
            crate::metrics::api_key_auth("malformed");
            return Err(unauthenticated());
        };
        if parsed.environment() != self.config().api_keys.environment {
            crate::metrics::api_key_auth("wrong_environment");
            return Err(unauthenticated());
        }
        let hash = parsed.hash();
        match self.check_key(ctx, &hash).await? {
            Ok(principal) => {
                crate::metrics::api_key_auth("success");
                Ok(principal)
            }
            Err((failure, key)) => {
                crate::metrics::api_key_auth(failure.reason());
                self.rate_limit(
                    RateLimitKey::ip(actions::API_KEY_AUTH_FAILURE, ctx.client_ip),
                    self.config().api_keys.auth_failures_per_ip,
                )
                .await?;
                let mut event = SecurityEvent::new(SecurityEventKind::ApiKeyAuthFailed, self.now())
                    .with_context(ctx)
                    .with_actor(Actor::Anonymous)
                    .failed(failure.reason());
                if let Some((key, org)) = key {
                    event = event.with_resource("api_key", key).with_org(org);
                }
                if let Err(err) = self.deps().audit.record(event).await {
                    tracing::warn!(error = %err, "recording api key authentication failure failed");
                }
                Err(unauthenticated())
            }
        }
    }

    async fn check_key(
        &self,
        ctx: &RequestContext,
        hash: &TokenHash,
    ) -> Result<Result<Principal, (AuthFailure, Option<(ApiKeyId, OrgId)>)>, AuthError> {
        let row = sqlx::query_as::<_, AuthRow>(
            "SELECT k.id, k.org_id, k.service_account_id, k.user_id, k.secret_hash, k.scopes, \
             k.expires_at, k.revoked_at, k.rotation_grace_until, o.status AS org_status, \
             sa.status AS sa_status, m.status AS member_status, p.ip_allowlist \
             FROM api_keys k JOIN organizations o ON o.id = k.org_id \
             LEFT JOIN service_accounts sa ON sa.id = k.service_account_id AND sa.org_id = k.org_id \
             LEFT JOIN memberships m ON m.org_id = k.org_id AND m.user_id = k.user_id \
             LEFT JOIN org_policies p ON p.org_id = k.org_id \
             WHERE k.secret_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Ok(Err((AuthFailure::Unknown, None)));
        };
        let ids = Some((row.id, row.org_id));
        // Defence in depth: the database matched on the hash; compare again
        // in constant time.
        if !constant_time_eq(&row.secret_hash, hash.as_bytes()) {
            return Ok(Err((AuthFailure::Unknown, None)));
        }
        let now = self.now();
        if row.revoked_at.is_some() || row.rotation_grace_until.is_some_and(|t| t <= now) {
            return Ok(Err((AuthFailure::Revoked, ids)));
        }
        if row.expires_at <= now {
            return Ok(Err((AuthFailure::Expired, ids)));
        }
        if row.org_status != OrgStatus::Active {
            return Ok(Err((AuthFailure::OrgInactive, ids)));
        }
        if let Some(list) = &row.ip_allowlist {
            let ip = canonical_ip(ctx.client_ip);
            if !list.iter().any(|net| net.contains(&ip)) {
                return Ok(Err((AuthFailure::IpNotAllowed, ids)));
            }
        }
        let subject = match (row.service_account_id, row.user_id) {
            (Some(service_account_id), None) => {
                if row.sa_status != Some(ServiceAccountStatus::Active) {
                    return Ok(Err((AuthFailure::OwnerInactive, ids)));
                }
                Subject::ServiceAccount {
                    service_account_id,
                    org_id: row.org_id,
                }
            }
            (None, Some(user_id)) => {
                if row.member_status != Some(MemberStatus::Active) {
                    return Ok(Err((AuthFailure::OwnerInactive, ids)));
                }
                let active = UserRepository::find_by_id(self.pool(), user_id)
                    .await?
                    .is_some_and(|u| u.status == AccountStatus::Active);
                if !active {
                    return Ok(Err((AuthFailure::OwnerInactive, ids)));
                }
                Subject::User { user_id }
            }
            _ => return Ok(Err((AuthFailure::OwnerInactive, ids))),
        };
        self.touch_last_used(row.id, ctx.client_ip, now).await;
        Ok(Ok(Principal {
            subject,
            credential: PrincipalCredential::ApiKey { api_key_id: row.id },
            active_org: Some(row.org_id),
            amr: Vec::new(),
            acr: None,
            auth_time: None,
            scopes: PermissionSet::from_db(&row.scopes)
                .to_strings()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            impersonation: None,
            is_platform_admin: false,
        }))
    }

    /// Throttled `last_used_*` update (a single conditional statement; a
    /// failure is logged, never fails the request).
    async fn touch_last_used(&self, key: ApiKeyId, ip: IpAddr, now: OffsetDateTime) {
        let interval = self.config().api_keys.last_used_update_interval;
        let threshold = now - interval;
        let net = IpNet::from(canonical_ip(ip));
        let result = sqlx::query(
            "UPDATE api_keys SET last_used_at = $2, last_used_ip = $3 \
             WHERE id = $1 AND (last_used_at IS NULL OR last_used_at <= $4)",
        )
        .bind(key)
        .bind(now)
        .bind(net)
        .bind(threshold)
        .execute(self.pool())
        .await;
        if let Err(err) = result {
            tracing::warn!(error = %err, "updating api key last use failed");
        }
    }

    fn expiry(
        &self,
        requested: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, AuthError> {
        let config = &self.config().api_keys;
        let max = now + config.max_lifetime;
        let expires_at = requested.unwrap_or(now + config.default_lifetime);
        if expires_at < now + MIN_LIFETIME || expires_at > max {
            return Err(AuthError::new(codes::org::API_KEY_EXPIRY_INVALID));
        }
        Ok(expires_at)
    }

    async fn ensure_key_capacity(
        &self,
        conn: &mut PgConnection,
        org: OrgId,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM api_keys WHERE org_id = $1 AND revoked_at IS NULL \
             AND expires_at > $2 AND (rotation_grace_until IS NULL OR rotation_grace_until > $2)",
        )
        .bind(org)
        .bind(now)
        .fetch_one(conn)
        .await?;
        if active >= i64::from(self.config().limits.api_keys) {
            Err(AuthError::new(codes::org::ORG_LIMIT_REACHED))
        } else {
            Ok(())
        }
    }

    async fn insert_key(
        &self,
        conn: &mut PgConnection,
        new: NewKey<'_>,
    ) -> Result<CreatedApiKey, AuthError> {
        let environment = self.config().api_keys.environment.clone();
        let generated = GeneratedApiKey::generate(&environment)
            .map_err(|e| AuthError::internal("api key generation failed").with_source(e))?;
        let id = ApiKeyId::generate();
        let sql = concat!(
            "INSERT INTO api_keys (id, org_id, service_account_id, user_id, name, environment, \
             display_prefix, secret_hash, scopes, created_by, created_at, expires_at, \
             rotated_from_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             RETURNING ",
            key_columns!()
        );
        let row = sqlx::query_as::<_, KeyRow>(sql)
            .bind(id)
            .bind(new.org)
            .bind(new.service_account)
            .bind(new.user)
            .bind(new.name)
            .bind(&environment)
            .bind(generated.display_prefix())
            .bind(generated.hash().as_bytes().as_slice())
            .bind(new.scopes.to_strings())
            .bind(new.created_by)
            .bind(new.now)
            .bind(new.expires_at)
            .bind(new.rotated_from)
            .fetch_one(conn)
            .await?;
        Ok(CreatedApiKey {
            api_key: row.summary(new.now)?,
            key: generated.into_sensitive(),
        })
    }
}

struct NewKey<'a> {
    org: OrgId,
    service_account: Option<ServiceAccountId>,
    user: Option<UserId>,
    name: &'a str,
    scopes: &'a PermissionSet,
    created_by: Option<UserId>,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
    rotated_from: Option<ApiKeyId>,
}

/// Parses scopes: 1–64 catalog permissions, never owner-only ones.
pub(crate) fn parse_scopes(values: &[String]) -> Result<PermissionSet, AuthError> {
    if values.is_empty() || values.len() > MAX_SCOPES {
        return Err(AuthError::new(codes::org::API_KEY_SCOPE_INVALID));
    }
    let mut set = BTreeSet::new();
    for value in values {
        let permission = Permission::from_catalog(value)
            .filter(|p| !p.is_owner_only())
            .ok_or_else(|| AuthError::new(codes::org::API_KEY_SCOPE_INVALID))?;
        set.insert(permission);
    }
    Ok(set.into_iter().collect())
}

async fn lock_key(conn: &mut PgConnection, org: OrgId, key: ApiKeyId) -> Result<KeyRow, AuthError> {
    let sql = concat!(
        "SELECT ",
        key_columns!(),
        " FROM api_keys WHERE org_id = $1 AND id = $2 FOR UPDATE"
    );
    sqlx::query_as::<_, KeyRow>(sql)
        .bind(org)
        .bind(key)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}

/// Status and role permissions of a service account of `org` (`404` for
/// other organizations).
async fn service_account_for_key(
    conn: &mut PgConnection,
    org: OrgId,
    sa: ServiceAccountId,
) -> Result<(ServiceAccountStatus, PermissionSet), AuthError> {
    let row: Option<(ServiceAccountStatus, Vec<String>)> = sqlx::query_as(
        "SELECT sa.status, ARRAY(SELECT rp.permission FROM role_permissions rp \
         WHERE rp.role_id = sa.role_id) FROM service_accounts sa \
         WHERE sa.org_id = $1 AND sa.id = $2 FOR SHARE",
    )
    .bind(org)
    .bind(sa)
    .fetch_optional(conn)
    .await?;
    let (status, permissions) = row.ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
    Ok((status, PermissionSet::from_db(&permissions)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_08_scopes_are_catalog_permissions_without_owner_only() {
        let set = parse_scopes(&["members:read".into(), "members:read".into()]).unwrap();
        assert_eq!(set.len(), 1);
        for bad in [
            vec![],
            vec!["org:delete".to_owned()],
            vec!["org:transfer_ownership".to_owned()],
            vec!["tokens:everything".to_owned()],
            vec!["members:read".to_owned(); 65],
        ] {
            assert_eq!(
                parse_scopes(&bad).unwrap_err().code(),
                codes::org::API_KEY_SCOPE_INVALID,
                "{bad:?}"
            );
        }
    }
}
