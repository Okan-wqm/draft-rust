//! Ownership transfer with acceptance by the target (ORG-11).
//!
//! * Request: an owner (built-in role, step-up) names another **active
//!   member**; a 256-bit link token (`one_time_tokens`, purpose
//!   `org_ownership_transfer`, owned by authn-org) is e-mailed to the
//!   target. The token's `group_id` is the organization id, so a new
//!   request, a cancellation, a scheduled deletion or a completed transfer
//!   revokes every other pending transfer of the organization.
//! * Accept: only the target user, signed in with step-up, can accept;
//!   for anybody else the token is reported as invalid and is **not**
//!   consumed. Consumption is the atomic `UPDATE … RETURNING` of the token
//!   repository, inside the transaction that holds the organization lock;
//!   the initiator must still be an active owner and the target still the
//!   same active member (a membership re-created after the request does
//!   not inherit it). The target becomes `owner`, the initiator `admin`,
//!   and the initiator's organization sessions are revoked.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OneTimeTokenId, OrgId, UserId};
use authn_core::ports::{
    DomainEventKind, Notification, NotificationKind, RateLimitKey, Recipient, RevocationReason,
    SecurityEventKind,
};
use authn_core::secret::SensitiveString;
use authn_crypto::token::OpaqueToken;
use authn_store::{
    NewOneTimeToken, OneTimeTokenRepository, TokenPurpose, TokenSubject, UserRepository,
};
use serde::Deserialize;
use utoipa::ToSchema;

use super::members::lock_member_of_user;
use super::{OrgService, actions, lock_org, require_session_user};
use crate::model::{MemberStatus, OwnershipTransfer, OwnershipTransferred};
use crate::permission::{ADMIN_ROLE_ID, OWNER_ROLE_ID, Permission, is_owner_role};

/// Body of `POST /v1/orgs/{org_id}/ownership-transfer`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestOwnershipTransfer {
    /// The member who should become owner.
    pub target_user_id: UserId,
}

/// Body of `POST /v1/ownership-transfers/accept`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptOwnershipTransfer {
    /// The token from the e-mail.
    #[schema(value_type = String)]
    pub token: SensitiveString,
}

impl std::fmt::Debug for AcceptOwnershipTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptOwnershipTransfer")
            .finish_non_exhaustive()
    }
}

fn invalid_token() -> AuthError {
    AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN)
}

impl OrgService {
    /// Starts an ownership transfer (owner, step-up).
    pub async fn request_ownership_transfer(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: RequestOwnershipTransfer,
    ) -> Result<OwnershipTransfer, AuthError> {
        self.require_step_up(principal)?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::OrgTransferOwnership, org)
            .await?;
        auth.require_owner(Permission::OrgTransferOwnership)?;
        let from = auth.require_user()?;
        let target = input.target_user_id;
        let valid_target = target != from
            && lock_member_of_user(&mut tx, org, target)
                .await?
                .is_some_and(|m| m.status == MemberStatus::Active);
        if !valid_target {
            return Err(AuthError::new(codes::org::ORG_TRANSFER_TARGET_INVALID));
        }
        let email = UserRepository::find_by_id(&mut *tx, target)
            .await?
            .and_then(|u| u.email)
            .and_then(|e| authn_core::domain::EmailAddress::parse(&e).ok())
            .ok_or_else(|| AuthError::new(codes::org::ORG_TRANSFER_TARGET_INVALID))?;
        self.rate_limit(
            RateLimitKey::org(actions::OWNERSHIP_TRANSFER, org),
            self.config().ownership_transfers_per_org,
        )
        .await?;
        let now = self.now();
        let expires_at = now + self.config().ownership_transfer_ttl;
        OneTimeTokenRepository::revoke_group(&mut tx, org.as_uuid(), now).await?;
        let token = OpaqueToken::generate()?;
        let target_text = org.to_string();
        OneTimeTokenRepository::create(
            &mut tx,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: TokenPurpose::OrgOwnershipTransfer,
                token_hash: token.hash(),
                subject: TokenSubject::user(target),
                group_id: Some(org.as_uuid()),
                target: Some(&target_text),
                max_attempts: 1,
                metadata: serde_json::json!({ "org_id": org, "from_user_id": from }),
                created_ip: Some(ctx.client_ip),
                created_at: now,
                expires_at,
            },
            false,
        )
        .await?;
        let notification = Notification {
            recipient: Recipient {
                email,
                user_id: Some(target),
                display_name: None,
            },
            locale: ctx.locale,
            kind: NotificationKind::OrgOwnershipTransfer {
                org_name: auth.org_name.clone(),
                token: token.into_sensitive(),
                expires_at,
            },
        };
        self.deps()
            .notifier
            .notify_in_tx(&mut tx, notification)
            .await?;
        let event = self
            .event(
                SecurityEventKind::OrgOwnershipTransferRequested,
                ctx,
                principal,
                Some(org),
            )
            .with_subject(target)
            .with_resource("organization", org);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(OwnershipTransfer {
            org_id: org,
            target_user_id: target,
            expires_at,
        })
    }

    /// Cancels pending ownership transfers of the organization (owner).
    pub async fn cancel_ownership_transfer(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<(), AuthError> {
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::OrgTransferOwnership, org)
            .await?;
        auth.require_owner(Permission::OrgTransferOwnership)?;
        let revoked =
            OneTimeTokenRepository::revoke_group(&mut tx, org.as_uuid(), self.now()).await?;
        let event = self
            .event(
                SecurityEventKind::OrgOwnershipTransferCancelled,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("organization", org)
            .with_meta("revoked", revoked);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await
    }

    /// Accepts an ownership transfer (the target user, step-up).
    pub async fn accept_ownership_transfer(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        token: &SensitiveString,
    ) -> Result<OwnershipTransferred, AuthError> {
        let user = require_session_user(principal)?;
        principal.require_writable()?;
        self.require_step_up(principal)?;
        self.rate_limit(
            RateLimitKey::user(actions::TOKEN_ATTEMPT, user),
            self.config().token_attempts_per_user,
        )
        .await?;
        let token = OpaqueToken::parse(token.expose()).map_err(|_| invalid_token())?;
        let hash = token.hash();
        let now = self.now();
        // Look without consuming: a token presented by anybody but its
        // target must stay usable for the target.
        let record = OneTimeTokenRepository::find_active_link(
            self.pool(),
            TokenPurpose::OrgOwnershipTransfer,
            &hash,
            now,
        )
        .await?
        .filter(|r| r.user_id == Some(user))
        .ok_or_else(invalid_token)?;
        let org: OrgId = record
            .target
            .as_deref()
            .and_then(|t| t.parse().ok())
            .ok_or_else(invalid_token)?;
        let from: UserId = record
            .metadata
            .get("from_user_id")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse().ok())
            .ok_or_else(invalid_token)?;

        let mut tx = self.begin().await?;
        lock_org(&mut tx, org).await.map_err(|e| {
            if e.is(codes::common::NOT_FOUND) {
                invalid_token()
            } else {
                e
            }
        })?;
        let consumed = OneTimeTokenRepository::consume_link(
            &mut tx,
            TokenPurpose::OrgOwnershipTransfer,
            &hash,
            now,
        )
        .await?
        .filter(|r| r.id == record.id && r.user_id == Some(user))
        .ok_or_else(invalid_token)?;
        let organization = super::orgs::load_org(&mut *tx, org).await?;
        if organization.status != crate::model::OrgStatus::Active {
            return Err(invalid_token());
        }
        let initiator = lock_member_of_user(&mut tx, org, from).await?;
        let target = lock_member_of_user(&mut tx, org, user).await?;
        let (Some(initiator), Some(target)) = (initiator, target) else {
            return Err(invalid_token());
        };
        if !initiator.is_active_owner()
            || target.status != MemberStatus::Active
            || target.created_at > consumed.created_at
        {
            return Err(invalid_token());
        }
        sqlx::query("UPDATE memberships SET role_id = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(user)
            .bind(OWNER_ROLE_ID)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE memberships SET role_id = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(from)
            .bind(ADMIN_ROLE_ID)
            .execute(&mut *tx)
            .await?;
        self.deps()
            .session_revoker
            .revoke_for_user_in_org(&mut tx, from, org, RevocationReason::MembershipChanged)
            .await?;
        for (member, role) in [(user, OWNER_ROLE_ID), (from, ADMIN_ROLE_ID)] {
            self.publish(
                &mut tx,
                DomainEventKind::MemberRoleChanged,
                org,
                Some(member),
                serde_json::json!({ "org_id": org, "user_id": member, "role_id": role }),
            )
            .await?;
        }
        let event = self
            .event(
                SecurityEventKind::OrgOwnershipTransferred,
                ctx,
                principal,
                Some(org),
            )
            .with_subject(user)
            .with_resource("organization", org)
            .with_meta("previous_owner", from.to_string())
            .with_meta("previous_owner_was_owner", is_owner_role(initiator.role_id));
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(OwnershipTransferred {
            org_id: org,
            new_owner: user,
            previous_owner: from,
        })
    }
}
