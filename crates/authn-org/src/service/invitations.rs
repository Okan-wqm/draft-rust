//! Invitations (ORG-05).
//!
//! * Token: 256-bit CSPRNG ([`OpaqueToken`]); only its SHA-256 is stored;
//!   it travels only inside the invitation e-mail (outbox, sealed). A
//!   resend issues a **new** token and invalidates the old one.
//! * Bound to the invited address: the accepting account's address must be
//!   verified and equal to the invited one (normalized). Unknown, used,
//!   revoked and expired tokens are indistinguishable
//!   (`invalid_or_expired_token`).
//! * Acceptance is atomic: the invitation row is locked and switched from
//!   `pending` in the same transaction that creates the membership, so a
//!   token can be used once, even by concurrent requests.
//! * Escalation guard: inviting (and re-sending) with a role requires
//!   holding all of its permissions; only owners invite owners, with
//!   step-up (like granting `owner` directly).
//! * Abuse: sends are rate-limited per organization, per organization and
//!   recipient address (revoke / re-invite cycles cannot bomb a mailbox) and
//!   per invitation (cooldown); pending invitations per organization are
//!   capped; preview / accept attempts are rate-limited per user.

use authn_core::domain::{EmailAddress, Locale, Page, PageRequest, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{InvitationId, OrgId, RoleId, UserId};
use authn_core::ports::{
    DomainEventKind, Notification, NotificationKind, RateLimitKey, RateLimitPolicy, Recipient,
    SecurityEventKind,
};
use authn_core::redact::mask_email;
use authn_core::secret::SensitiveString;
use authn_crypto::token::OpaqueToken;
use authn_store::UserRepository;
use serde::Deserialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::orgs::insert_membership;
use super::roles::load_role;
use super::{
    OrgService, actions, cursor_of, fetch_limit, lock_org, on_unique, page_after,
    require_session_user,
};
use crate::model::{
    Invitation, InvitationPage, InvitationPreview, InvitationStatus, MemberStatus, MyOrganization,
    OrgStatus, RoleRef,
};
use crate::permission::{Permission, is_owner_role};
use crate::validate;

/// Body of `POST /v1/orgs/{org_id}/invitations`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateInvitation {
    /// Address to invite.
    pub email: String,
    /// Role granted on acceptance.
    pub role_id: RoleId,
}

/// Body of `POST /v1/invitations/preview` and `/v1/invitations/accept`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InvitationToken {
    /// The token from the invitation e-mail.
    #[schema(value_type = String)]
    pub token: SensitiveString,
}

impl std::fmt::Debug for InvitationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationToken").finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: InvitationId,
    org_id: OrgId,
    email: String,
    email_normalized: String,
    status: InvitationStatus,
    invited_by: Option<UserId>,
    send_count: i32,
    last_sent_at: OffsetDateTime,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    accepted_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    role_id: RoleId,
    role_key: String,
    role_name: String,
}

impl InvitationRow {
    fn into_invitation(self, now: OffsetDateTime) -> Invitation {
        let status = if self.status == InvitationStatus::Pending && self.expires_at <= now {
            InvitationStatus::Expired
        } else {
            self.status
        };
        Invitation {
            id: self.id,
            email: self.email,
            role: RoleRef {
                id: self.role_id,
                key: self.role_key,
                name: self.role_name,
            },
            status,
            invited_by: self.invited_by,
            send_count: self.send_count,
            last_sent_at: self.last_sent_at,
            created_at: self.created_at,
            expires_at: self.expires_at,
            accepted_at: self.accepted_at,
            revoked_at: self.revoked_at,
        }
    }

    fn is_usable(&self, now: OffsetDateTime) -> bool {
        self.status == InvitationStatus::Pending && self.expires_at > now
    }
}

macro_rules! invitation_select {
    () => {
        "SELECT i.id, i.org_id, i.email, i.email_normalized, i.status, i.invited_by, \
         i.send_count, i.last_sent_at, i.created_at, i.expires_at, i.accepted_at, i.revoked_at, \
         r.id AS role_id, r.key AS role_key, r.name AS role_name \
         FROM invitations i JOIN roles r ON r.id = i.role_id "
    };
}

fn invalid_token() -> AuthError {
    AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN)
}

impl OrgService {
    /// Invites an address (`members:invite`).
    pub async fn create_invitation(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: CreateInvitation,
    ) -> Result<Invitation, AuthError> {
        let email = EmailAddress::parse(&input.email).map_err(|_| validate::invalid("email"))?;
        if is_owner_role(input.role_id) {
            // Granting `owner` needs step-up on every path (ORG-04), not
            // only on a direct role change.
            self.require_step_up(principal)?;
        }
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::MembersInvite, org)
            .await?;
        let role = load_role(&mut tx, org, input.role_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        auth.ensure_can_grant(role.id, &role.permission_set())?;
        if let Some(existing) = UserRepository::find_by_email(&mut *tx, &email).await? {
            let member: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2)",
            )
            .bind(org)
            .bind(existing.id)
            .fetch_one(&mut *tx)
            .await?;
            if member {
                return Err(AuthError::new(codes::org::ORG_ALREADY_MEMBER));
            }
        }
        let now = self.now();
        // A pending invitation past its expiry no longer blocks a new one.
        sqlx::query(
            "UPDATE invitations SET status = 'expired' WHERE org_id = $1 \
             AND email_normalized = $2 AND status = 'pending' AND expires_at <= $3",
        )
        .bind(org)
        .bind(email.normalized())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invitations WHERE org_id = $1 AND status = 'pending'",
        )
        .bind(org)
        .fetch_one(&mut *tx)
        .await?;
        if pending >= i64::from(self.config().limits.pending_invitations) {
            return Err(AuthError::new(codes::org::ORG_LIMIT_REACHED));
        }
        self.recipient_budget(org, &email).await?;
        self.rate_limit(
            RateLimitKey::org(actions::INVITATION_SEND, org),
            self.config().invitation_sends_per_org,
        )
        .await?;
        let token = OpaqueToken::generate()?;
        let id = InvitationId::generate();
        let expires_at = now + self.config().invitation_ttl;
        sqlx::query(
            "INSERT INTO invitations (id, org_id, email, email_normalized, role_id, token_hash, \
             status, invited_by, send_count, last_sent_at, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, 1, $8, $8, $9)",
        )
        .bind(id)
        .bind(org)
        .bind(email.as_str())
        .bind(email.normalized())
        .bind(role.id)
        .bind(token.hash().as_bytes().as_slice())
        .bind(auth.user_id())
        .bind(now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            on_unique(
                e,
                "invitations_one_pending_idx",
                codes::org::ORG_INVITATION_PENDING,
            )
        })?;
        self.send_invitation(
            &mut tx,
            ctx.locale,
            &email,
            &auth.org_name,
            token,
            expires_at,
        )
        .await?;
        self.publish(
            &mut tx,
            DomainEventKind::InvitationCreated,
            org,
            None,
            serde_json::json!({ "org_id": org, "invitation_id": id, "role_id": role.id }),
        )
        .await?;
        let event = self
            .event(
                SecurityEventKind::InvitationCreated,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("invitation", id)
            .with_meta("role", role.key.clone());
        self.audit_in_tx(&mut tx, event).await?;
        let invitation = load_invitation(&mut tx, org, id).await?;
        authn_store::commit(tx).await?;
        Ok(invitation.into_invitation(now))
    }

    /// Lists invitations (`members:invite`: the list contains addresses).
    pub async fn list_invitations(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        page: &PageRequest,
    ) -> Result<InvitationPage, AuthError> {
        self.authorize(ctx, principal, Permission::MembersInvite, org)
            .await?;
        let (after_at, after_id) = page_after(page)?;
        let sql = concat!(
            invitation_select!(),
            "WHERE i.org_id = $1 AND ($2::timestamptz IS NULL OR (i.created_at, i.id) > ($2, $3)) \
             ORDER BY i.created_at, i.id LIMIT $4"
        );
        let rows = sqlx::query_as::<_, InvitationRow>(sql)
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
        Ok(InvitationPage {
            items: page
                .items
                .into_iter()
                .map(|r| r.into_invitation(now))
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    /// Re-sends a pending invitation with a **new** token and a new expiry
    /// (`members:invite`, cooldown per invitation, budget per organization).
    pub async fn resend_invitation(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        invitation: InvitationId,
    ) -> Result<Invitation, AuthError> {
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::MembersInvite, org)
            .await?;
        let row = lock_invitation(&mut tx, org, invitation).await?;
        if row.status != InvitationStatus::Pending {
            return Err(
                AuthError::new(codes::common::CONFLICT).with_context("invitation is not pending")
            );
        }
        let role = load_role(&mut tx, org, row.role_id)
            .await?
            .ok_or_else(|| AuthError::internal("invitation role missing"))?;
        if is_owner_role(role.id) {
            self.require_step_up(principal)?;
        }
        auth.ensure_can_grant(role.id, &role.permission_set())?;
        let cooldown = self.config().invitation_resend_cooldown;
        if !cooldown.is_zero() {
            self.rate_limit(
                RateLimitKey::account(actions::INVITATION_RESEND, &invitation.to_string()),
                RateLimitPolicy::new(1, cooldown),
            )
            .await?;
        }
        let email = EmailAddress::parse(&row.email)
            .map_err(|_| AuthError::internal("stored invitation address is invalid"))?;
        self.recipient_budget(org, &email).await?;
        self.rate_limit(
            RateLimitKey::org(actions::INVITATION_SEND, org),
            self.config().invitation_sends_per_org,
        )
        .await?;
        let now = self.now();
        let token = OpaqueToken::generate()?;
        let expires_at = now + self.config().invitation_ttl;
        sqlx::query(
            "UPDATE invitations SET token_hash = $3, send_count = send_count + 1, \
             last_sent_at = $4, expires_at = $5 WHERE id = $1 AND org_id = $2",
        )
        .bind(invitation)
        .bind(org)
        .bind(token.hash().as_bytes().as_slice())
        .bind(now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        self.send_invitation(
            &mut tx,
            ctx.locale,
            &email,
            &auth.org_name,
            token,
            expires_at,
        )
        .await?;
        let event = self
            .event(
                SecurityEventKind::InvitationCreated,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("invitation", invitation)
            .with_meta("resend", true);
        self.audit_in_tx(&mut tx, event).await?;
        let updated = load_invitation(&mut tx, org, invitation).await?;
        authn_store::commit(tx).await?;
        Ok(updated.into_invitation(now))
    }

    /// Revokes a pending invitation (`members:invite`).
    pub async fn revoke_invitation(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        invitation: InvitationId,
    ) -> Result<(), AuthError> {
        let (mut tx, _auth) = self
            .begin_write(ctx, principal, Permission::MembersInvite, org)
            .await?;
        let row = lock_invitation(&mut tx, org, invitation).await?;
        if row.status != InvitationStatus::Pending {
            return Err(
                AuthError::new(codes::common::CONFLICT).with_context("invitation is not pending")
            );
        }
        sqlx::query(
            "UPDATE invitations SET status = 'revoked', revoked_at = $3 WHERE id = $1 AND org_id = $2",
        )
        .bind(invitation)
        .bind(org)
        .bind(self.now())
        .execute(&mut *tx)
        .await?;
        self.publish(
            &mut tx,
            DomainEventKind::InvitationRevoked,
            org,
            None,
            serde_json::json!({ "org_id": org, "invitation_id": invitation }),
        )
        .await?;
        let event = self
            .event(
                SecurityEventKind::InvitationRevoked,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("invitation", invitation);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await
    }

    /// What the invitation grants (signed-in user, rate-limited). The
    /// invited address is shown masked only.
    pub async fn preview_invitation(
        &self,
        principal: &Principal,
        token: &SensitiveString,
    ) -> Result<InvitationPreview, AuthError> {
        let user = require_session_user(principal)?;
        self.token_attempt(user).await?;
        let token = OpaqueToken::parse(token.expose()).map_err(|_| invalid_token())?;
        let now = self.now();
        let row = find_by_token(self.pool(), &token).await?;
        let row = row.filter(|r| r.is_usable(now)).ok_or_else(invalid_token)?;
        let org = super::orgs::load_org(self.pool(), row.org_id).await?;
        if org.status != OrgStatus::Active {
            return Err(invalid_token());
        }
        let record = UserRepository::find_by_id(self.pool(), user).await?;
        let email_matches = record.is_some_and(|u| {
            u.is_email_verified()
                && u.email_normalized.as_deref() == Some(row.email_normalized.as_str())
        });
        Ok(InvitationPreview {
            org_id: org.id,
            org_name: org.name,
            role: RoleRef {
                id: row.role_id,
                key: row.role_key,
                name: row.role_name,
            },
            email_masked: mask_email(&row.email),
            email_matches,
            expires_at: row.expires_at,
        })
    }

    /// Accepts an invitation (ORG-05): the caller's **verified** address must
    /// equal the invited address. Single use, atomic.
    pub async fn accept_invitation(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        token: &SensitiveString,
    ) -> Result<MyOrganization, AuthError> {
        let user = require_session_user(principal)?;
        principal.require_writable()?;
        self.token_attempt(user).await?;
        let token = OpaqueToken::parse(token.expose()).map_err(|_| invalid_token())?;
        let now = self.now();
        // Find the organization first, then lock in the global order
        // (organization row, then invitation row) used by every writer.
        let org = find_by_token(self.pool(), &token)
            .await?
            .filter(|r| r.is_usable(now))
            .map(|r| r.org_id)
            .ok_or_else(invalid_token)?;
        let mut tx = self.begin().await?;
        lock_org(&mut tx, org).await?;
        let sql = concat!(
            invitation_select!(),
            "WHERE i.token_hash = $1 AND i.org_id = $2 FOR UPDATE OF i"
        );
        let row = sqlx::query_as::<_, InvitationRow>(sql)
            .bind(token.hash().as_bytes().as_slice())
            .bind(org)
            .fetch_optional(&mut *tx)
            .await?
            .filter(|r| r.is_usable(now))
            .ok_or_else(invalid_token)?;
        let organization = super::orgs::load_org(&mut *tx, org).await?;
        match organization.status {
            OrgStatus::Active => {}
            OrgStatus::PendingDeletion | OrgStatus::Suspended => return Err(invalid_token()),
        }
        let record = UserRepository::find_by_id(&mut *tx, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))?;
        if record.email_normalized.as_deref() != Some(row.email_normalized.as_str()) {
            return Err(AuthError::new(codes::org::ORG_INVITATION_EMAIL_MISMATCH));
        }
        if !record.is_email_verified() {
            return Err(AuthError::new(codes::org::ORG_EMAIL_VERIFICATION_REQUIRED));
        }
        let membership =
            insert_membership(&mut tx, org, user, row.role_id, row.invited_by, now).await?;
        // An accepted invitation is the organization's explicit decision to
        // admit the user again: domain auto-join may apply after a later
        // departure only once that departure is recorded anew.
        sqlx::query("DELETE FROM org_auto_join_exclusions WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(user)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE invitations SET status = 'accepted', accepted_at = $2, accepted_by = $3 \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(row.id)
        .bind(now)
        .bind(user)
        .execute(&mut *tx)
        .await?;
        self.publish(
            &mut tx,
            DomainEventKind::InvitationAccepted,
            org,
            Some(user),
            serde_json::json!({ "org_id": org, "invitation_id": row.id, "user_id": user }),
        )
        .await?;
        self.publish(
            &mut tx,
            DomainEventKind::MemberAdded,
            org,
            Some(user),
            serde_json::json!({ "org_id": org, "user_id": user, "role_id": row.role_id }),
        )
        .await?;
        let event = self
            .event(
                SecurityEventKind::InvitationAccepted,
                ctx,
                principal,
                Some(org),
            )
            .with_subject(user)
            .with_resource("invitation", row.id)
            .with_meta("role", row.role_key.clone());
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(MyOrganization {
            organization,
            membership_id: membership,
            role: RoleRef {
                id: row.role_id,
                key: row.role_key,
                name: row.role_name,
            },
            member_status: MemberStatus::Active,
        })
    }

    /// Mails per organization and recipient address (new + resend): the
    /// per-invitation cooldown alone is bypassed by revoking and inviting
    /// the same address again. Keyed by organization too, so one tenant's
    /// sends never reveal or exhaust another tenant's budget.
    async fn recipient_budget(&self, org: OrgId, email: &EmailAddress) -> Result<(), AuthError> {
        let subject = format!("{org}|{}", email.normalized());
        self.rate_limit(
            RateLimitKey::account(actions::INVITATION_RECIPIENT, &subject),
            self.config().invitation_sends_per_recipient,
        )
        .await
    }

    async fn token_attempt(&self, user: UserId) -> Result<(), AuthError> {
        self.rate_limit(
            RateLimitKey::user(actions::TOKEN_ATTEMPT, user),
            self.config().token_attempts_per_user,
        )
        .await
    }

    async fn send_invitation(
        &self,
        conn: &mut PgConnection,
        locale: Locale,
        email: &EmailAddress,
        org_name: &str,
        token: OpaqueToken,
        expires_at: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let notification = Notification {
            recipient: Recipient {
                email: email.clone(),
                user_id: None,
                display_name: None,
            },
            locale,
            kind: NotificationKind::Invitation {
                org_name: org_name.to_owned(),
                inviter_name: None,
                token: token.into_sensitive(),
                expires_at,
            },
        };
        self.deps().notifier.notify_in_tx(conn, notification).await
    }
}

async fn find_by_token<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    token: &OpaqueToken,
) -> Result<Option<InvitationRow>, AuthError> {
    let sql = concat!(invitation_select!(), "WHERE i.token_hash = $1");
    Ok(sqlx::query_as::<_, InvitationRow>(sql)
        .bind(token.hash().as_bytes().as_slice())
        .fetch_optional(executor)
        .await?)
}

async fn load_invitation(
    conn: &mut PgConnection,
    org: OrgId,
    id: InvitationId,
) -> Result<InvitationRow, AuthError> {
    let sql = concat!(invitation_select!(), "WHERE i.org_id = $1 AND i.id = $2");
    sqlx::query_as::<_, InvitationRow>(sql)
        .bind(org)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}

async fn lock_invitation(
    conn: &mut PgConnection,
    org: OrgId,
    id: InvitationId,
) -> Result<InvitationRow, AuthError> {
    let sql = concat!(
        invitation_select!(),
        "WHERE i.org_id = $1 AND i.id = $2 FOR UPDATE OF i"
    );
    sqlx::query_as::<_, InvitationRow>(sql)
        .bind(org)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}
