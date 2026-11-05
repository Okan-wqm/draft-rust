//! The signed-in user's sessions (SES-11), logout (SES-12) and `GET /v1/me`
//! (SES-16).

use authn_core::domain::{AccountStatus, AuthMethodRef, ClientKind, FactorKind, Locale, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, SessionId, UserId};
use authn_core::ports::{Actor, RevocationReason, SecurityEvent, SecurityEventKind};
use authn_store::UserRepository;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::SessionService;
use super::revoke::Attribution;
use crate::model::SessionRecord;
use crate::store::sessions::{self, Target};

/// One entry of `GET /v1/me/sessions` (SES-11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionSummary {
    /// Session id.
    pub id: SessionId,
    /// `web` or `native`.
    pub client_kind: ClientKind,
    /// Simple device description parsed from the user agent.
    pub device: Option<String>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Last activity.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub last_seen_at: OffsetDateTime,
    /// Partially masked IP of the last activity (`203.0.113.x`).
    pub ip: Option<String>,
    /// The session of this request.
    pub current: bool,
    /// "Remember me".
    pub remember_me: bool,
    /// An administrator acts as you in this session (ADM-04).
    pub impersonated: bool,
    /// Active organization.
    pub active_org_id: Option<OrgId>,
    /// End of the session at the latest.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
}

impl SessionSummary {
    fn of(record: &SessionRecord, current: Option<SessionId>) -> Self {
        Self {
            id: record.id,
            client_kind: record.client_kind,
            device: record.device_name.clone(),
            created_at: record.created_at,
            last_seen_at: record.last_seen_at,
            ip: record
                .last_seen_ip
                .or(record.created_ip)
                .map(authn_core::redact::mask_ip),
            current: Some(record.id) == current,
            remember_me: record.remember_me,
            impersonated: record.is_impersonation(),
            active_org_id: record.active_org_id,
            expires_at: record.absolute_expires_at,
        }
    }
}

/// The caller's view of the current session in `GET /v1/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MeSession {
    /// Session id.
    pub id: SessionId,
    /// `web` or `native`.
    pub client_kind: ClientKind,
    /// Authentication methods (RFC 8176).
    pub amr: Vec<AuthMethodRef>,
    /// Authentication context class.
    pub acr: Option<String>,
    /// Last (re-)authentication (SES-13).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub auth_time: OffsetDateTime,
    /// Absolute expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// Impersonation details (ADM-04).
    pub impersonation: Option<MeImpersonation>,
}

/// Impersonation details shown in `GET /v1/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MeImpersonation {
    /// The acting administrator.
    pub admin_user_id: UserId,
    /// Read-only mode.
    pub read_only: bool,
}

/// Verified sign-in methods of the user (SES-16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MeMethods {
    /// A password is set.
    pub password: bool,
    /// Registered passkeys.
    pub passkeys: u32,
    /// MFA is enabled (an active second factor exists).
    pub mfa_enabled: bool,
    /// Active second-factor kinds.
    pub mfa_factors: Vec<FactorKind>,
}

/// The active organization in `GET /v1/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MeOrganization {
    /// Organization id.
    pub id: OrgId,
    /// Display name (present when the session currently satisfies the
    /// organization's policy).
    pub name: Option<String>,
}

/// `GET /v1/me` (SES-16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MeResponse {
    /// User id.
    pub user_id: UserId,
    /// E-mail address.
    pub email: Option<String>,
    /// Whether the address is verified.
    pub email_verified: bool,
    /// Display name.
    pub display_name: Option<String>,
    /// Preferred language.
    pub locale: Locale,
    /// IANA time zone.
    pub time_zone: String,
    /// Account status.
    pub status: AccountStatus,
    /// Platform administrator (never during impersonation).
    pub is_platform_admin: bool,
    /// Verified sign-in methods.
    pub methods: MeMethods,
    /// Active organization (SES-17).
    pub active_organization: Option<MeOrganization>,
    /// The current session.
    pub session: MeSession,
}

/// The session behind a user principal, or `unauthenticated` (API keys and
/// service accounts have no session; `/v1/me/…` refuses them, contracts §7).
pub(crate) fn session_user(principal: &Principal) -> Result<(UserId, SessionId), AuthError> {
    let user = principal
        .user_id()
        .ok_or_else(|| AuthError::new(codes::common::FORBIDDEN))?;
    let session = principal
        .session_id()
        .ok_or_else(|| AuthError::new(codes::common::FORBIDDEN).with_context("api key"))?;
    Ok((user, session))
}

fn actor(principal: &Principal, user: UserId) -> (Actor, Option<UserId>) {
    (
        Actor::User(user),
        principal.impersonation.map(|i| i.admin_user_id),
    )
}

impl SessionService {
    /// The caller's live sessions, newest first (SES-11).
    pub async fn list_sessions(
        &self,
        principal: &Principal,
    ) -> Result<Vec<SessionSummary>, AuthError> {
        let (user, current) = session_user(principal)?;
        let records = sessions::list_live_for_user(self.pool(), user, self.now()).await?;
        Ok(records
            .iter()
            .map(|r| SessionSummary::of(r, Some(current)))
            .collect())
    }

    /// Revokes one of the caller's sessions (SES-11). Another user's
    /// session is `not_found` (no existence oracle). Returns whether it was
    /// the current session. An impersonating admin (ADM-04) may only end
    /// the impersonation session itself, never the user's other sessions
    /// (the same rule as "sign out other sessions" / "everywhere").
    pub async fn revoke_own_session(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        target: SessionId,
    ) -> Result<bool, AuthError> {
        let (user, current) = session_user(principal)?;
        principal.require_writable()?;
        if principal.is_impersonated() && target != current {
            return Err(AuthError::new(codes::common::FORBIDDEN)
                .with_context("impersonation cannot end the user's other sessions"));
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        if !sessions::is_live_session_of(&mut *tx, target, user, now).await? {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        let (actor, impersonator) = actor(principal, user);
        let reason = if target == current {
            RevocationReason::Logout
        } else {
            RevocationReason::UserRequest
        };
        self.pg_revoker()
            .revoke(
                &mut tx,
                Target::One(target),
                reason,
                None,
                Some(Attribution {
                    actor,
                    impersonator,
                    ctx,
                }),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(target == current)
    }

    /// "Sign out other sessions" (SES-11): every session of the caller
    /// except the current one, plus the trusted devices (MFA-09) and the
    /// pending e-mail change (ACC-07). Returns the number revoked.
    pub async fn revoke_other_sessions(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
    ) -> Result<u64, AuthError> {
        let (user, current) = session_user(principal)?;
        if principal.is_impersonated() {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        self.bulk_revoke(ctx, principal, Target::UserExcept(user, current), user)
            .await
    }

    /// Logout (SES-12): revokes the current session and its refresh-token
    /// family.
    pub async fn logout(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
    ) -> Result<(), AuthError> {
        let (user, current) = session_user(principal)?;
        let (actor, impersonator) = actor(principal, user);
        let mut tx = self.begin().await?;
        let reason = if principal.is_impersonated() {
            RevocationReason::ImpersonationEnded
        } else {
            RevocationReason::Logout
        };
        self.pg_revoker()
            .revoke(
                &mut tx,
                Target::One(current),
                reason,
                None,
                Some(Attribution {
                    actor,
                    impersonator,
                    ctx,
                }),
            )
            .await?;
        let kind = if principal.is_impersonated() {
            SecurityEventKind::ImpersonationEnded
        } else {
            SecurityEventKind::Logout
        };
        let mut event = SecurityEvent::new(kind, self.now())
            .with_context(ctx)
            .with_actor(actor)
            .with_subject(user)
            .with_resource("session", current);
        event.impersonator = impersonator;
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(())
    }

    /// "Sign out everywhere" (SES-11, SES-12): every session of the user,
    /// the trusted devices (MFA-09) and the pending e-mail change (ACC-07).
    /// Returns the number of sessions revoked.
    pub async fn logout_everywhere(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
    ) -> Result<u64, AuthError> {
        let (user, _) = session_user(principal)?;
        if principal.is_impersonated() {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        self.bulk_revoke(ctx, principal, Target::User(user), user)
            .await
    }

    async fn bulk_revoke(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        target: Target,
        user: UserId,
    ) -> Result<u64, AuthError> {
        let (actor, impersonator) = actor(principal, user);
        let mut tx = self.begin().await?;
        let revoked = self
            .pg_revoker()
            .revoke(
                &mut tx,
                target,
                RevocationReason::UserRequest,
                Some(user),
                Some(Attribution {
                    actor,
                    impersonator,
                    ctx,
                }),
            )
            .await?;
        self.deps()
            .accounts
            .on_sessions_revoked_in_tx(&mut tx, user, RevocationReason::UserRequest)
            .await?;
        authn_store::commit(tx).await?;
        Ok(u64::try_from(revoked.len()).unwrap_or(u64::MAX))
    }

    /// `GET /v1/me` (SES-16): basic profile, verified methods, active
    /// organization and the current session.
    pub async fn me(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        session: &SessionRecord,
    ) -> Result<MeResponse, AuthError> {
        let (user_id, _) = session_user(principal)?;
        // The profile view carries the user's e-mail, verification and
        // status: no second read of the same `users` row (K-70).
        let profile = self
            .deps()
            .accounts
            .profile_of(user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))?;
        let password = UserRepository::find_password(self.pool(), user_id)
            .await?
            .is_some();
        let passkeys = {
            let mut conn = self.pool().acquire().await?;
            self.deps()
                .webauthn
                .passkey_count_in(&mut conn, user_id, false)
                .await?
        };
        let mfa = self.deps().mfa.status_for_user(user_id).await?;
        let mfa_factors = {
            let mut kinds: Vec<FactorKind> = mfa
                .factors
                .iter()
                .filter(|f| f.status == authn_mfa::FactorState::Active)
                .map(|f| f.kind)
                .collect();
            kinds.sort();
            kinds.dedup();
            kinds
        };
        let active_organization = match principal.active_org {
            Some(org) => Some(MeOrganization {
                id: org,
                name: self
                    .deps()
                    .orgs
                    .check_membership(principal, org, Some(ctx.client_ip))
                    .await
                    .ok()
                    .map(|a| a.org_name),
            }),
            None => None,
        };
        Ok(MeResponse {
            user_id,
            email: profile.email,
            email_verified: profile.email_verified,
            display_name: profile.display_name,
            locale: profile.locale,
            time_zone: profile.time_zone,
            status: profile.status,
            is_platform_admin: principal.is_platform_admin,
            methods: MeMethods {
                password,
                passkeys,
                mfa_enabled: mfa.enabled,
                mfa_factors,
            },
            active_organization,
            session: MeSession {
                id: session.id,
                client_kind: session.client_kind,
                amr: principal.amr.clone(),
                acr: principal.acr.clone(),
                auth_time: principal.auth_time.unwrap_or(session.auth_time),
                expires_at: session.absolute_expires_at,
                impersonation: principal.impersonation.map(|i| MeImpersonation {
                    admin_user_id: i.admin_user_id,
                    read_only: i.read_only,
                }),
            },
        })
    }
}
