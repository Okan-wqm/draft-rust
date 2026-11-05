//! Switching the active organization (SES-17).
//!
//! The target must be an organization in which the user has an active
//! membership (otherwise `404`, ORG-10); its policy is applied to the
//! current session through authn-org's `check_membership` (IP allow-list,
//! MFA / phishing-resistant MFA from the session `amr`, session lifetime
//! cap from `auth_time`) plus the allowed primary login methods (checked
//! here). A session that does not satisfy the policy gets
//! `org_policy_mfa_required` / `step_up_required` — the client re-verifies
//! with `POST /v1/reauth` (a second factor or a passkey) and retries.
//!
//! On success the session id is rotated (SES-03): web clients get a new
//! cookie and CSRF token, native clients a new token pair; the absolute
//! expiry can only shrink (the organization's lifetime cap).

use authn_core::domain::{AuthMethodRef, ClientKind, FactorKind, LoginMethod, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::OrgId;
use authn_core::ports::{Actor, SecurityEvent, SecurityEventKind};
use authn_crypto::token::{OpaqueToken, TokenHash};
use authn_org::OrgPolicy;
use serde::Deserialize;
use utoipa::ToSchema;

use super::manage::session_user;
use super::{SessionService, after};
use crate::model::{CurrentSession, IssuedCredentials, SessionRecord};
use crate::store::sessions::{self, SessionUpdate};

/// Body of `POST /v1/session/org`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgSwitch {
    /// The organization to activate; `null` leaves the organization context
    /// (personal context).
    pub org_id: Option<OrgId>,
}

/// The new state of a session after a privilege change.
pub(crate) struct PrivilegeChange<'a> {
    pub(crate) amr: &'a [AuthMethodRef],
    /// Second factors behind the session's `mfa` (K-78).
    pub(crate) mfa_factors: &'a [FactorKind],
    pub(crate) auth_time: time::OffsetDateTime,
    pub(crate) active_org_id: Option<OrgId>,
    pub(crate) absolute_expires_at: time::OffsetDateTime,
    /// `jti` of the access token that authenticated a native request
    /// (K-58: a concurrent rotation refuses the change).
    pub(crate) presented_access_token: Option<uuid::Uuid>,
}

/// Whether the session proved a passkey (phishing-resistant) factor.
pub(crate) fn has_passkey(amr: &[AuthMethodRef]) -> bool {
    amr.iter()
        .any(|a| matches!(a, AuthMethodRef::Hwk | AuthMethodRef::Swk))
}

impl SessionService {
    /// Re-reads the locked session's token and checks that the request's
    /// cookie (or impersonation header token, K-12) is still the current
    /// one (a concurrent rotation wins).
    pub(crate) async fn check_current_token(
        conn: &mut sqlx::PgConnection,
        current: &CurrentSession,
    ) -> Result<(), AuthError> {
        if let Some(presented) = current.token_hash.or(current.impersonation_header_hash) {
            let stored = sessions::token_hash(conn, current.record.id).await?;
            if stored != Some(TokenHash::from_bytes(presented)) {
                return Err(AuthError::new(codes::common::UNAUTHENTICATED)
                    .with_context("session token rotated concurrently"));
            }
        }
        Ok(())
    }

    /// Rotates the credentials of a locked session after a privilege change
    /// and writes the new state.
    pub(crate) async fn apply_privilege_change(
        &self,
        conn: &mut sqlx::PgConnection,
        ctx: &RequestContext,
        record: &SessionRecord,
        change: PrivilegeChange<'_>,
    ) -> Result<(SessionRecord, IssuedCredentials), AuthError> {
        let PrivilegeChange {
            amr,
            mfa_factors,
            auth_time,
            active_org_id,
            absolute_expires_at,
            presented_access_token,
        } = change;
        let now = self.now();
        let idle = if record.is_impersonation() {
            absolute_expires_at
        } else {
            after(now, self.settings().lifetime(record.shape()).idle_timeout)
        };
        let web_token = match record.client_kind {
            ClientKind::Web => Some(OpaqueToken::generate().map_err(AuthError::from)?),
            ClientKind::Native => None,
        };
        let new_hash = web_token.as_ref().map(OpaqueToken::hash);
        let updated = sessions::apply_update(
            &mut *conn,
            record.id,
            &SessionUpdate {
                new_token_hash: new_hash.as_ref(),
                amr,
                mfa_factors,
                auth_time,
                active_org_id,
                absolute_expires_at,
                idle_expires_at: idle,
                now,
                ip: Some(ctx.client_ip),
            },
        )
        .await?;
        let credentials = match web_token {
            Some(token) => self.web_credentials(&updated, token, None, now)?,
            None => {
                self.rotate_native_credentials(&mut *conn, &updated, presented_access_token, now)
                    .await?
            }
        };
        Ok((updated, credentials))
    }

    /// Switches the active organization of the current session (SES-17).
    pub async fn switch_org(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        current: &CurrentSession,
        target: Option<OrgId>,
    ) -> Result<(SessionRecord, IssuedCredentials), AuthError> {
        let (user, session_id) = session_user(principal)?;
        principal.require_writable()?;
        if session_id != current.record.id {
            return Err(AuthError::new(codes::common::UNAUTHENTICATED));
        }
        // K-57: authn-org checks the session's login method and second
        // factors on every organization request. A bearer principal
        // verified without the live session check carries neither; the
        // switch reads them from the stored session (as below).
        let mut checked = principal.clone();
        if checked.login_method.is_none()
            && target.is_some()
            && let Some(live) = sessions::find_live_by_id(self.pool(), session_id, self.now())
                .await?
                .filter(|live| live.record.user_id == user)
        {
            checked.login_method = live.record.login_method;
            checked.mfa_factors =
                super::authenticate::factors_proven_by(&live.record.mfa_factors, &principal.amr);
        }
        let policy = match target {
            None => None,
            Some(org) => Some(
                self.deps()
                    .orgs
                    .check_membership(&checked, org, Some(ctx.client_ip))
                    .await?
                    .policy,
            ),
        };
        let now = self.now();
        let mut tx = self.begin().await?;
        let live = sessions::lock_live(&mut tx, session_id, now)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))?;
        Self::check_current_token(&mut tx, current).await?;
        let record = live.record;
        if record.user_id != user {
            return Err(AuthError::new(codes::common::UNAUTHENTICATED));
        }
        // The allowed primary login methods are checked against the stored
        // session (a bearer principal without the live session check only
        // carries the token's claims, not the login method).
        if let Some(policy) = &policy {
            let method_allowed = match record.login_method {
                Some(method) => policy.allows_login_method(method),
                // Impersonation sessions have no login method; any other
                // session without one is "method unknown".
                None => record.is_impersonation() || policy.allowed_login_methods.is_none(),
            };
            if !method_allowed
                && !(policy.allows_login_method(LoginMethod::Passkey)
                    && has_passkey(&principal.amr))
            {
                return Err(AuthError::new(codes::session::LOGIN_METHOD_NOT_ALLOWED));
            }
        }
        // K-58 audit: the organization's allowed second factors apply to
        // the `mfa` the session brings along, not only to logins made with
        // the organization requested. K-78: read from the recorded second
        // factors, never inferred from `amr` (a risk confirmation e-mail
        // is in `amr` but is no factor).
        if let Some(policy) = &policy
            && !record.is_impersonation()
            && !second_factor_allowed(policy, &record.mfa_factors, &record.amr)
        {
            return Err(AuthError::new(codes::org::ORG_POLICY_MFA_REQUIRED)
                .with_context("the session's second factor is not allowed here"));
        }
        let cap = policy.as_ref().and_then(OrgPolicy::session_lifetime_cap);
        let absolute = match cap {
            Some(cap) => record.absolute_expires_at.min(after(record.auth_time, cap)),
            None => record.absolute_expires_at,
        };
        if absolute <= now {
            return Err(AuthError::new(codes::common::STEP_UP_REQUIRED));
        }
        let previous = record.active_org_id;
        let (updated, credentials) = self
            .apply_privilege_change(
                &mut tx,
                ctx,
                &record,
                PrivilegeChange {
                    amr: &record.amr,
                    mfa_factors: &record.mfa_factors,
                    auth_time: record.auth_time,
                    active_org_id: target,
                    absolute_expires_at: absolute,
                    presented_access_token: current.token_id,
                },
            )
            .await?;
        let mut event = SecurityEvent::new(SecurityEventKind::SessionOrgSwitched, now)
            .with_context(ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
            .with_resource("session", record.id)
            .with_meta(
                "from_org_id",
                previous.map_or(serde_json::Value::Null, |o| o.to_string().into()),
            );
        event.impersonator = principal.impersonation.map(|i| i.admin_user_id);
        if let Some(org) = target {
            event = event.with_org(org);
        }
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok((updated, credentials))
    }
}

/// Whether the second factor behind the session's `mfa` is one `policy`
/// allows (`allowed_mfa_factors`, MFA-08), when the policy requires MFA.
///
/// K-78: the factor is read from the session's recorded `mfa_factors` (the
/// factor kinds verified as second factors at login or step-up), never
/// inferred from `amr` — a risk confirmation e-mail (RSK-03) adds `email`
/// to `amr` without being a factor. A passkey is MFA on its own (SES-21).
/// A session without a recorded allowed factor (provider MFA, sessions
/// created before migration 2002) gets "no": the user steps up with an
/// allowed factor.
pub(crate) fn second_factor_allowed(
    policy: &OrgPolicy,
    mfa_factors: &[FactorKind],
    amr: &[AuthMethodRef],
) -> bool {
    let Some(allowed) = &policy.allowed_mfa_factors else {
        return true;
    };
    if !(policy.mfa_required || policy.phishing_resistant_mfa_required) || has_passkey(amr) {
        return true;
    }
    mfa_factors.iter().any(|factor| allowed.contains(factor))
}
