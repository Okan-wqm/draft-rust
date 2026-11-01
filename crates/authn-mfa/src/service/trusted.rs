//! Trusted devices (MFA-09): "don't ask for MFA on this device for 30 days".
//!
//! * Disabled by configuration (`mfa.trusted_device.enabled`), by the
//!   organization policy of the login context (`trusted_devices_allowed`,
//!   passed by the caller), by the policy of **any** organization the user
//!   is a member of ([`crate::MfaPolicySource::org_policy_for_user`], the
//!   strictest combination — a trusted device skips MFA before any
//!   organization context exists) and always for platform admins (ADM-01).
//! * The token is signed with the HKDF purpose key (`DeviceTokenSigner`)
//!   and bound to the user; only its SHA-256 is stored.
//! * Revoked on password reset, MFA changes and "sign out everywhere"
//!   ([`MfaService::revoke_trusted_devices_in_tx`]).

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes as error_codes};
use authn_core::http::RequestContext;
use authn_core::id::{TrustedDeviceId, UserId};
use authn_core::ports::{RevocationReason, SecurityEventKind};
use authn_core::redact::mask_ip;
use sqlx::PgConnection;

use super::{
    IssuedTrustedDevice, MAX_DEVICE_NAME_CHARS, MAX_TRUSTED_DEVICES, MfaService,
    TrustedDeviceSummary, after,
};
use crate::store::trusted::{self, NewTrustedDevice};

impl MfaService {
    /// Trusts the requesting device for `user` after a successful MFA
    /// verification (the caller — authn-session — has just verified a
    /// second factor and the user asked to be remembered). Returns `None`
    /// when trusted devices are disabled by configuration, by
    /// `trusted_devices_allowed = false` (organization policy of the login
    /// context), by the policy of any organization the user belongs to, or
    /// because the user is a platform admin. At most 20 devices stay active
    /// per user; older ones are revoked.
    pub async fn trust_device(
        &self,
        ctx: &RequestContext,
        user: UserId,
        trusted_devices_allowed: bool,
    ) -> Result<Option<IssuedTrustedDevice>, AuthError> {
        if !self.config().trusted_device.enabled || !trusted_devices_allowed {
            return Ok(None);
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        let account = self.user_record(&mut tx, user).await?;
        if account.is_platform_admin {
            return Ok(None);
        }
        self.lock_settings(&mut tx, user).await?;
        if !self
            .memberships_allow_trusted_devices(&mut tx, user)
            .await?
        {
            return Ok(None);
        }
        let id = TrustedDeviceId::generate();
        let expires_at = after(now, self.config().trusted_device.ttl)?;
        let token = self.inner.device_signer.issue(user, id, expires_at)?;
        trusted::revoke_oldest_beyond(
            &mut tx,
            user,
            MAX_TRUSTED_DEVICES - 1,
            RevocationReason::UserRequest.as_str(),
            now,
        )
        .await?;
        let name: Option<String> = ctx
            .user_agent
            .as_deref()
            .map(|ua| ua.chars().take(MAX_DEVICE_NAME_CHARS).collect());
        trusted::insert(
            &mut tx,
            &NewTrustedDevice {
                id,
                user,
                token_hash: &token.hash(),
                device_name: name.as_deref(),
                user_agent: ctx.user_agent.as_deref(),
                created_ip: Some(ctx.client_ip),
                created_at: now,
                expires_at,
            },
        )
        .await?;
        let event = self
            .event(SecurityEventKind::TrustedDeviceAdded, ctx, user)
            .with_resource("trusted_device", id);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(Some(IssuedTrustedDevice {
            device_id: id,
            token,
            expires_at,
        }))
    }

    /// Whether `token` marks the requesting device as trusted for `user`
    /// (MFA-09). Any problem — disabled feature, policy (the caller's flag
    /// or any membership's organization policy), admin account, malformed /
    /// forged / expired / revoked token, token of another user — answers
    /// `false`; the login flow then simply asks for MFA. Records the use on
    /// success.
    pub async fn is_trusted_device(
        &self,
        user: UserId,
        token: &str,
        trusted_devices_allowed: bool,
    ) -> Result<bool, AuthError> {
        if !self.config().trusted_device.enabled || !trusted_devices_allowed {
            return Ok(false);
        }
        let now = self.now();
        // Signature and expiry first: forged tokens never reach the
        // database.
        let Some(verified) = self.inner.device_signer.verify(user, token, now) else {
            return Ok(false);
        };
        let mut conn = self.pool().acquire().await?;
        let Some(account) = authn_store::UserRepository::find_by_id(&mut *conn, user).await? else {
            return Ok(false);
        };
        if account.is_platform_admin
            || !self
                .memberships_allow_trusted_devices(&mut conn, user)
                .await?
        {
            return Ok(false);
        }
        Ok(trusted::touch_active(
            &mut conn,
            user,
            verified.device_id,
            &verified.token_hash,
            now,
        )
        .await?)
    }

    /// Whether no organization the user belongs to forbids trusted devices
    /// (the strictest combination reported by the [`crate::MfaPolicySource`]).
    /// The caller's `trusted_devices_allowed` flag only describes the login
    /// context; an organization that switched the feature off must not be
    /// bypassed by a login in another (or no) organization context.
    async fn memberships_allow_trusted_devices(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<bool, AuthError> {
        Ok(self
            .deps()
            .policy_source
            .org_policy_for_user(conn, user)
            .await?
            .is_none_or(|policy| policy.trusted_devices_allowed))
    }

    /// Revokes every trusted device of `user` inside the caller's
    /// transaction (password reset, MFA change, "sign out everywhere";
    /// authn-session calls it from `SessionRevoker` when
    /// `RevokeOptions::also_trusted_devices` is set). Returns the number of
    /// revoked devices. No audit event: the caller audits its own action.
    pub async fn revoke_trusted_devices_in_tx(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        Ok(trusted::revoke_all(conn, user, reason.as_str(), self.now()).await?)
    }

    /// The caller's active trusted devices (IP masked).
    pub async fn list_trusted_devices(
        &self,
        principal: &Principal,
    ) -> Result<Vec<TrustedDeviceSummary>, AuthError> {
        let user = Self::reading_user(principal)?;
        let rows = trusted::list_active(self.pool(), user, self.now()).await?;
        Ok(rows
            .into_iter()
            .map(|row| TrustedDeviceSummary {
                id: row.id,
                name: row.device_name,
                ip: row.created_ip.map(mask_ip),
                created_at: row.created_at,
                expires_at: row.expires_at,
                last_used_at: row.last_used_at,
            })
            .collect())
    }

    /// Revokes one of the caller's trusted devices. Protective action: a
    /// session is required, step-up is not. Foreign or unknown ids are
    /// `not_found`.
    pub async fn revoke_trusted_device(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        device: TrustedDeviceId,
    ) -> Result<(), AuthError> {
        let user = Self::session_user(principal)?;
        let mut tx = self.begin().await?;
        if !trusted::revoke(
            &mut tx,
            user,
            device,
            RevocationReason::UserRequest.as_str(),
            self.now(),
        )
        .await?
        {
            return Err(AuthError::new(error_codes::common::NOT_FOUND));
        }
        let event = self
            .event(SecurityEventKind::TrustedDeviceRevoked, ctx, user)
            .with_resource("trusted_device", device);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(())
    }

    /// Revokes all of the caller's trusted devices; returns how many.
    pub async fn revoke_all_trusted_devices(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
    ) -> Result<u64, AuthError> {
        let user = Self::session_user(principal)?;
        let mut tx = self.begin().await?;
        let count = trusted::revoke_all(
            &mut tx,
            user,
            RevocationReason::UserRequest.as_str(),
            self.now(),
        )
        .await?;
        if count > 0 {
            let event = self
                .event(SecurityEventKind::TrustedDeviceRevoked, ctx, user)
                .with_meta("count", count);
            self.deps().audit.record_in_tx(&mut tx, event).await?;
        }
        authn_store::commit(tx).await?;
        Ok(count)
    }
}
