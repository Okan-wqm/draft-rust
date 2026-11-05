//! Factor management (MFA-04, MFA-07, MFA-10), admin reset (ADM-03) and
//! cleanup (OPS-06).

use authn_core::domain::{FactorKind, Principal};
use authn_core::error::{AuthError, codes as error_codes};
use authn_core::http::RequestContext;
use authn_core::id::{FactorId, UserId};
use authn_core::ports::{NotificationKind, RevocationReason, SecurityEventKind};
use authn_store::{OneTimeTokenRepository, TokenPurpose, UserRepository};
use sqlx::PgConnection;

use super::{
    GeneratedRecoveryCodes, MfaResetSummary, MfaService, MfaStatus, PurgeReport,
    RecoveryCodesStatus, summary,
};
use crate::metrics;
use crate::policy::{MfaRequirement, evaluate, required_by_policy};
use crate::store::factors::{self, FactorStatus};
use crate::store::{recovery, settings, trusted};

/// Rows removed per table and purge run.
const PURGE_BATCH: u32 = 1000;

impl MfaService {
    /// The caller's MFA state (MFA-10): factors without secrets (contact
    /// data masked), recovery-code counters, trusted-device count. Readable
    /// under read-only impersonation.
    pub async fn status(&self, principal: &Principal) -> Result<MfaStatus, AuthError> {
        let user = Self::reading_user(principal)?;
        self.status_for_user(user).await
    }

    /// [`MfaService::status`] for any user (authn-session `GET /v1/me`,
    /// authn-admin user details, ADM-02).
    pub async fn status_for_user(&self, user: UserId) -> Result<MfaStatus, AuthError> {
        let now = self.now();
        let mut conn = self.pool().acquire().await?;
        let account = self.user_record(&mut conn, user).await?;
        let factors = factors::list(&mut *conn, user).await?;
        let recovery = recovery::status(&mut *conn, user).await?;
        let devices = trusted::list_active(&mut *conn, user, now).await?;
        Ok(MfaStatus {
            enabled: factors.iter().any(|f| f.status == FactorStatus::Active),
            factors: factors
                .iter()
                .map(|f| summary(f, account.email.as_deref(), now))
                .collect(),
            recovery_codes: RecoveryCodesStatus {
                remaining: recovery.remaining,
                total: recovery.total,
                generated_at: recovery.generated_at,
            },
            trusted_devices: u32::try_from(devices.len()).unwrap_or(u32::MAX),
        })
    }

    /// Recovery-code counters of the caller (MFA-04).
    pub async fn recovery_codes_status(
        &self,
        principal: &Principal,
    ) -> Result<RecoveryCodesStatus, AuthError> {
        let user = Self::reading_user(principal)?;
        let status = recovery::status(self.pool(), user).await?;
        Ok(RecoveryCodesStatus {
            remaining: status.remaining,
            total: status.total,
            generated_at: status.generated_at,
        })
    }

    /// Removes a factor (MFA-07). Requires step-up. An active factor cannot
    /// be removed when MFA is required by policy (admin role, organization)
    /// and no other permitted factor would remain (`mfa_last_factor_required`).
    /// Removing an active factor revokes the trusted devices (MFA-09),
    /// sends a notification and is audited; removing the last factor also
    /// deletes the recovery codes and turns the preference off.
    ///
    /// Race-free: the `users` row (shared convention with password /
    /// passkey removal, PWD-11) and the user's MFA row are locked first.
    pub async fn remove_factor(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        factor_id: FactorId,
    ) -> Result<(), AuthError> {
        let user = self.step_up_user(principal)?;
        let now = self.now();
        let mut tx = self.begin().await?;
        let account = UserRepository::lock_for_update(&mut tx, user)
            .await
            .map_err(super::lock_error)?
            .ok_or_else(|| AuthError::new(error_codes::common::NOT_FOUND))?;
        self.lock_settings(&mut tx, user).await?;
        let factor = factors::lock(&mut tx, user, factor_id)
            .await?
            .ok_or_else(|| AuthError::new(error_codes::common::NOT_FOUND))?;

        if factor.status == FactorStatus::Pending {
            factors::delete(&mut tx, user, factor.id).await?;
            revoke_codes_of(&mut tx, user, factor.kind, now).await?;
            authn_store::commit(tx).await?;
            return Ok(());
        }

        let org_policy = self
            .deps()
            .policy_source
            .org_policy_for_user(&mut tx, user)
            .await?;
        let mut before = self
            .policy_input_excluding(&mut tx, user, org_policy.clone(), false, None)
            .await?;
        let mut after_removal = self
            .policy_input_excluding(&mut tx, user, org_policy, false, Some(factor.id))
            .await?;
        // Only a requirement imposed by someone else blocks the removal; the
        // user's own preference never locks the user in.
        before.user_opted_in = false;
        after_removal.user_opted_in = false;
        let only_primary = |input: &crate::policy::MfaPolicyInput| {
            input
                .enrolled_factors
                .iter()
                .any(|k| *k != FactorKind::RecoveryCode)
        };
        if required_by_policy(&before)
            && matches!(evaluate(&before), MfaRequirement::Required { .. })
            && !matches!(evaluate(&after_removal), MfaRequirement::Required { .. })
        {
            return Err(AuthError::new(error_codes::mfa::MFA_LAST_FACTOR_REQUIRED));
        }

        factors::delete(&mut tx, user, factor.id).await?;
        revoke_codes_of(&mut tx, user, factor.kind, now).await?;
        let last_factor = !only_primary(&after_removal);
        if last_factor {
            recovery::delete_all(&mut tx, user).await?;
            settings::set_enabled(&mut tx, user, false).await?;
        }
        trusted::revoke_all(&mut tx, user, RevocationReason::MfaChanged.as_str(), now).await?;
        self.notify_user(
            &mut tx,
            ctx,
            &account,
            NotificationKind::MfaFactorRemoved {
                factor: factor.kind,
                at: now,
            },
        )
        .await?;
        let event = self
            .event(SecurityEventKind::MfaFactorRemoved, ctx, user)
            .with_resource("mfa_factor", factor.id)
            .with_meta("factor", factor.kind.as_str())
            .with_meta("last_factor", last_factor);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        metrics::removed(factor.kind.as_str());
        Ok(())
    }

    /// Generates a new batch of recovery codes, invalidating every old one
    /// (MFA-04). Requires step-up and at least one active factor (an
    /// account without MFA has nothing to recover). Revokes trusted devices
    /// (MFA change, MFA-09). The codes are returned exactly once.
    pub async fn regenerate_recovery_codes(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
    ) -> Result<GeneratedRecoveryCodes, AuthError> {
        let user = self.step_up_user(principal)?;
        let now = self.now();
        let mut tx = self.begin().await?;
        self.lock_settings(&mut tx, user).await?;
        let has_factor = factors::list(&mut *tx, user)
            .await?
            .iter()
            .any(|f| f.status == FactorStatus::Active)
            || self
                .deps()
                .policy_source
                .webauthn_factor_count(&mut tx, user)
                .await?
                > 0;
        if !has_factor {
            return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE)
                .with_context("recovery codes need an active second factor"));
        }
        let codes = self.store_new_recovery_codes(&mut tx, user, now).await?;
        trusted::revoke_all(&mut tx, user, RevocationReason::MfaChanged.as_str(), now).await?;
        let event = self
            .event(SecurityEventKind::RecoveryCodesGenerated, ctx, user)
            .with_meta("count", codes.codes.len());
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(codes)
    }

    /// Admin MFA reset (ADM-03), inside the caller's transaction: deletes
    /// every factor and recovery code, revokes trusted devices and pending
    /// codes, resets the preference and lock, and queues the `mfa_reset`
    /// notification. The caller (authn-admin) checks the admin's authority
    /// and records the `mfa.reset` / `admin.action` audit events with its
    /// reason.
    pub async fn reset_user_mfa_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<MfaResetSummary, AuthError> {
        let now = self.now();
        let account = self.user_record(conn, user).await?;
        self.lock_settings(conn, user).await?;
        let summary = MfaResetSummary {
            factors: factors::delete_all(conn, user).await?,
            recovery_codes: recovery::delete_all(conn, user).await?,
            trusted_devices: trusted::revoke_all(
                conn,
                user,
                RevocationReason::AdminAction.as_str(),
                now,
            )
            .await?,
        };
        OneTimeTokenRepository::revoke_for_user(
            conn,
            user,
            &[
                TokenPurpose::MfaEmailOtp,
                TokenPurpose::MfaSmsOtp,
                TokenPurpose::PhoneVerification,
            ],
            now,
        )
        .await?;
        settings::reset(conn, user).await?;
        self.notify_user(conn, ctx, &account, NotificationKind::MfaReset { at: now })
            .await?;
        Ok(summary)
    }

    /// Deletes abandoned pending enrollments and trusted devices that
    /// expired or were revoked before the retention point (OPS-06). Safe on
    /// several instances (`FOR UPDATE SKIP LOCKED`).
    pub async fn purge_expired(&self) -> Result<PurgeReport, AuthError> {
        let now = self.now();
        let pending_before = now
            .checked_sub(
                time::Duration::try_from(self.config().enrollment_ttl)
                    .map_err(|_| AuthError::internal("enrollment ttl"))?,
            )
            .ok_or_else(|| AuthError::internal("purge time out of range"))?;
        let mut conn = self.pool().acquire().await?;
        Ok(PurgeReport {
            pending_factors: factors::purge_pending(&mut conn, pending_before, PURGE_BATCH).await?,
            trusted_devices: trusted::purge(&mut conn, now, PURGE_BATCH).await?,
        })
    }
}

/// Revokes outstanding codes of a removed factor's kind.
async fn revoke_codes_of(
    conn: &mut PgConnection,
    user: UserId,
    kind: FactorKind,
    now: time::OffsetDateTime,
) -> Result<(), AuthError> {
    let purposes: &[TokenPurpose] = match kind {
        FactorKind::Email => &[TokenPurpose::MfaEmailOtp],
        FactorKind::Sms => &[TokenPurpose::MfaSmsOtp, TokenPurpose::PhoneVerification],
        FactorKind::Totp | FactorKind::RecoveryCode | FactorKind::Webauthn => &[],
    };
    if !purposes.is_empty() {
        OneTimeTokenRepository::revoke_for_user(conn, user, purposes, now).await?;
    }
    Ok(())
}
