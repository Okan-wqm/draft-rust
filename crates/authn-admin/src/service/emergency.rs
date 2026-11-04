//! Emergency operations (ADM-06), audited as `admin.emergency_action`
//! with the justification (ADM-08).
//!
//! * **Revoke every session of every user** — one transaction
//!   (`SessionRevoker::revoke_everything`, reason `emergency`). The calling
//!   admin's own session ends too.
//! * **Emergency signing key rotation** — `SigningKeyRepository::
//!   emergency_rotate` revokes the active key and activates a fresh one in
//!   the same transaction as the audit event; afterwards the in-process key
//!   cache is dropped ([`crate::SigningKeyCache`]). Access tokens signed by
//!   the old key stop verifying.
//! * **Force a password change for every password older than a date** —
//!   `must_change_password` is set (PWD-12) for every account whose
//!   password was last changed before `changed_before`, optionally revoking
//!   their sessions and trusted devices, in batches of
//!   `AdminSettings::bulk_batch_size` accounts per transaction. A summary
//!   event is recorded at the end; if a batch fails, a failure event with
//!   the progress so far and the justification is recorded and the error
//!   returned (already
//!   committed batches stay; re-running continues where it stopped, as
//!   updated accounts no longer match).

use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{SigningKeyId, UserId};
use authn_core::ports::{RevocationReason, RevokeOptions, SecurityEventKind};
use authn_store::{SigningKeyRepository, UserRepository};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::{AdminService, meta};
use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::store;

/// Result of an emergency revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EmergencyOutcome {
    /// Action code.
    pub action: String,
    /// Sessions revoked.
    pub sessions_revoked: u64,
    /// Audit event.
    pub event_id: authn_core::id::EventId,
}

/// Result of an emergency key rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KeyRotationOutcome {
    /// Action code.
    pub action: String,
    /// The new active key (`kid`).
    pub key_id: SigningKeyId,
    /// Audit event.
    pub event_id: authn_core::id::EventId,
}

/// Result of a bulk forced password change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BulkResetOutcome {
    /// Action code.
    pub action: String,
    /// Accounts now required to change their password.
    pub accounts_updated: u64,
    /// Sessions revoked.
    pub sessions_revoked: u64,
    /// Audit event (summary).
    pub event_id: authn_core::id::EventId,
}

impl AdminService {
    /// Revokes every session of every user (ADM-06).
    pub async fn revoke_all_sessions(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        reason: &Justification,
    ) -> Result<EmergencyOutcome, AuthError> {
        const ACTION: &str = "revoke_all_sessions";
        let mut tx = self.begin().await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_everything(&mut tx, RevocationReason::Emergency)
            .await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::EmergencyAction,
                ACTION,
                None,
                Some(reason),
                meta([
                    ("sessions_revoked", Value::from(revoked)),
                    ("priority", Value::from("high")),
                ]),
            )
            .await?;
        authn_store::commit(tx).await?;
        tracing::warn!(revoked, "emergency: every session revoked");
        Ok(EmergencyOutcome {
            action: ACTION.to_owned(),
            sessions_revoked: revoked,
            event_id: event,
        })
    }

    /// Emergency signing key rotation (ADM-06, CRY-10).
    pub async fn rotate_signing_key(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        reason: &Justification,
    ) -> Result<KeyRotationOutcome, AuthError> {
        const ACTION: &str = "rotate_signing_key";
        let mut tx = self.begin().await?;
        let key =
            SigningKeyRepository::emergency_rotate(&mut tx, &self.deps().envelopes, self.now())
                .await
                .map_err(|e| {
                    AuthError::internal("emergency signing key rotation failed").with_source(e)
                })?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::EmergencyAction,
                ACTION,
                None,
                Some(reason),
                meta([
                    ("signing_key_id", Value::from(key.id.to_string())),
                    ("priority", Value::from("high")),
                ]),
            )
            .await?;
        authn_store::commit(tx).await?;
        self.deps().signing_keys.invalidate_signing_keys();
        tracing::warn!(kid = %key.id, "emergency: signing key rotated");
        Ok(KeyRotationOutcome {
            action: ACTION.to_owned(),
            key_id: key.id,
            event_id: event,
        })
    }

    /// Requires a password change from every account whose password was
    /// last changed before `changed_before` (ADM-06).
    pub async fn force_password_change_before(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        changed_before: OffsetDateTime,
        revoke_sessions: bool,
        reason: &Justification,
    ) -> Result<BulkResetOutcome, AuthError> {
        const ACTION: &str = "force_password_change_before";
        if changed_before > self.now() {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(serde_json::json!({ "field": "changed_before" })));
        }
        let batch = i64::from(self.settings().bulk_batch_size.max(1));
        let mut cursor: Option<UserId> = None;
        let mut updated: u64 = 0;
        let mut revoked: u64 = 0;
        loop {
            match self
                .bulk_batch(changed_before, cursor, batch, revoke_sessions)
                .await
            {
                Ok(None) => break,
                Ok(Some((last, n, r))) => {
                    cursor = Some(last);
                    updated += n;
                    revoked += r;
                }
                Err(err) => {
                    // The committed batches are an admin action too: audit
                    // them with the justification (ADM-08).
                    let audited: Result<(), AuthError> = async {
                        let mut tx = self.begin().await?;
                        self.record_action_outcome(
                            &mut tx,
                            ctx,
                            caller,
                            SecurityEventKind::EmergencyAction,
                            ACTION,
                            None,
                            Some(reason),
                            meta([
                                ("accounts_updated", Value::from(updated)),
                                ("sessions_revoked", Value::from(revoked)),
                                ("revoke_sessions", Value::from(revoke_sessions)),
                                (
                                    "changed_before_unix",
                                    Value::from(changed_before.unix_timestamp()),
                                ),
                                ("priority", Value::from("high")),
                            ]),
                            Some("batch_failed"),
                        )
                        .await?;
                        authn_store::commit(tx).await
                    }
                    .await;
                    if let Err(audit_err) = audited {
                        tracing::error!(
                            code = audit_err.code().code(),
                            "could not audit a failed bulk password reset"
                        );
                    }
                    return Err(err);
                }
            }
        }
        let mut tx = self.begin().await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::EmergencyAction,
                ACTION,
                None,
                Some(reason),
                meta([
                    ("accounts_updated", Value::from(updated)),
                    ("sessions_revoked", Value::from(revoked)),
                    ("revoke_sessions", Value::from(revoke_sessions)),
                    (
                        "changed_before_unix",
                        Value::from(changed_before.unix_timestamp()),
                    ),
                    ("priority", Value::from("high")),
                ]),
            )
            .await?;
        authn_store::commit(tx).await?;
        tracing::warn!(updated, revoked, "emergency: password change forced");
        Ok(BulkResetOutcome {
            action: ACTION.to_owned(),
            accounts_updated: updated,
            sessions_revoked: revoked,
            event_id: event,
        })
    }

    /// One batch: returns the last processed id and the counts, or `None`
    /// when nothing is left.
    async fn bulk_batch(
        &self,
        changed_before: OffsetDateTime,
        after: Option<UserId>,
        limit: i64,
        revoke_sessions: bool,
    ) -> Result<Option<(UserId, u64, u64)>, AuthError> {
        let mut tx = self.begin().await?;
        let ids = store::stale_password_users(&mut tx, changed_before, after, limit).await?;
        let Some(last) = ids.last().copied() else {
            return Ok(None);
        };
        let mut updated = 0;
        let mut revoked = 0;
        for user in ids {
            if UserRepository::set_must_change_password(&mut tx, user, true).await? {
                updated += 1;
            }
            if revoke_sessions {
                revoked += self
                    .deps()
                    .sessions
                    .revoke_all_for_user(
                        &mut tx,
                        user,
                        RevocationReason::Emergency,
                        RevokeOptions {
                            also_trusted_devices: true,
                        },
                    )
                    .await?;
            }
        }
        authn_store::commit(tx).await?;
        Ok(Some((last, updated, revoked)))
    }
}
