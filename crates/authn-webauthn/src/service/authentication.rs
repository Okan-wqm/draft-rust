//! Authentication ceremonies for authn-session (PKY-01, PKY-02, PKY-05,
//! PKY-08, SES-02, SES-13, SES-20).
//!
//! * **Discoverable** (passwordless login): username-less, optional
//!   conditional mediation, user verification **required**. Only passkeys
//!   registered with user verification (`usage = both`) are accepted. A
//!   username-first passkey login is deliberately not offered: it would
//!   reveal which accounts have passkeys (allow-list) or need fake
//!   credential lists to hide it.
//! * **Second factor**: bound to the login challenge; allow-list of the
//!   user's passkeys; user verification preferred (required when every
//!   allowed passkey was registered with it — `webauthn-rs` enforces it for
//!   such passkeys anyway).
//! * **Step-up**: bound to the session; user verification required.
//!
//! Every ceremony carries a 256-bit client binding token (only its SHA-256
//! is stored) and is consumed atomically before verification (PKY-01).
//!
//! Clone detection (PKY-05): `webauthn-rs` rejects signature-counter
//! regressions and backup-eligibility changes; in addition the counter is
//! compared again with the **row-locked** stored value before it is
//! updated, so concurrent assertions or a stale ceremony snapshot cannot
//! slip a regression through. A counter regression on a *signature-verified*
//! assertion marks the passkey (`clone_suspected_at`), records
//! `passkey.clone_suspected`, queues the `passkey_clone_suspected` e-mail
//! (first detection of that passkey only; K-19) — all in one transaction —
//! and fails the ceremony. Backup-flag
//! inconsistencies are detected by `webauthn-rs` before the signature is
//! checked, so they only fail the ceremony (forgeable without the key).
//!
//! Organization policy (PKY-08): the caller's policy is always combined
//! (strictest) with [`crate::PasskeyPolicySource`] for the user — at start
//! for known users, at finish for discoverable login (the user is only known
//! then).

use authn_core::domain::AuthMethodRef;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{CeremonyId, UserId};
use authn_core::ports::{Actor, RateLimitKey, SecurityEvent, SecurityEventKind};
use authn_crypto::token::OpaqueToken;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, Credential, DiscoverableAuthentication, Passkey, PasskeyAuthentication,
    PublicKeyCredential, SecurityKey, SecurityKeyAuthentication, WebauthnError,
};

use super::{
    AuthenticatedPasskey, AuthenticationFinish, AuthenticationPurpose, AuthenticationStart,
    AuthenticationTarget, WebauthnService, actions,
};
use crate::metrics;
use crate::policy::PasskeyPolicy;
use crate::store::ceremonies::{self, CeremonyBinding, CeremonyKind, CeremonyPurpose};
use crate::store::credentials::{self, CredentialRow, UsageUpdate};
use crate::store::{handles, map_binding_error};

/// Serialized authentication ceremony (`webauthn_ceremonies.state`).
#[derive(Serialize, Deserialize)]
struct StoredAuthentication {
    /// Format version.
    v: u8,
    /// Snapshot of the policy at start (PKY-08); `None` = unrestricted.
    allowed_aaguids: Option<Vec<Uuid>>,
    #[serde(flatten)]
    variant: AuthenticationVariant,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "variant", content = "state", rename_all = "snake_case")]
enum AuthenticationVariant {
    /// Username-less, user verification required.
    Discoverable(DiscoverableAuthentication),
    /// Allow-list, user verification required.
    Passkey(PasskeyAuthentication),
    /// Allow-list, user verification preferred.
    SecurityKey(SecurityKeyAuthentication),
}

impl StoredAuthentication {
    fn policy(&self) -> PasskeyPolicy {
        PasskeyPolicy {
            allowed_aaguids: self
                .allowed_aaguids
                .as_ref()
                .map(|list| list.iter().copied().collect()),
        }
    }
}

fn binding_for(target: &AuthenticationTarget, binding_hash: [u8; 32]) -> CeremonyBinding {
    match *target {
        AuthenticationTarget::Discoverable { .. } => CeremonyBinding {
            kind: CeremonyKind::DiscoverableAuthentication,
            purpose: CeremonyPurpose::Login,
            user_id: None,
            session_id: None,
            challenge_id: None,
            binding_hash: Some(binding_hash),
        },
        AuthenticationTarget::SecondFactor {
            user_id,
            challenge_id,
        } => CeremonyBinding {
            kind: CeremonyKind::Authentication,
            purpose: CeremonyPurpose::SecondFactor,
            user_id: Some(user_id),
            session_id: None,
            challenge_id: Some(challenge_id),
            binding_hash: Some(binding_hash),
        },
        AuthenticationTarget::StepUp {
            user_id,
            session_id,
        } => CeremonyBinding {
            kind: CeremonyKind::Authentication,
            purpose: CeremonyPurpose::StepUp,
            user_id: Some(user_id),
            session_id: Some(session_id),
            challenge_id: None,
            binding_hash: Some(binding_hash),
        },
    }
}

/// Whether a stored passkey may serve this purpose under the policy.
fn eligible(row: &CredentialRow, purpose: AuthenticationPurpose, policy: &PasskeyPolicy) -> bool {
    let usage = row.usage();
    let usage_ok = match purpose {
        AuthenticationPurpose::Login | AuthenticationPurpose::StepUp => usage.allows_passwordless(),
        AuthenticationPurpose::SecondFactor => usage.allows_second_factor(),
    };
    usage_ok && policy.permits(row.aaguid)
}

fn stored_credential(row: &CredentialRow) -> Result<Credential, AuthError> {
    serde_json::from_value(row.passkey.0.clone())
        .map_err(|_| AuthError::internal("stored passkey is unreadable"))
}

/// *Authenticated* clone signals from `webauthn-rs` (PKY-05).
///
/// Only a signature-counter regression qualifies: `webauthn-rs` reports it
/// after the assertion signature verified, so the holder of the private key
/// produced it. The backup-flag checks (`CredentialBackupEligibilityInconsistent`,
/// `CredentialMayNotBeHardwareBound`) run **before** the signature check:
/// anyone who knows a credential id (e.g. from a second-factor
/// `allowCredentials` list) can trigger them with forged authenticator data,
/// so they only fail the ceremony — they never mark the passkey or record a
/// clone event.
fn clone_signal(err: &WebauthnError) -> Option<&'static str> {
    matches!(err, WebauthnError::CredentialPossibleCompromise).then_some("counter_regression")
}

fn failed() -> AuthError {
    AuthError::new(codes::webauthn::PASSKEY_AUTHENTICATION_FAILED)
}

/// RFC 8176 references of a verified assertion (SES-08, SES-21).
pub(super) fn amr_for(backup_eligible: bool, user_verified: bool) -> Vec<AuthMethodRef> {
    let mut amr = vec![
        if backup_eligible {
            AuthMethodRef::Swk
        } else {
            AuthMethodRef::Hwk
        },
        AuthMethodRef::User,
    ];
    if user_verified {
        amr.push(AuthMethodRef::Mfa);
    }
    amr
}

impl WebauthnService {
    /// Starts an authentication ceremony (authn-session). `policy` is an
    /// additional restriction from the caller (PKY-08; usually
    /// [`PasskeyPolicy::unrestricted`]). It is always combined, strictest
    /// wins, with the user's organization policy from
    /// [`crate::PasskeyPolicySource`] (`active_org = None`): at start for
    /// `SecondFactor` / `StepUp`, at finish for `Discoverable` (the user is
    /// only known once the assertion arrives).
    ///
    /// Errors: `rate_limited` (per client IP and, for known users, per
    /// user), `passkey_not_available` (the user has no eligible passkey),
    /// `unauthenticated` (the bound session / challenge vanished).
    pub async fn start_authentication(
        &self,
        ctx: &RequestContext,
        target: AuthenticationTarget,
        policy: &PasskeyPolicy,
    ) -> Result<AuthenticationStart, AuthError> {
        let limit = self.config().authentication_per_ip;
        self.deps()
            .rate_limiter
            .check(
                &RateLimitKey::ip(actions::AUTHENTICATION_START_IP, ctx.client_ip),
                limit,
                1,
            )
            .await?
            .into_result()?;
        let purpose = target.purpose();
        let now = self.now();
        let rp = &self.inner.relying_party;
        let mut tx = self.begin().await?;

        let (options, variant, policy) = match target {
            AuthenticationTarget::Discoverable { conditional_ui } => {
                let (mut options, state) = rp
                    .start_discoverable_authentication()
                    .map_err(|e| start_failed(&e))?;
                if !conditional_ui {
                    options.mediation = None;
                }
                (
                    options,
                    AuthenticationVariant::Discoverable(state),
                    policy.clone(),
                )
            }
            AuthenticationTarget::SecondFactor { user_id, .. }
            | AuthenticationTarget::StepUp { user_id, .. } => {
                self.deps()
                    .rate_limiter
                    .check(
                        &RateLimitKey::user(actions::AUTHENTICATION_START_USER, user_id),
                        limit,
                        1,
                    )
                    .await?
                    .into_result()?;
                let policy = self.effective_policy(&mut tx, user_id, policy).await?;
                let rows = credentials::list_for_user(&mut *tx, user_id).await?;
                let allowed: Vec<Credential> = rows
                    .iter()
                    .filter(|row| eligible(row, purpose, &policy))
                    .map(stored_credential)
                    .collect::<Result<_, _>>()?;
                if allowed.is_empty() {
                    return Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE));
                }
                let require_uv = purpose == AuthenticationPurpose::StepUp
                    || allowed.iter().all(|c| c.user_verified);
                if require_uv {
                    let passkeys: Vec<Passkey> = allowed.into_iter().map(Passkey::from).collect();
                    let (options, state) = rp
                        .start_passkey_authentication(&passkeys)
                        .map_err(|e| start_failed(&e))?;
                    (options, AuthenticationVariant::Passkey(state), policy)
                } else {
                    let keys: Vec<SecurityKey> =
                        allowed.into_iter().map(SecurityKey::from).collect();
                    let (mut options, state) = rp
                        .start_securitykey_authentication(&keys)
                        .map_err(|e| start_failed(&e))?;
                    // Do not steer the browser towards roaming keys only:
                    // platform passkeys are valid second factors too.
                    options.public_key.hints = None;
                    (options, AuthenticationVariant::SecurityKey(state), policy)
                }
            }
        };

        let binding_token = OpaqueToken::generate()?;
        let binding = binding_for(&target, *binding_token.hash().as_bytes());
        let ceremony_id = CeremonyId::generate();
        let expires_at = now + self.config().ceremony_ttl;
        let state = serde_json::to_value(StoredAuthentication {
            v: 1,
            allowed_aaguids: policy
                .allowed_aaguids
                .as_ref()
                .map(|set| set.iter().copied().collect()),
            variant,
        })
        .map_err(|_| AuthError::internal("authentication state cannot be serialized"))?;
        ceremonies::insert(&mut tx, ceremony_id, &binding, state, now, expires_at)
            .await
            .map_err(map_binding_error)?;
        authn_store::commit(tx).await?;
        metrics::ceremony_started(purpose_label(purpose));

        let options = serde_json::to_value(&options)
            .map_err(|_| AuthError::internal("authentication options cannot be serialized"))?;
        Ok(AuthenticationStart {
            ceremony_id,
            binding_token: binding_token.into_sensitive(),
            options,
            expires_at,
        })
    }

    /// Finishes an authentication ceremony (authn-session): verifies the
    /// assertion with `webauthn-rs`, detects clones (PKY-05), updates the
    /// counter / backup state / last use and returns who authenticated.
    ///
    /// Errors: `passkey_ceremony_invalid` (unknown, expired, replayed or
    /// differently bound ceremony, wrong binding token) and
    /// `passkey_authentication_failed` (anything about the assertion; never
    /// more specific). The caller records login / step-up audit events.
    pub async fn finish_authentication(
        &self,
        ctx: &RequestContext,
        finish: AuthenticationFinish,
    ) -> Result<AuthenticatedPasskey, AuthError> {
        let purpose = finish.target.purpose();
        let label = purpose_label(purpose);
        let Ok(token) = OpaqueToken::parse(finish.binding_token.expose()) else {
            metrics::authentication_finished(label, "invalid_ceremony");
            return Err(AuthError::new(codes::webauthn::PASSKEY_CEREMONY_INVALID));
        };
        let binding = binding_for(&finish.target, *token.hash().as_bytes());
        let now = self.now();
        let state = {
            let mut tx = self.begin().await?;
            let state = ceremonies::consume(&mut tx, finish.ceremony_id, &binding, now).await?;
            authn_store::commit(tx).await?;
            state
        };
        let Some(state) = state else {
            metrics::authentication_finished(label, "invalid_ceremony");
            return Err(AuthError::new(codes::webauthn::PASSKEY_CEREMONY_INVALID));
        };
        let stored: StoredAuthentication = serde_json::from_value(state)
            .map_err(|_| AuthError::internal("stored authentication state is unreadable"))?;
        let Ok(response) = serde_json::from_value::<PublicKeyCredential>(finish.credential) else {
            metrics::authentication_finished(label, "malformed_response");
            return Err(failed());
        };
        let policy = stored.policy();
        let outcome = match (stored.variant, finish.target) {
            (
                AuthenticationVariant::Discoverable(state),
                AuthenticationTarget::Discoverable { .. },
            ) => {
                self.finish_discoverable(ctx, state, &response, &policy)
                    .await
            }
            (
                AuthenticationVariant::Passkey(state),
                AuthenticationTarget::SecondFactor { user_id, .. }
                | AuthenticationTarget::StepUp { user_id, .. },
            ) => {
                let verified = self
                    .inner
                    .relying_party
                    .finish_passkey_authentication(&response, &state);
                self.finish_known_user(ctx, user_id, purpose, &response, verified, &policy)
                    .await
            }
            (
                AuthenticationVariant::SecurityKey(state),
                AuthenticationTarget::SecondFactor { user_id, .. }
                | AuthenticationTarget::StepUp { user_id, .. },
            ) => {
                let verified = self
                    .inner
                    .relying_party
                    .finish_securitykey_authentication(&response, &state);
                self.finish_known_user(ctx, user_id, purpose, &response, verified, &policy)
                    .await
            }
            // The binding (kind / purpose) makes this unreachable unless
            // the stored state was tampered with.
            _ => Err(AuthError::internal(
                "ceremony state does not match its binding",
            )),
        };
        match &outcome {
            Ok(_) => metrics::authentication_finished(label, "success"),
            Err(err) if err.is(codes::webauthn::PASSKEY_AUTHENTICATION_FAILED) => {
                metrics::authentication_finished(label, "failed");
            }
            Err(_) => metrics::authentication_finished(label, "error"),
        }
        outcome
    }

    async fn finish_discoverable(
        &self,
        ctx: &RequestContext,
        state: DiscoverableAuthentication,
        response: &PublicKeyCredential,
        policy: &PasskeyPolicy,
    ) -> Result<AuthenticatedPasskey, AuthError> {
        let rp = &self.inner.relying_party;
        let Ok((handle, raw_id)) = rp.identify_discoverable_authentication(response) else {
            return Err(failed());
        };
        let Some(user) = handles::find_user(self.pool(), handle.as_bytes()).await? else {
            return Err(failed());
        };
        let mut tx = self.begin().await?;
        let Some(row) = credentials::lock_by_raw_id(&mut tx, raw_id, user).await? else {
            return Err(failed());
        };
        // The user's organization policy could not be known at start
        // (username-less): apply it now (PKY-08).
        let policy = self.effective_policy(&mut tx, user, policy).await?;
        if !eligible(&row, AuthenticationPurpose::Login, &policy) {
            return Err(failed());
        }
        let mut credential = stored_credential(&row)?;
        // Verified against the row-locked credential: the counter check of
        // webauthn-rs uses the current stored value.
        match rp.finish_discoverable_authentication_v2(response, state, &credential) {
            Ok(result) => {
                if !result.user_verified() {
                    return Err(failed());
                }
                self.record_success(
                    &mut tx,
                    &row,
                    &mut credential,
                    &result,
                    AuthenticationPurpose::Login,
                )
                .await?;
                authn_store::commit(tx).await?;
                Ok(authenticated(
                    user,
                    &row,
                    &result,
                    AuthenticationPurpose::Login,
                ))
            }
            Err(err) => {
                if let Some(reason) = clone_signal(&err) {
                    self.flag_clone(&mut tx, ctx, &row, AuthenticationPurpose::Login, reason)
                        .await?;
                    authn_store::commit(tx).await?;
                }
                tracing::debug!(error = ?err, "passkey login rejected");
                Err(failed())
            }
        }
    }

    async fn finish_known_user(
        &self,
        ctx: &RequestContext,
        user: UserId,
        purpose: AuthenticationPurpose,
        response: &PublicKeyCredential,
        verified: Result<AuthenticationResult, WebauthnError>,
        policy: &PasskeyPolicy,
    ) -> Result<AuthenticatedPasskey, AuthError> {
        let result = match verified {
            Ok(result) => result,
            Err(err) => {
                tracing::debug!(error = ?err, "passkey assertion rejected");
                if let Some(reason) = clone_signal(&err) {
                    let mut tx = self.begin().await?;
                    if let Some(row) =
                        credentials::lock_by_raw_id(&mut tx, response.get_credential_id(), user)
                            .await?
                    {
                        self.flag_clone(&mut tx, ctx, &row, purpose, reason).await?;
                        authn_store::commit(tx).await?;
                    }
                }
                return Err(failed());
            }
        };
        let mut tx = self.begin().await?;
        // The credential may have been deleted (or changed) since the
        // ceremony started: re-read it under a row lock.
        let Some(row) = credentials::lock_by_raw_id(&mut tx, result.cred_id(), user).await? else {
            return Err(failed());
        };
        if !eligible(&row, purpose, policy) {
            return Err(failed());
        }
        if purpose == AuthenticationPurpose::StepUp && !result.user_verified() {
            return Err(failed());
        }
        // Counter check against the locked, current value (the ceremony
        // holds a snapshot from its start).
        let presented = i64::from(result.counter());
        if (presented > 0 || row.sign_count > 0) && presented <= row.sign_count {
            self.flag_clone(&mut tx, ctx, &row, purpose, "counter_regression")
                .await?;
            authn_store::commit(tx).await?;
            return Err(failed());
        }
        let mut credential = stored_credential(&row)?;
        self.record_success(&mut tx, &row, &mut credential, &result, purpose)
            .await?;
        authn_store::commit(tx).await?;
        Ok(authenticated(user, &row, &result, purpose))
    }

    /// The caller's `policy` combined (strictest) with the organization
    /// policy of `user` (PKY-08). Authentication has no active organization,
    /// so the source is asked with `active_org = None`.
    async fn effective_policy(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        policy: &PasskeyPolicy,
    ) -> Result<PasskeyPolicy, AuthError> {
        let organization = self
            .deps()
            .policy_source
            .policy_for_user(conn, user, None)
            .await?;
        Ok(PasskeyPolicy::strictest([policy.clone(), organization]))
    }

    /// Persists counter, backup flags and last use after a verified
    /// assertion.
    async fn record_success(
        &self,
        conn: &mut PgConnection,
        row: &CredentialRow,
        credential: &mut Credential,
        result: &AuthenticationResult,
        purpose: AuthenticationPurpose,
    ) -> Result<(), AuthError> {
        if result.counter() > credential.counter {
            credential.counter = result.counter();
        }
        credential.backup_state = result.backup_state();
        if result.backup_eligible() {
            credential.backup_eligible = true;
        }
        let passkey = serde_json::to_value(&*credential)
            .map_err(|_| AuthError::internal("credential cannot be serialized"))?;
        credentials::record_use(
            conn,
            row.id,
            UsageUpdate {
                passkey,
                sign_count: i64::from(credential.counter),
                backup_eligible: credential.backup_eligible,
                backup_state: credential.backup_state,
                used_at: self.now(),
            },
        )
        .await?;
        tracing::debug!(passkey = %row.id, purpose = ?purpose, "passkey assertion verified");
        Ok(())
    }

    /// Marks a passkey as possibly cloned and records the security event in
    /// the caller's transaction (PKY-05). The caller commits.
    async fn flag_clone(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        row: &CredentialRow,
        purpose: AuthenticationPurpose,
        reason: &'static str,
    ) -> Result<(), AuthError> {
        let now = self.now();
        credentials::mark_clone_suspected(conn, row.id, now).await?;
        metrics::clone_suspected(reason);
        tracing::warn!(
            request_id = %ctx.request_id,
            user = %row.user_id,
            passkey = %row.id,
            reason,
            "possible cloned passkey"
        );
        let actor = if purpose == AuthenticationPurpose::StepUp {
            Actor::User(row.user_id)
        } else {
            Actor::Anonymous
        };
        let event = SecurityEvent::new(SecurityEventKind::PasskeyCloneSuspected, now)
            .with_context(ctx)
            .with_actor(actor)
            .with_subject(row.user_id)
            .with_resource("passkey", row.id)
            .failed(reason)
            .with_meta("purpose", purpose_label(purpose))
            .with_meta("stored_sign_count", row.sign_count);
        self.deps().audit.record_in_tx(&mut *conn, event).await?;
        // K-19: tell the owner once per passkey (the first detection); later
        // detections of an already flagged passkey only add audit events.
        if row.clone_suspected_at.is_none() {
            self.notify_clone_suspected(conn, ctx, row.user_id).await?;
        }
        Ok(())
    }
}

fn authenticated(
    user: UserId,
    row: &CredentialRow,
    result: &AuthenticationResult,
    purpose: AuthenticationPurpose,
) -> AuthenticatedPasskey {
    AuthenticatedPasskey {
        user_id: user,
        credential_id: row.id,
        purpose,
        user_verified: result.user_verified(),
        backup_eligible: result.backup_eligible(),
        backup_state: result.backup_state(),
        amr: amr_for(result.backup_eligible(), result.user_verified()),
    }
}

fn purpose_label(purpose: AuthenticationPurpose) -> &'static str {
    match purpose {
        AuthenticationPurpose::Login => "login",
        AuthenticationPurpose::SecondFactor => "second_factor",
        AuthenticationPurpose::StepUp => "step_up",
    }
}

fn start_failed(err: &WebauthnError) -> AuthError {
    AuthError::internal("webauthn-rs could not create authentication options")
        .with_context(format!("webauthn-rs error: {err:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ses_21_amr_reflects_key_kind_and_user_verification() {
        assert_eq!(
            amr_for(true, true),
            vec![AuthMethodRef::Swk, AuthMethodRef::User, AuthMethodRef::Mfa]
        );
        assert_eq!(
            amr_for(false, false),
            vec![AuthMethodRef::Hwk, AuthMethodRef::User]
        );
    }

    #[test]
    fn pky_05_clone_signals_are_recognised() {
        assert_eq!(
            clone_signal(&WebauthnError::CredentialPossibleCompromise),
            Some("counter_regression")
        );
        assert!(clone_signal(&WebauthnError::InvalidRPOrigin).is_none());
        // Raised before the signature is verified: forgeable, not evidence.
        assert!(clone_signal(&WebauthnError::CredentialBackupEligibilityInconsistent).is_none());
        assert!(clone_signal(&WebauthnError::CredentialMayNotBeHardwareBound).is_none());
    }
}
