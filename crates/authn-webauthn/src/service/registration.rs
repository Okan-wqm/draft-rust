//! Registration ceremonies (PKY-01, PKY-02, PKY-03, PKY-08).
//!
//! Start (`POST /v1/me/passkeys/registration/options`):
//! 1. the user's own session (never an impersonation, ADM-04), per-user
//!    rate limit;
//! 2. step-up when the account already has passkeys (always, unless
//!    `webauthn.step_up_for_first_passkey = false`) — SES-13;
//! 3. per-user limit, organization policy (PKY-08), random user handle
//!    (PKY-03), every existing credential in `excludeCredentials`;
//! 4. `webauthn-rs` options; discoverable credential preferred
//!    (`residentKey: "preferred"`) for passwordless passkeys;
//! 5. state stored server-side, bound to the user **and the session**,
//!    valid `webauthn.ceremony_ttl` (PKY-01).
//!
//! Finish (`POST /v1/me/passkeys/registration/verify`): the ceremony is
//! consumed atomically (bound to the same user + session, single use,
//! unexpired) and committed *before* `webauthn-rs` verifies origin,
//! challenge, RP id hash, user presence / verification, algorithm and — under
//! a restricting policy — the attestation chain and AAGUID. The credential is
//! then stored with its audit event and notification in one transaction.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{CeremonyId, CredentialId, SessionId, UserId};
use authn_core::ports::{RateLimitKey, SecurityEventKind};
use authn_store::{StoreError, UserRepository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationMetadata, AttestedPasskeyRegistration, Credential, CredentialID,
    PasskeyRegistration, RegisterPublicKeyCredential, SecurityKeyRegistration, WebauthnError,
};
use webauthn_rs_proto::{CreationChallengeResponse, ResidentKeyRequirement};

use super::{
    PasskeySummary, PasskeyUsage, RegistrationIntent, RegistrationOptionsRequest,
    RegistrationStart, RegistrationVerifyRequest, WebauthnService, actions, summary,
};
use crate::metrics;
use crate::name::{DEFAULT_PASSKEY_NAME, DEFAULT_SECURITY_KEY_NAME, normalize_name};
use crate::policy::trust;
use crate::store::ceremonies::{self, CeremonyBinding, CeremonyKind, CeremonyPurpose};
use crate::store::credentials::{self, CREDENTIAL_ID_UNIQUE, NewCredential};
use crate::store::{handles, map_binding_error};

/// Valid authenticator credential id lengths (WebAuthn L3 §6.1; matches
/// the `webauthn_credentials` CHECK constraint).
const CREDENTIAL_ID_LEN: std::ops::RangeInclusive<usize> = 16..=1023;

/// Serialized registration ceremony (`webauthn_ceremonies.state`).
#[derive(Serialize, Deserialize)]
struct StoredRegistration {
    /// Format version.
    v: u8,
    intent: RegistrationIntent,
    name: Option<String>,
    #[serde(flatten)]
    variant: RegistrationVariant,
}

/// The `webauthn-rs` registration state; the variant decides how the
/// response is verified.
#[derive(Serialize, Deserialize)]
#[serde(tag = "variant", content = "state", rename_all = "snake_case")]
enum RegistrationVariant {
    /// Passkey, attestation `none`, user verification required.
    Passkey(PasskeyRegistration),
    /// Passkey with verified attestation (restricting policy).
    AttestedPasskey(AttestedPasskeyRegistration),
    /// Second-factor security key, user verification preferred
    /// (attested when a restricting policy applies).
    SecurityKey {
        registration: SecurityKeyRegistration,
        attested: bool,
    },
}

impl RegistrationVariant {
    fn attested(&self) -> bool {
        match self {
            Self::Passkey(_) => false,
            Self::AttestedPasskey(_) => true,
            Self::SecurityKey { attested, .. } => *attested,
        }
    }
}

fn registration_binding(user: UserId, session: SessionId) -> CeremonyBinding {
    CeremonyBinding {
        kind: CeremonyKind::Registration,
        purpose: CeremonyPurpose::Register,
        user_id: Some(user),
        session_id: Some(session),
        challenge_id: None,
        binding_hash: None,
    }
}

impl WebauthnService {
    /// Starts registering a passkey for the calling user (PKY-01/02/03/08).
    pub async fn start_registration(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        request: RegistrationOptionsRequest,
    ) -> Result<RegistrationStart, AuthError> {
        let (user, session) = Self::registering_session_user(principal)?;
        let intent = request.usage.unwrap_or_default();
        let name = request.name.as_deref().map(normalize_name).transpose()?;

        // Authorization first (step-up, limit), so that a stale or stolen
        // session cannot burn the user's registration budget.
        let account = UserRepository::find_by_id(self.pool(), user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let account_name = account
            .email
            .clone()
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let existing = credentials::list_for_user(self.pool(), user).await?;
        if !existing.is_empty() || self.config().step_up_for_first_passkey {
            self.require_step_up(principal)?;
        }
        // Re-checked under the user lock at finish (concurrent ceremonies).
        if existing.len() >= usize::try_from(self.config().max_credentials_per_user).unwrap_or(0) {
            return Err(AuthError::new(codes::webauthn::PASSKEY_LIMIT_REACHED));
        }
        self.deps()
            .rate_limiter
            .check(
                &RateLimitKey::user(actions::REGISTRATION_START, user),
                self.config().registration_per_user,
                1,
            )
            .await?
            .into_result()?;

        let now = self.now();
        let mut tx = self.begin().await?;
        let policy = self
            .deps()
            .policy_source
            .policy_for_user(&mut tx, user, principal.active_org)
            .await?;
        let handle = handles::get_or_create(&mut tx, user, now).await?;
        let exclude: Vec<CredentialID> = existing
            .iter()
            .map(|c| CredentialID::from(c.credential_id.clone()))
            .collect();
        let user_unique_id = Uuid::from_bytes(handle);

        let rp = &self.inner.relying_party;
        let (mut options, variant) = match (&policy.allowed_aaguids, intent) {
            (None, RegistrationIntent::Passwordless) => {
                let (ccr, state) = rp
                    .start_passkey_registration(
                        user_unique_id,
                        &account_name,
                        &account_name,
                        Some(exclude),
                    )
                    .map_err(|e| start_failed(&e))?;
                (ccr, RegistrationVariant::Passkey(state))
            }
            (None, RegistrationIntent::SecondFactor) => {
                let (ccr, state) = rp
                    .start_securitykey_registration(
                        user_unique_id,
                        &account_name,
                        &account_name,
                        Some(exclude),
                        None,
                        None,
                    )
                    .map_err(|e| start_failed(&e))?;
                (
                    ccr,
                    RegistrationVariant::SecurityKey {
                        registration: state,
                        attested: false,
                    },
                )
            }
            (Some(allowed), intent) => {
                let roots = trust::restricted_to(&self.inner.settings.attestation_roots, allowed)?;
                if roots.is_empty() {
                    // No trusted root vouches for any allowed model: no
                    // authenticator could ever satisfy the policy.
                    return Err(AuthError::new(codes::webauthn::PASSKEY_NOT_ALLOWED)
                        .with_context("no attestation root covers the allowed AAGUIDs"));
                }
                match intent {
                    RegistrationIntent::Passwordless => {
                        let (ccr, state) = rp
                            .start_attested_passkey_registration(
                                user_unique_id,
                                &account_name,
                                &account_name,
                                Some(exclude),
                                roots,
                                None,
                            )
                            .map_err(|e| start_failed(&e))?;
                        (ccr, RegistrationVariant::AttestedPasskey(state))
                    }
                    RegistrationIntent::SecondFactor => {
                        let (ccr, state) = rp
                            .start_securitykey_registration(
                                user_unique_id,
                                &account_name,
                                &account_name,
                                Some(exclude),
                                Some(roots),
                                None,
                            )
                            .map_err(|e| start_failed(&e))?;
                        (
                            ccr,
                            RegistrationVariant::SecurityKey {
                                registration: state,
                                attested: true,
                            },
                        )
                    }
                }
            }
        };
        if intent == RegistrationIntent::Passwordless {
            prefer_discoverable(&mut options);
        }

        let ceremony_id = CeremonyId::generate();
        let expires_at = now + self.config().ceremony_ttl;
        let state = serde_json::to_value(StoredRegistration {
            v: 1,
            intent,
            name,
            variant,
        })
        .map_err(|_| AuthError::internal("registration state cannot be serialized"))?;
        ceremonies::insert(
            &mut tx,
            ceremony_id,
            &registration_binding(user, session),
            state,
            now,
            expires_at,
        )
        .await
        .map_err(map_binding_error)?;
        authn_store::commit(tx).await?;
        metrics::ceremony_started("registration");
        tracing::debug!(
            request_id = %ctx.request_id,
            user = %user,
            ceremony = %ceremony_id,
            "passkey registration started"
        );

        let options = serde_json::to_value(&options)
            .map_err(|_| AuthError::internal("registration options cannot be serialized"))?;
        Ok(RegistrationStart {
            ceremony_id,
            expires_at,
            options,
        })
    }

    /// Finishes a registration ceremony and stores the passkey (PKY-01,
    /// PKY-02, PKY-08). Every failure burns the ceremony.
    pub async fn finish_registration(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        request: RegistrationVerifyRequest,
    ) -> Result<PasskeySummary, AuthError> {
        let (user, session) = Self::registering_session_user(principal)?;
        let override_name = request.name.as_deref().map(normalize_name).transpose()?;
        let now = self.now();

        // 1. Single use: consume and commit before verifying anything.
        let state = {
            let mut tx = self.begin().await?;
            let state = ceremonies::consume(
                &mut tx,
                request.ceremony_id,
                &registration_binding(user, session),
                now,
            )
            .await?;
            authn_store::commit(tx).await?;
            state
        };
        let Some(state) = state else {
            metrics::registration_finished("invalid_ceremony");
            return Err(AuthError::new(codes::webauthn::PASSKEY_CEREMONY_INVALID));
        };
        let state: StoredRegistration = serde_json::from_value(state)
            .map_err(|_| AuthError::internal("stored registration state is unreadable"))?;

        // 2. Verification (webauthn-rs only).
        let response: RegisterPublicKeyCredential = match serde_json::from_value(request.credential)
        {
            Ok(response) => response,
            Err(_) => {
                return Err(self
                    .registration_rejected(ctx, principal, user, "malformed_response")
                    .await);
            }
        };
        let rp = &self.inner.relying_party;
        let verified = match &state.variant {
            RegistrationVariant::Passkey(reg) => rp
                .finish_passkey_registration(&response, reg)
                .map(Credential::from),
            RegistrationVariant::AttestedPasskey(reg) => rp
                .finish_attested_passkey_registration(&response, reg)
                .map(Credential::from),
            RegistrationVariant::SecurityKey { registration, .. } => rp
                .finish_securitykey_registration(&response, registration)
                .map(Credential::from),
        };
        let credential = match verified {
            Ok(credential) => credential,
            Err(err) => {
                let (code, reason) = classify_registration_error(&err);
                tracing::debug!(user = %user, error = ?err, "passkey registration rejected");
                let rejected = self
                    .registration_rejected(ctx, principal, user, reason)
                    .await;
                return Err(if code == codes::webauthn::PASSKEY_REGISTRATION_FAILED {
                    rejected
                } else {
                    AuthError::new(code)
                });
            }
        };
        // WebAuthn credential ids are 16–1023 bytes; anything else would
        // only fail later on the table constraint.
        if !CREDENTIAL_ID_LEN.contains(&credential.cred_id.len()) {
            return Err(self
                .registration_rejected(ctx, principal, user, "invalid_credential_id")
                .await);
        }

        // 3. Persist with audit + notification.
        let aaguid = if state.variant.attested() {
            attested_aaguid(&credential)
        } else {
            None
        };
        let usage = if credential.user_verified {
            PasskeyUsage::Both
        } else {
            PasskeyUsage::SecondFactor
        };
        let default_name = if usage.allows_passwordless() {
            DEFAULT_PASSKEY_NAME
        } else {
            DEFAULT_SECURITY_KEY_NAME
        };
        let name = override_name
            .or(state.name)
            .unwrap_or_else(|| default_name.to_owned());
        let discoverable = response.extensions.cred_props.as_ref().and_then(|p| p.rk);
        let transports = transports_of(&credential);
        let passkey_json = serde_json::to_value(&credential)
            .map_err(|_| AuthError::internal("credential cannot be serialized"))?;
        let sign_count = i64::from(credential.counter);

        let mut tx = self.begin().await?;
        let account = UserRepository::lock_for_update(&mut tx, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let count = credentials::count_for_user(&mut *tx, user, false).await?;
        if count >= self.config().max_credentials_per_user {
            return Err(AuthError::new(codes::webauthn::PASSKEY_LIMIT_REACHED));
        }
        let row = match credentials::insert(
            &mut tx,
            NewCredential {
                id: CredentialId::generate(),
                user_id: user,
                credential_id: credential.cred_id.as_slice(),
                passkey: passkey_json,
                name: &name,
                aaguid,
                usage,
                user_verified: credential.user_verified,
                backup_eligible: credential.backup_eligible,
                backup_state: credential.backup_state,
                sign_count,
                transports,
                attestation_format: enum_text(&credential.attestation_format),
                discoverable,
                created_at: now,
            },
        )
        .await
        {
            Ok(row) => row,
            Err(StoreError::UniqueViolation { constraint })
                if constraint == CREDENTIAL_ID_UNIQUE =>
            {
                drop(tx);
                metrics::registration_finished("duplicate");
                return Err(AuthError::new(codes::webauthn::PASSKEY_ALREADY_REGISTERED));
            }
            Err(err) => return Err(err.into()),
        };
        self.notify_factor_change(&mut tx, ctx, &account, true)
            .await?;
        let event = self
            .event(
                SecurityEventKind::PasskeyRegistered,
                ctx,
                user,
                Some(principal),
            )
            .with_resource("passkey", row.id)
            .with_meta("usage", usage.as_str())
            .with_meta("backup_eligible", row.backup_eligible)
            .with_meta("attested", aaguid.is_some());
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        metrics::registration_finished("success");
        tracing::info!(user = %user, passkey = %row.id, "passkey registered");
        Ok(summary(&row))
    }

    /// Records a rejected registration and returns the generic error.
    async fn registration_rejected(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        user: UserId,
        reason: &'static str,
    ) -> AuthError {
        metrics::registration_finished(reason);
        self.record_detached(
            self.event(
                SecurityEventKind::PasskeyRegistered,
                ctx,
                user,
                Some(principal),
            )
            .failed(reason),
        )
        .await;
        AuthError::new(codes::webauthn::PASSKEY_REGISTRATION_FAILED)
    }
}

/// `residentKey: "preferred"` (PKY-02: discoverable credentials preferred).
/// A client hint only: the server state never requires a resident key.
fn prefer_discoverable(options: &mut CreationChallengeResponse) {
    if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Preferred);
        selection.require_resident_key = false;
    }
}

fn start_failed(err: &WebauthnError) -> AuthError {
    AuthError::internal("webauthn-rs could not create registration options")
        .with_context(format!("webauthn-rs error: {err:?}"))
}

/// Maps a `webauthn-rs` registration error to a client code and a stable
/// audit reason.
fn classify_registration_error(err: &WebauthnError) -> (authn_core::ErrorCode, &'static str) {
    match err {
        WebauthnError::AttestationUntrustedAaguid
        | WebauthnError::AttestationNotVerifiable
        | WebauthnError::AttestationFormatMissingAaguid
        | WebauthnError::AttestationChainNotTrusted(_)
        | WebauthnError::AttestationTrustFailure
        | WebauthnError::AttestationCertificateTrustStoreEmpty
        | WebauthnError::CredentialMayNotBeHardwareBound => (
            codes::webauthn::PASSKEY_NOT_ALLOWED,
            "attestation_not_trusted",
        ),
        WebauthnError::CredentialExcludedFromRequest => (
            codes::webauthn::PASSKEY_ALREADY_REGISTERED,
            "credential_excluded",
        ),
        WebauthnError::InvalidRPOrigin | WebauthnError::CredentialCrossOrigin => (
            codes::webauthn::PASSKEY_REGISTRATION_FAILED,
            "invalid_origin",
        ),
        WebauthnError::UserNotVerified => (
            codes::webauthn::PASSKEY_REGISTRATION_FAILED,
            "user_not_verified",
        ),
        WebauthnError::MismatchedChallenge => (
            codes::webauthn::PASSKEY_REGISTRATION_FAILED,
            "challenge_mismatch",
        ),
        _ => (
            codes::webauthn::PASSKEY_REGISTRATION_FAILED,
            "verification_failed",
        ),
    }
}

/// The authenticator model, only when its attestation was verified against
/// a trusted root (PKY-08).
fn attested_aaguid(credential: &Credential) -> Option<Uuid> {
    match &credential.attestation.metadata {
        AttestationMetadata::Packed { aaguid } | AttestationMetadata::Tpm { aaguid, .. } => {
            Some(*aaguid)
        }
        _ => None,
    }
}

fn transports_of(credential: &Credential) -> Vec<String> {
    credential
        .transports
        .as_ref()
        .map(|list| list.iter().filter_map(enum_text).take(8).collect())
        .unwrap_or_default()
}

/// The serde string form of a unit enum (`"packed"`, `"usb"`…), bounded.
fn enum_text<T: Serialize>(value: &T) -> Option<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|s| !s.is_empty() && s.len() <= 32)
}
