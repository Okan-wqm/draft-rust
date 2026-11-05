//! Passkey enrollment inside a login challenge (SES-22, MFA-07, K-112).
//!
//! When the `enroll_mfa` step permits `webauthn` (a platform admin, whose
//! only permitted factor is a passkey, or an organization policy that
//! demands one), the client registers a passkey without a session:
//!
//! 1. `POST /v1/login/challenge/passkey/register/options` — only once the
//!    primary factor is verified (the challenge exists only after it) and
//!    no `verify_mfa` step is outstanding (an e-mailed mailbox proof, an
//!    existing factor or a risk confirmation always comes first), only
//!    while `enroll_mfa` is outstanding and `webauthn` is enrollable. The
//!    ceremony is bound to the user, **this** challenge and a fresh 256-bit
//!    binding token (web: `__Host-authn_passkey` cookie, native: body);
//!    the relying party (RP id, allowed origins) and the strictest AAGUID
//!    policy of every organization of the user apply (PKY-08). Per-user
//!    registration rate limit (`webauthn.registration_per_user`).
//! 2. `POST /v1/login/challenge/passkey/register/verify` — the ceremony is
//!    consumed (single use; another challenge's, another user's or a
//!    replayed ceremony is `passkey_ceremony_invalid`) and verified by
//!    `webauthn-rs`. A failure counts against the challenge. On success
//!    the passkey is stored **in the transaction that records the
//!    challenge progress** (audit `passkey.registered` with
//!    `enrollment: login_challenge`, "factor added" notification): either
//!    both commit or neither. Only then does the passkey count as the
//!    second factor of this login (`mfa_factors` gains `webauthn`, K-78;
//!    `amr` gains `hwk`/`swk`, `user`, `mfa`).

use authn_core::domain::ClientKind;
#[cfg(feature = "passkey")]
use authn_core::domain::FactorKind;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::CeremonyId;
#[cfg(feature = "passkey")]
use authn_core::ports::RequiredAction;
use authn_core::secret::SensitiveString;
use serde::Deserialize;
use utoipa::ToSchema;

use super::ChallengeOutcome;
#[cfg(feature = "passkey")]
use super::{PENDING_FACTOR, step_not_allowed};
#[cfg(feature = "passkey")]
use crate::service::{ChallengeState, record_second_factor};
use crate::service::{ClientChannel, SessionService};

/// Body of `POST /v1/login/challenge/passkey/register/verify`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyEnrollmentVerify {
    /// Ceremony id from the options response.
    pub ceremony_id: CeremonyId,
    /// Native clients: the binding token of the options response (web
    /// clients send the `__Host-authn_passkey` cookie).
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub binding_token: Option<SensitiveString>,
    /// `PublicKeyCredential` from `navigator.credentials.create()` (JSON,
    /// binary fields base64url).
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
    /// Name shown in the passkey list (1–64 characters). Default
    /// `Passkey`.
    #[serde(default)]
    pub name: Option<String>,
}

impl std::fmt::Debug for PasskeyEnrollmentVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyEnrollmentVerify")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

/// Whether `state` may enroll a passkey now: the primary factor passed
/// (implied by the challenge), no factor proof is outstanding, `enroll_mfa`
/// is outstanding and permits `webauthn`.
#[cfg(feature = "passkey")]
fn require_passkey_enrollable(state: &ChallengeState) -> Result<(), AuthError> {
    if state.required_actions.contains(&RequiredAction::VerifyMfa) {
        return Err(step_not_allowed("verify the second factor first"));
    }
    if state.required_actions.contains(&RequiredAction::EnrollMfa)
        && state.allows_factor(FactorKind::Webauthn)
    {
        Ok(())
    } else {
        Err(step_not_allowed("passkey not enrollable here"))
    }
}

impl SessionService {
    /// K-112: starts registering a passkey for the `enroll_mfa` step of a
    /// pending login. Returns the ceremony (creation options and binding
    /// token).
    #[cfg(feature = "passkey")]
    pub async fn start_challenge_passkey_enrollment(
        &self,
        ctx: &RequestContext,
        token: &str,
        client: ClientKind,
    ) -> Result<crate::login::PasskeyLoginStart, AuthError> {
        let state = self.peek_login(ctx, token, client).await?;
        require_passkey_enrollable(&state)?;
        let start = self
            .deps()
            .webauthn
            .start_challenge_registration(ctx, state.user_id, state.id)
            .await?;
        crate::metrics::login_factor("passkey_enrollment", "started");
        Ok(crate::login::PasskeyLoginStart {
            ceremony_id: start.ceremony_id,
            binding_token: start.binding_token,
            options: start.options,
            expires_at: start.expires_at,
        })
    }

    /// Without the `passkey` feature.
    #[cfg(not(feature = "passkey"))]
    pub async fn start_challenge_passkey_enrollment(
        &self,
        _ctx: &RequestContext,
        _token: &str,
        _client: ClientKind,
    ) -> Result<crate::login::PasskeyLoginStart, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }

    /// K-112: finishes the passkey registration of the `enroll_mfa` step.
    /// The passkey and the challenge progress (or the session, when nothing
    /// else is outstanding) commit together.
    #[cfg(feature = "passkey")]
    pub async fn complete_challenge_passkey_enrollment(
        &self,
        ctx: &RequestContext,
        token: &str,
        request: PasskeyEnrollmentVerify,
        client: ClientChannel,
        binding_cookie: Option<SensitiveString>,
    ) -> Result<ChallengeOutcome, AuthError> {
        let peeked = self.peek_login(ctx, token, client.kind()).await?;
        require_passkey_enrollable(&peeked)?;
        let PasskeyEnrollmentVerify {
            ceremony_id,
            binding_token,
            credential,
            name,
        } = request;
        let Some(binding_token) = binding_cookie.or(binding_token) else {
            return Err(self
                .challenge_failed(
                    &peeked,
                    AuthError::new(codes::webauthn::PASSKEY_CEREMONY_INVALID)
                        .with_context("missing binding token"),
                )
                .await);
        };
        // Consumed (and committed) before verification; no connection is
        // held while webauthn-rs verifies.
        let verified = match self
            .deps()
            .webauthn
            .verify_challenge_registration(
                ctx,
                peeked.user_id,
                peeked.id,
                &binding_token,
                authn_webauthn::RegistrationVerifyRequest {
                    ceremony_id,
                    credential,
                    name,
                },
            )
            .await
        {
            Ok(verified) if verified.user_id() == peeked.user_id => verified,
            Ok(_) => {
                crate::metrics::login_factor("passkey_enrollment", "failed");
                return Err(self
                    .challenge_failed(
                        &peeked,
                        AuthError::new(codes::webauthn::PASSKEY_CEREMONY_INVALID),
                    )
                    .await);
            }
            Err(err) => {
                crate::metrics::login_factor("passkey_enrollment", "failed");
                return Err(self.challenge_failed(&peeked, err).await);
            }
        };
        let proven = verified.amr();
        self.warm_credentials(client.kind()).await?;
        let (mut tx, mut state) = self
            .reopen_login(ctx, token, client.kind(), &peeked)
            .await?;
        let passkey = self
            .deps()
            .webauthn
            .store_enrollment_in_tx(&mut tx, ctx, verified)
            .await?;
        crate::metrics::login_factor("passkey_enrollment", "succeeded");
        // Only a stored passkey is a second factor of this login (K-78).
        state.amr = record_second_factor(
            &state.amr,
            &mut state.mfa_factors,
            state.primary_method,
            FactorKind::Webauthn,
            &proven,
        )?;
        state.metadata.remove(PENDING_FACTOR);
        state.allowed_factors.clear();
        state
            .required_actions
            .retain(|a| *a != RequiredAction::EnrollMfa);
        let data = serde_json::json!({ "passkey": passkey });
        self.advance(tx, ctx, state, client, Some(data)).await
    }

    /// Without the `passkey` feature.
    #[cfg(not(feature = "passkey"))]
    pub async fn complete_challenge_passkey_enrollment(
        &self,
        _ctx: &RequestContext,
        _token: &str,
        _request: PasskeyEnrollmentVerify,
        _client: ClientChannel,
        _binding_cookie: Option<SensitiveString>,
    ) -> Result<ChallengeOutcome, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }
}
