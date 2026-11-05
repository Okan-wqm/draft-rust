//! Step-up re-authentication (SES-13).
//!
//! Sensitive operations call `principal.require_recent_authentication(now,
//! session.step_up_max_age)`; when it fails (`step_up_required`) the client
//! re-verifies here with a password (authn-password), a TOTP or recovery
//! code (authn-mfa) or a passkey (authn-webauthn). On success `auth_time`
//! becomes now, the verified methods are merged into the session `amr`
//! (`mfa` is added when a new factor joins, SES-08) and the session id is
//! rotated (SES-03).
//!
//! Rules:
//! * impersonated principals and API keys can never step up (ADM-04);
//! * platform administrators step up with a passkey only (ADM-01, MFA-08);
//! * an organization requiring phishing-resistant MFA accepts only a
//!   passkey; an organization's allowed factors restrict TOTP / recovery
//!   codes (ORG-07) — the strictest combination over the active
//!   organization and every membership of the user applies, also in the
//!   personal context (step-up guards account-wide operations);
//! * attempts are limited per user (`session.step_up_per_user`), and every
//!   failure is the uniform `reauthentication_failed` (the factor modules'
//!   own attempt limits and locks apply in addition).

use authn_core::domain::{AuthMethodRef, FactorKind, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{CeremonyId, FactorId, OrgId, UserId};
use authn_core::ports::{Actor, RateLimitKey, SecurityEvent, SecurityEventKind};
use authn_core::secret::{SecretString, SensitiveString};
use authn_mfa::{FactorProof, OrgMfaPolicy};
use authn_password::LoginPasswordOutcome;
use serde::Deserialize;
use utoipa::ToSchema;

use super::SessionService;
use super::establish::{normalize_amr, record_second_factor};
use super::issuer::{org_mfa_policy, strictest_membership_policy};
use super::manage::session_user;
use super::org_switch::PrivilegeChange;
use crate::metrics;
use crate::model::{CurrentSession, IssuedCredentials, SessionRecord};
use crate::store::sessions;

/// Rate-limit action of `POST /v1/reauth`.
pub const STEP_UP_ACTION: &str = "step_up";

/// Body of `POST /v1/reauth`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepUpProof {
    /// The account password.
    Password {
        /// Password.
        #[schema(value_type = String)]
        password: SecretString,
    },
    /// A TOTP code.
    Totp {
        /// Six-digit code.
        #[schema(value_type = String)]
        code: SecretString,
        /// Restrict to one TOTP factor.
        #[serde(default)]
        factor_id: Option<FactorId>,
    },
    /// A recovery code (MFA-04).
    RecoveryCode {
        /// Recovery code (`xxxxx-xxxxx`).
        #[schema(value_type = String)]
        code: SecretString,
    },
    /// A passkey assertion for a ceremony started with
    /// `POST /v1/reauth/passkey/options`.
    Passkey {
        /// Ceremony id.
        ceremony_id: CeremonyId,
        /// Binding token (native clients; web clients send the
        /// `__Host-authn_passkey` cookie instead).
        #[serde(default)]
        #[schema(value_type = Option<String>)]
        binding_token: Option<SensitiveString>,
        /// `PublicKeyCredential` from `navigator.credentials.get()`.
        #[schema(value_type = Object)]
        credential: serde_json::Value,
    },
}

impl StepUpProof {
    /// Stable label (metrics, audit).
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Password { .. } => "password",
            Self::Totp { .. } => "totp",
            Self::RecoveryCode { .. } => "recovery_code",
            Self::Passkey { .. } => "passkey",
        }
    }

    /// The second factor this proof is (`None` for the password).
    #[must_use]
    pub const fn factor(&self) -> Option<FactorKind> {
        match self {
            Self::Password { .. } => None,
            Self::Totp { .. } => Some(FactorKind::Totp),
            Self::RecoveryCode { .. } => Some(FactorKind::RecoveryCode),
            Self::Passkey { .. } => Some(FactorKind::Webauthn),
        }
    }
}

/// A started passkey step-up ceremony.
#[derive(Clone)]
pub struct PasskeyStepUpStart {
    /// Ceremony id.
    pub ceremony_id: CeremonyId,
    /// Binding token: web clients get it as the `__Host-authn_passkey`
    /// cookie, native clients in the body.
    pub binding_token: SensitiveString,
    /// `CredentialRequestOptions` for `navigator.credentials.get()`.
    pub options: serde_json::Value,
    /// Ceremony expiry.
    pub expires_at: time::OffsetDateTime,
}

impl std::fmt::Debug for PasskeyStepUpStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyStepUpStart")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

fn failed(context: &'static str) -> AuthError {
    AuthError::new(codes::session::REAUTHENTICATION_FAILED).with_context(context)
}

fn not_allowed(context: &'static str) -> AuthError {
    AuthError::new(codes::session::STEP_UP_METHOD_NOT_ALLOWED).with_context(context)
}

/// Maps a factor-module error to the uniform step-up failure, keeping
/// lockouts (`429` + `Retry-After`) and server errors visible.
fn map_factor_error(err: AuthError) -> AuthError {
    let code = err.code();
    if code == codes::common::TOO_MANY_ATTEMPTS
        || code == codes::common::RATE_LIMITED
        || err.status().is_server_error()
    {
        err
    } else if code == codes::mfa::MFA_FACTOR_NOT_AVAILABLE {
        not_allowed("factor not available")
    } else {
        failed("factor rejected")
    }
}

impl SessionService {
    /// Checks whether `proof` may be used by this principal / session.
    fn step_up_allowed(
        principal: &Principal,
        policy: Option<&OrgMfaPolicy>,
        proof: &StepUpProof,
    ) -> Result<(), AuthError> {
        let passkey = matches!(proof, StepUpProof::Passkey { .. });
        if principal.is_platform_admin && !passkey {
            return Err(not_allowed("platform admins step up with a passkey"));
        }
        if let Some(policy) = policy {
            if policy.phishing_resistant_required && !passkey {
                return Err(not_allowed("organization requires a passkey"));
            }
            if let Some(factor) = proof.factor()
                && policy
                    .allowed_factors
                    .as_ref()
                    .is_some_and(|list| !list.contains(&factor))
            {
                return Err(not_allowed("factor not allowed by the organization"));
            }
        }
        Ok(())
    }

    /// The organization MFA policy a step-up must satisfy: the strictest
    /// combination of the active organization and **every** active
    /// membership of the user. Step-up unlocks account-wide operations
    /// (e-mail, password, MFA factors) shared by all of the user's
    /// organizations, so a lax organization or the personal context must
    /// not let a weaker proof through than the strictest organization
    /// demands (ORG-07, MFA-08 — the login pipeline applies the same
    /// strictest combination when no organization is requested).
    async fn step_up_policy(
        &self,
        user: UserId,
        active_org: Option<OrgId>,
    ) -> Result<Option<OrgMfaPolicy>, AuthError> {
        let memberships = {
            let mut conn = self.pool().acquire().await?;
            strictest_membership_policy(&mut conn, user).await?
        };
        let active = match active_org {
            Some(org) => Some(org_mfa_policy(&self.deps().orgs.policy(org).await?)),
            None => None,
        };
        Ok(match (memberships, active) {
            (Some(a), Some(b)) => Some(a.strictest(&b)),
            (a, b) => a.or(b),
        })
    }

    /// Verifies the proof and returns the methods it proved.
    async fn verify_step_up_proof(
        &self,
        ctx: &RequestContext,
        user: UserId,
        current: &CurrentSession,
        proof: StepUpProof,
        binding_cookie: Option<SensitiveString>,
    ) -> Result<Vec<AuthMethodRef>, AuthError> {
        match proof {
            StepUpProof::Password { password } => {
                match self
                    .deps()
                    .passwords
                    .verify_login_password(ctx, Some(user), &password)
                    .await?
                {
                    LoginPasswordOutcome::Valid | LoginPasswordOutcome::MustChangePassword => {
                        Ok(vec![AuthMethodRef::Pwd])
                    }
                    LoginPasswordOutcome::Invalid => Err(failed("wrong password")),
                }
            }
            StepUpProof::Totp { code, factor_id } => self
                .deps()
                .mfa
                .verify_factor(ctx, user, None, FactorProof::Totp { code, factor_id })
                .await
                .map(|v| v.amr)
                .map_err(map_factor_error),
            StepUpProof::RecoveryCode { code } => self
                .deps()
                .mfa
                .verify_factor(ctx, user, None, FactorProof::RecoveryCode { code })
                .await
                .map(|v| v.amr)
                .map_err(map_factor_error),
            StepUpProof::Passkey {
                ceremony_id,
                binding_token,
                credential,
            } => {
                self.verify_passkey_step_up(
                    ctx,
                    user,
                    current,
                    ceremony_id,
                    binding_cookie.or(binding_token),
                    credential,
                )
                .await
            }
        }
    }

    #[cfg(feature = "passkey")]
    async fn verify_passkey_step_up(
        &self,
        ctx: &RequestContext,
        user: UserId,
        current: &CurrentSession,
        ceremony_id: CeremonyId,
        binding_token: Option<SensitiveString>,
        credential: serde_json::Value,
    ) -> Result<Vec<AuthMethodRef>, AuthError> {
        let binding_token = binding_token.ok_or_else(|| {
            AuthError::new(codes::webauthn::PASSKEY_CEREMONY_INVALID)
                .with_context("missing binding token")
        })?;
        let verified = self
            .deps()
            .webauthn
            .finish_authentication(
                ctx,
                authn_webauthn::AuthenticationFinish {
                    ceremony_id,
                    binding_token,
                    target: authn_webauthn::AuthenticationTarget::StepUp {
                        user_id: user,
                        session_id: current.record.id,
                    },
                    credential,
                },
            )
            .await
            .map_err(|e| {
                if e.code() == codes::webauthn::PASSKEY_CEREMONY_INVALID {
                    e
                } else {
                    map_factor_error(e)
                }
            })?;
        if verified.user_id != user || !verified.user_verified {
            return Err(failed(
                "passkey of another user or without user verification",
            ));
        }
        Ok(verified.amr)
    }

    #[cfg(not(feature = "passkey"))]
    async fn verify_passkey_step_up(
        &self,
        _ctx: &RequestContext,
        _user: UserId,
        _current: &CurrentSession,
        _ceremony_id: CeremonyId,
        _binding_token: Option<SensitiveString>,
        _credential: serde_json::Value,
    ) -> Result<Vec<AuthMethodRef>, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }

    /// Starts a passkey step-up ceremony bound to the current session
    /// (`webauthn_ceremonies.session_id`); finish it with
    /// [`StepUpProof::Passkey`].
    pub async fn start_passkey_step_up(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        current: &CurrentSession,
    ) -> Result<PasskeyStepUpStart, AuthError> {
        let (user, session) = session_user(principal)?;
        if principal.is_impersonated() {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        if session != current.record.id {
            return Err(AuthError::new(codes::common::UNAUTHENTICATED));
        }
        self.start_passkey_ceremony(ctx, user, session).await
    }

    #[cfg(feature = "passkey")]
    async fn start_passkey_ceremony(
        &self,
        ctx: &RequestContext,
        user: UserId,
        session: authn_core::id::SessionId,
    ) -> Result<PasskeyStepUpStart, AuthError> {
        let start = self
            .deps()
            .webauthn
            .start_authentication(
                ctx,
                authn_webauthn::AuthenticationTarget::StepUp {
                    user_id: user,
                    session_id: session,
                },
                &authn_webauthn::PasskeyPolicy::unrestricted(),
            )
            .await?;
        Ok(PasskeyStepUpStart {
            ceremony_id: start.ceremony_id,
            binding_token: start.binding_token,
            options: start.options,
            expires_at: start.expires_at,
        })
    }

    #[cfg(not(feature = "passkey"))]
    async fn start_passkey_ceremony(
        &self,
        _ctx: &RequestContext,
        _user: UserId,
        _session: authn_core::id::SessionId,
    ) -> Result<PasskeyStepUpStart, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }

    /// Re-authenticates the current session (SES-13): verifies the proof,
    /// sets `auth_time` to now, merges the `amr` and rotates the session's
    /// credentials. `binding_cookie` is the `__Host-authn_passkey` cookie of
    /// web passkey step-ups.
    pub async fn step_up(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        current: &CurrentSession,
        proof: StepUpProof,
        binding_cookie: Option<SensitiveString>,
    ) -> Result<(SessionRecord, IssuedCredentials), AuthError> {
        let (user, session_id) = session_user(principal)?;
        if principal.is_impersonated() {
            return Err(AuthError::new(codes::common::FORBIDDEN)
                .with_context("impersonation never satisfies step-up"));
        }
        if session_id != current.record.id {
            return Err(AuthError::new(codes::common::UNAUTHENTICATED));
        }
        self.deps()
            .rate_limiter
            .check(
                &RateLimitKey::user(STEP_UP_ACTION, user),
                self.settings().session.step_up_per_user,
                1,
            )
            .await?
            .into_result()?;
        let policy = self
            .step_up_policy(user, current.record.active_org_id)
            .await?;
        let label = proof.label();
        let factor = proof.factor();
        Self::step_up_allowed(principal, policy.as_ref(), &proof)?;
        let proven = match self
            .verify_step_up_proof(ctx, user, current, proof, binding_cookie)
            .await
        {
            Ok(amr) => amr,
            Err(err) => {
                metrics::step_up(label, "failed");
                let event = SecurityEvent::new(SecurityEventKind::StepUpFailed, self.now())
                    .with_context(ctx)
                    .with_actor(Actor::User(user))
                    .with_subject(user)
                    .with_resource("session", session_id)
                    .failed(err.code().code())
                    .with_meta("method", label);
                if let Err(audit_err) = self.deps().audit.record(event).await {
                    tracing::warn!(error = %audit_err, "step-up failure audit failed");
                }
                return Err(err);
            }
        };

        let now = self.now();
        let mut tx = self.begin().await?;
        let live = sessions::lock_live(&mut tx, session_id, now)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))?;
        Self::check_current_token(&mut tx, current).await?;
        let record = live.record;
        // K-78: a verified second factor is recorded (what produced `mfa`);
        // a password re-authentication is no second factor.
        let mut mfa_factors = record.mfa_factors.clone();
        let amr = match factor {
            Some(kind) => record_second_factor(
                &record.amr,
                &mut mfa_factors,
                record.login_method,
                kind,
                &proven,
            )?,
            None => normalize_amr(&authn_mfa::amr::combine(&record.amr, &proven))?,
        };
        let (updated, credentials) = self
            .apply_privilege_change(
                &mut tx,
                ctx,
                &record,
                PrivilegeChange {
                    amr: &amr,
                    mfa_factors: &mfa_factors,
                    auth_time: now,
                    active_org_id: record.active_org_id,
                    absolute_expires_at: record.absolute_expires_at,
                    presented_access_token: current.token_id,
                },
            )
            .await?;
        let event = SecurityEvent::new(SecurityEventKind::StepUpSucceeded, now)
            .with_context(ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
            .with_resource("session", session_id)
            .with_meta("method", label);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        metrics::step_up(label, "succeeded");
        Ok((updated, credentials))
    }
}
