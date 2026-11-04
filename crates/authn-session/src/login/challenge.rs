//! Completing a pending login (SES-02, SES-22, MFA-01 … MFA-09).
//!
//! A login challenge carries the outstanding steps. The order is fixed:
//!
//! 1. `verify_mfa` — a second factor from the challenge's
//!    `allowed_factors` (checked **before** any verification, contracts
//!    §15.7), or — when risk demanded it (RSK-03) — an e-mailed
//!    confirmation code;
//! 2. `enroll_mfa` — enrolling a permitted factor (the confirmation proves
//!    it);
//! 3. `change_password`, `accept_terms`, `verify_email` — only after the
//!    factor steps, so a stolen password alone can never change the
//!    password, accept terms or prove the mailbox.
//!
//! Every attempt row-locks the challenge (attempts on one challenge are
//! serialized); a wrong proof counts against the challenge
//! (`record_challenge_failure`, after the lock was released), the last one
//! burns it. When no step is left the challenge is consumed and the session
//! established in one transaction, after re-checking the account status
//! and the requested organization.

use authn_core::domain::{
    AuthMethodRef, ClientKind, FactorKind, LoginMethod, Principal, PrincipalCredential, Subject,
};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{CeremonyId, FactorId, OneTimeTokenId, SessionId};
use authn_core::ports::{
    Notification, NotificationKind, RateLimitKey, RateLimitPolicy, RequiredAction,
};
use authn_core::secret::{SecretString, SensitiveString};
use authn_crypto::otp::OtpCode;
use authn_mfa::{FactorProof, IssuedTrustedDevice, OtpChannel};
use authn_store::{
    CodeVerification, NewOneTimeToken, OneTimeTokenRepository, PgTx, TokenPurpose, TokenSubject,
    UserRepository,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use super::pipeline::{EMAIL_CONFIRMATION, ENROLL_FACTORS, recipient_of};
use crate::model::{DeviceInfo, EstablishedSession};
use crate::service::{
    ChallengeKind, ChallengeProgress, ChallengeState, ClientChannel, EstablishSession,
    SessionService, after, normalize_amr, org_mfa_policy, strictest_membership_policy,
};

/// Challenge metadata key: the user asked to trust this device after the
/// second factor (MFA-09).
const TRUST_DEVICE: &str = "trust_device";
/// Challenge metadata key: the pending factor of an enrollment (SES-22).
const PENDING_FACTOR: &str = "pending_factor";
/// Rate-limit action of the e-mailed challenge codes.
const CHALLENGE_CODE_ACTION: &str = "login_challenge_code";
/// At most this many e-mailed challenge codes per user and window.
const CHALLENGE_CODES_PER_USER: u32 = 5;
const CHALLENGE_CODE_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// A second factor submitted for a login challenge (`POST
/// /v1/login/challenge/verify`).
#[derive(Clone, Deserialize, ToSchema)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum FactorSubmission {
    /// TOTP code (MFA-01, MFA-02).
    Totp {
        /// Six-digit code.
        #[schema(value_type = String)]
        code: SecretString,
        /// Restrict to one TOTP factor.
        #[serde(default)]
        factor_id: Option<FactorId>,
        /// Trust this device afterwards (MFA-09).
        #[serde(default)]
        trust_device: bool,
    },
    /// Recovery code (MFA-04).
    RecoveryCode {
        /// `xxxxx-xxxxx`.
        #[schema(value_type = String)]
        code: SecretString,
        /// Trust this device afterwards (MFA-09).
        #[serde(default)]
        trust_device: bool,
    },
    /// E-mail OTP of an enrolled e-mail factor (MFA-05).
    Email {
        /// Six-digit code.
        #[schema(value_type = String)]
        code: SecretString,
        /// Trust this device afterwards (MFA-09).
        #[serde(default)]
        trust_device: bool,
    },
    /// SMS OTP (MFA-06).
    Sms {
        /// Six-digit code.
        #[schema(value_type = String)]
        code: SecretString,
        /// Trust this device afterwards (MFA-09).
        #[serde(default)]
        trust_device: bool,
    },
    /// The e-mailed confirmation code of a risky login (RSK-03) or of the
    /// `verify_email` step (ACC-05).
    EmailConfirmation {
        /// Six-digit code.
        #[schema(value_type = String)]
        code: SecretString,
    },
    /// A passkey assertion for a ceremony started with `POST
    /// /v1/login/challenge/passkey/options`.
    Passkey {
        /// Ceremony id.
        ceremony_id: CeremonyId,
        /// Binding token (native; web sends the `__Host-authn_passkey`
        /// cookie).
        #[serde(default)]
        #[schema(value_type = Option<String>)]
        binding_token: Option<SensitiveString>,
        /// `PublicKeyCredential` from `navigator.credentials.get()`.
        #[schema(value_type = Object)]
        credential: serde_json::Value,
        /// Trust this device afterwards (MFA-09).
        #[serde(default)]
        trust_device: bool,
    },
}

impl std::fmt::Debug for FactorSubmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactorSubmission")
            .field("method", &self.label())
            .finish_non_exhaustive()
    }
}

impl FactorSubmission {
    /// Stable label (metrics, audit).
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Totp { .. } => "totp",
            Self::RecoveryCode { .. } => "recovery_code",
            Self::Email { .. } => "email",
            Self::Sms { .. } => "sms",
            Self::EmailConfirmation { .. } => "email_confirmation",
            Self::Passkey { .. } => "passkey",
        }
    }

    /// The factor kind checked against `allowed_factors`.
    const fn kind(&self) -> FactorKind {
        match self {
            Self::Totp { .. } => FactorKind::Totp,
            Self::RecoveryCode { .. } => FactorKind::RecoveryCode,
            Self::Email { .. } | Self::EmailConfirmation { .. } => FactorKind::Email,
            Self::Sms { .. } => FactorKind::Sms,
            Self::Passkey { .. } => FactorKind::Webauthn,
        }
    }

    const fn trust_device(&self) -> bool {
        match self {
            Self::Totp { trust_device, .. }
            | Self::RecoveryCode { trust_device, .. }
            | Self::Email { trust_device, .. }
            | Self::Sms { trust_device, .. }
            | Self::Passkey { trust_device, .. } => *trust_device,
            Self::EmailConfirmation { .. } => false,
        }
    }
}

/// Where to send a challenge code (`POST /v1/login/challenge/send-code`).
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(tag = "channel", rename_all = "snake_case", deny_unknown_fields)]
pub enum SendCodeChannel {
    /// The enrolled e-mail factor (MFA-05).
    Email,
    /// An enrolled SMS factor (MFA-06).
    Sms {
        /// A specific SMS factor.
        #[serde(default)]
        factor_id: Option<FactorId>,
    },
    /// The account address, for the risk confirmation (RSK-03) or the
    /// `verify_email` step.
    EmailConfirmation,
}

/// A required action (`POST /v1/login/challenge/step`, SES-22).
#[derive(Clone, Deserialize, ToSchema)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChallengeStep {
    /// `change_password` (PWD-12).
    ChangePassword {
        /// The new password (password policy applies).
        #[schema(value_type = String)]
        new_password: SecretString,
    },
    /// `accept_terms` (ACC-11).
    AcceptTerms {
        /// Accepted documents and versions.
        #[schema(value_type = Vec<Object>)]
        accepted: Vec<authn_account::TermsAcceptance>,
    },
    /// `enroll_mfa`: start a TOTP enrollment (MFA-01).
    EnrollTotp {
        /// Optional label.
        #[serde(default)]
        label: Option<String>,
    },
    /// `enroll_mfa`: start the e-mail factor (MFA-05).
    EnrollEmail,
    /// `enroll_mfa`: start an SMS factor (MFA-06).
    EnrollSms {
        /// E.164 phone number.
        phone: String,
        /// Optional label.
        #[serde(default)]
        label: Option<String>,
    },
    /// `enroll_mfa`: confirm the pending factor with its code.
    ConfirmEnrollment {
        /// The pending factor.
        factor_id: FactorId,
        /// Code from the authenticator / message.
        #[schema(value_type = String)]
        code: SecretString,
    },
}

impl std::fmt::Debug for ChallengeStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeStep")
            .field("step", &self.label())
            .finish_non_exhaustive()
    }
}

impl ChallengeStep {
    const fn label(&self) -> &'static str {
        match self {
            Self::ChangePassword { .. } => "change_password",
            Self::AcceptTerms { .. } => "accept_terms",
            Self::EnrollTotp { .. } => "enroll_totp",
            Self::EnrollEmail => "enroll_email",
            Self::EnrollSms { .. } => "enroll_sms",
            Self::ConfirmEnrollment { .. } => "confirm_enrollment",
        }
    }
}

/// Result of a challenge step.
#[derive(Debug)]
pub enum ChallengeOutcome {
    /// More steps are outstanding.
    Pending {
        /// The challenge after this step.
        challenge: Box<ChallengeState>,
        /// Data the step returns once (TOTP secret, code destination,
        /// recovery codes).
        data: Option<serde_json::Value>,
    },
    /// Every step is done: the session.
    Established {
        /// The new session.
        session: Box<EstablishedSession>,
        /// A trusted-device token, when requested and allowed (MFA-09).
        trusted_device: Option<IssuedTrustedDevice>,
        /// Data the last step returned (recovery codes).
        data: Option<serde_json::Value>,
    },
}

fn step_not_allowed(context: &'static str) -> AuthError {
    AuthError::new(codes::session::CHALLENGE_STEP_NOT_ALLOWED).with_context(context)
}

fn factor_pending(state: &ChallengeState) -> bool {
    state.required_actions.contains(&RequiredAction::VerifyMfa)
        || state.required_actions.contains(&RequiredAction::EnrollMfa)
}

fn is_email_confirmation(state: &ChallengeState) -> bool {
    state
        .metadata
        .get(EMAIL_CONFIRMATION)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Maps a factor-module error: lockouts (`429` + `Retry-After`), rate
/// limits and server errors stay visible; anything else is the uniform
/// `invalid_code`.
fn map_factor_error(err: AuthError) -> AuthError {
    let code = err.code();
    if code == codes::common::TOO_MANY_ATTEMPTS
        || code == codes::common::RATE_LIMITED
        || code == codes::mfa::MFA_FACTOR_NOT_AVAILABLE
        || err.status().is_server_error()
    {
        err
    } else {
        AuthError::new(codes::common::INVALID_CODE)
    }
}

/// The principal a pending login acts as for the factor-module APIs that
/// require a fresh authentication (enrollment, SES-22). It never leaves
/// this module: no session or token is issued for it.
fn challenge_principal(state: &ChallengeState) -> Principal {
    Principal {
        subject: Subject::User {
            user_id: state.user_id,
        },
        credential: PrincipalCredential::SessionCookie {
            session_id: SessionId::from_uuid(state.id.as_uuid()),
        },
        active_org: None,
        amr: state.amr.clone(),
        acr: None,
        auth_time: state.first_factor_at,
        scopes: Vec::new(),
        is_platform_admin: false,
        impersonation: None,
    }
}

impl SessionService {
    /// Opens the login challenge of `token` (row lock) in a new transaction.
    async fn open_login(
        &self,
        ctx: &RequestContext,
        token: &str,
        client: ClientKind,
    ) -> Result<(PgTx, ChallengeState), AuthError> {
        let mut tx = self.begin().await?;
        let state = self
            .open_challenge(&mut tx, ctx, token, ChallengeKind::Login, client)
            .await?;
        Ok((tx, state))
    }

    /// Reads the login challenge of `token` and releases it at once: the
    /// verification of a proof (other services, other connections) never
    /// runs while this request holds a pooled connection (no pool
    /// starvation under concurrent logins). The writing phase re-opens it
    /// with [`Self::open_login`] and checks it did not move on meanwhile.
    async fn peek_login(
        &self,
        ctx: &RequestContext,
        token: &str,
        client: ClientKind,
    ) -> Result<ChallengeState, AuthError> {
        let (tx, state) = self.open_login(ctx, token, client).await?;
        if let Err(err) = tx.rollback().await {
            tracing::warn!(error = %err, "releasing a login challenge failed");
        }
        Ok(state)
    }

    /// Re-opens (row lock) a challenge read by [`Self::peek_login`]; fails
    /// with `challenge_invalid` when a concurrent request completed a step
    /// in between.
    async fn reopen_login(
        &self,
        ctx: &RequestContext,
        token: &str,
        client: ClientKind,
        peeked: &ChallengeState,
    ) -> Result<(PgTx, ChallengeState), AuthError> {
        let (tx, state) = self.open_login(ctx, token, client).await?;
        if state.id != peeked.id || state.required_actions != peeked.required_actions {
            return Err(AuthError::new(codes::session::CHALLENGE_INVALID)
                .with_context("the challenge changed concurrently"));
        }
        Ok((tx, state))
    }

    /// Counts a failed attempt after the caller released the lock; returns
    /// the error to send (`challenge_invalid` once the challenge burnt).
    async fn challenge_failed(&self, state: &ChallengeState, err: AuthError) -> AuthError {
        let left = self.record_challenge_failure(state.id).await.unwrap_or(0);
        if left == 0 && !err.status().is_server_error() {
            return AuthError::new(codes::session::CHALLENGE_INVALID)
                .with_context("attempts exhausted");
        }
        err
    }

    /// SES-02: verifies a second factor of a login challenge.
    pub async fn verify_challenge_factor(
        &self,
        ctx: &RequestContext,
        token: &str,
        submission: FactorSubmission,
        client: ClientChannel,
        binding_cookie: Option<SensitiveString>,
    ) -> Result<ChallengeOutcome, AuthError> {
        let peeked = self.peek_login(ctx, token, client.kind()).await?;
        let state = &peeked;
        let label = submission.label();
        let kind = submission.kind();
        let email_confirmation = matches!(submission, FactorSubmission::EmailConfirmation { .. });
        let completes = if state.required_actions.contains(&RequiredAction::VerifyMfa) {
            // contracts §15.7: the kind must be allowed *before* anything is
            // verified; risk confirmations and enrolled e-mail factors are
            // not interchangeable.
            if !state.allows_factor(kind) || email_confirmation != is_email_confirmation(state) {
                crate::metrics::login_factor(label, "not_allowed");
                return Err(self
                    .challenge_failed(state, step_not_allowed("factor not allowed"))
                    .await);
            }
            RequiredAction::VerifyMfa
        } else if email_confirmation
            && state
                .required_actions
                .contains(&RequiredAction::VerifyEmail)
            && !factor_pending(state)
        {
            RequiredAction::VerifyEmail
        } else {
            return Err(step_not_allowed("no factor step outstanding"));
        };
        let trust_device = submission.trust_device();
        let proven = match self
            .check_factor(ctx, state, submission, binding_cookie)
            .await
        {
            Ok(amr) => amr,
            Err(err) => {
                crate::metrics::login_factor(label, "failed");
                return Err(self.challenge_failed(state, err).await);
            }
        };
        crate::metrics::login_factor(label, "succeeded");
        self.warm_credentials(client.kind()).await?;
        let (mut tx, mut state) = self
            .reopen_login(ctx, token, client.kind(), &peeked)
            .await?;
        state.required_actions.retain(|a| *a != completes);
        if completes == RequiredAction::VerifyMfa {
            if email_confirmation {
                // A mailbox confirmation of a risky login: recorded, but it
                // is not an enrolled second factor (never `mfa`).
                state.amr =
                    normalize_amr(&[state.amr.as_slice(), &[AuthMethodRef::Email]].concat())?;
            } else {
                state.amr = normalize_amr(&authn_mfa::amr::combine(&state.amr, &proven))?;
            }
            // A policy enrollment that waited for this proof (existing
            // factor, RSK-03 confirmation) may start now.
            state.allowed_factors = match state.metadata.remove(ENROLL_FACTORS) {
                Some(kinds) => serde_json::from_value(kinds)
                    .map_err(|_| AuthError::internal("enrollable factors"))?,
                None => Vec::new(),
            };
            state.metadata.remove(EMAIL_CONFIRMATION);
            if trust_device {
                state.metadata.insert(TRUST_DEVICE.into(), true.into());
            }
        } else {
            // ACC-05: the mailbox owner proved control of the address.
            // ADR 0002: the password stored before verification was never
            // proven by the mailbox owner and is removed by this proof.
            self.deps()
                .accounts
                .confirm_mailbox_control_in_tx(
                    &mut tx,
                    Some(ctx),
                    state.user_id,
                    authn_account::MailboxProof::Passwordless,
                )
                .await?;
        }
        self.advance(tx, ctx, state, client, None).await
    }

    /// Verifies the proof; returns the methods it proved.
    async fn check_factor(
        &self,
        ctx: &RequestContext,
        state: &ChallengeState,
        submission: FactorSubmission,
        binding_cookie: Option<SensitiveString>,
    ) -> Result<Vec<AuthMethodRef>, AuthError> {
        let user = state.user_id;
        let mfa = &self.deps().mfa;
        let proof = match submission {
            FactorSubmission::Totp {
                code, factor_id, ..
            } => FactorProof::Totp { code, factor_id },
            FactorSubmission::RecoveryCode { code, .. } => FactorProof::RecoveryCode { code },
            FactorSubmission::Email { code, .. } => FactorProof::EmailOtp { code },
            FactorSubmission::Sms { code, .. } => FactorProof::SmsOtp { code },
            FactorSubmission::EmailConfirmation { code } => {
                self.check_challenge_code(state, &code).await?;
                return Ok(vec![AuthMethodRef::Email]);
            }
            FactorSubmission::Passkey {
                ceremony_id,
                binding_token,
                credential,
                ..
            } => {
                return self
                    .check_passkey_factor(
                        ctx,
                        state,
                        ceremony_id,
                        binding_cookie.or(binding_token),
                        credential,
                    )
                    .await;
            }
        };
        mfa.verify_factor(ctx, user, Some(state.id), proof)
            .await
            .map(|v| v.amr)
            .map_err(map_factor_error)
    }

    #[cfg(feature = "passkey")]
    async fn check_passkey_factor(
        &self,
        ctx: &RequestContext,
        state: &ChallengeState,
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
                    target: authn_webauthn::AuthenticationTarget::SecondFactor {
                        user_id: state.user_id,
                        challenge_id: state.id,
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
        if verified.user_id != state.user_id {
            return Err(AuthError::new(codes::common::INVALID_CODE));
        }
        Ok(verified.amr)
    }

    #[cfg(not(feature = "passkey"))]
    async fn check_passkey_factor(
        &self,
        _ctx: &RequestContext,
        _state: &ChallengeState,
        _ceremony_id: CeremonyId,
        _binding_token: Option<SensitiveString>,
        _credential: serde_json::Value,
    ) -> Result<Vec<AuthMethodRef>, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }

    /// Checks an e-mailed challenge code (`login_code`, bound to the user
    /// and the challenge; attempts counted by the store).
    pub(crate) async fn check_challenge_code(
        &self,
        state: &ChallengeState,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        self.check_login_code(state.user_id, state.id, code).await
    }

    /// [`Self::check_challenge_code`] by ids (the passwordless login runs
    /// it for unknown challenges too, against ids that never exist, so both
    /// answers cost the same — SES-19).
    pub(crate) async fn check_login_code(
        &self,
        user: authn_core::id::UserId,
        challenge: authn_core::id::ChallengeId,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let Ok(code) = OtpCode::parse(code.expose_secret()) else {
            return Err(AuthError::new(codes::common::INVALID_CODE));
        };
        let hash = self
            .deps()
            .otp
            .hash(TokenPurpose::LoginCode.as_str(), &code);
        match OneTimeTokenRepository::verify_code(
            self.pool(),
            TokenPurpose::LoginCode,
            TokenSubject::user_and_challenge(user, challenge),
            &hash,
            self.now(),
        )
        .await?
        {
            CodeVerification::Verified(_) => Ok(()),
            CodeVerification::Invalid { .. }
            | CodeVerification::LockedOut
            | CodeVerification::NotFound => Err(AuthError::new(codes::common::INVALID_CODE)),
        }
    }

    /// Creates and mails a `login_code` bound to the user and `challenge`
    /// in the caller's transaction (earlier codes of the challenge are
    /// revoked). The recipient is looked up by the caller **before** the
    /// transaction. Returns the masked destination.
    pub(crate) async fn issue_challenge_code(
        &self,
        conn: &mut sqlx::PgConnection,
        user: authn_core::id::UserId,
        (recipient, locale): (authn_core::ports::Recipient, authn_core::domain::Locale),
        challenge: authn_core::id::ChallengeId,
        challenge_expires_at: time::OffsetDateTime,
        ip: Option<std::net::IpAddr>,
    ) -> Result<String, AuthError> {
        let now = self.now();
        let settings = &self.settings().session;
        let expires_at = after(now, settings.email_code_ttl).min(challenge_expires_at);
        let code = OtpCode::generate().map_err(AuthError::from)?;
        let hash = self
            .deps()
            .otp
            .hash(TokenPurpose::LoginCode.as_str(), &code);
        OneTimeTokenRepository::create(
            conn,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: TokenPurpose::LoginCode,
                token_hash: hash,
                subject: TokenSubject::user_and_challenge(user, challenge),
                group_id: None,
                target: None,
                max_attempts: settings.email_code_max_attempts,
                metadata: serde_json::json!({}),
                created_ip: ip,
                created_at: now,
                expires_at,
            },
            true,
        )
        .await?;
        let destination = authn_core::redact::mask_email(recipient.email.as_str());
        self.deps()
            .notifier
            .notify_in_tx(
                conn,
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::LoginCode {
                        code: SensitiveString::new(code.expose().to_owned()),
                        expires_at,
                    },
                },
            )
            .await?;
        Ok(destination)
    }

    /// Sends a code for the current factor step (SES-02): the enrolled
    /// e-mail / SMS factor (authn-mfa cooldowns and budgets apply) or the
    /// e-mailed confirmation code (RSK-03, `verify_email`).
    pub async fn send_challenge_code(
        &self,
        ctx: &RequestContext,
        token: &str,
        channel: SendCodeChannel,
        client: ClientKind,
    ) -> Result<serde_json::Value, AuthError> {
        let state = self.peek_login(ctx, token, client).await?;
        match channel {
            SendCodeChannel::Email | SendCodeChannel::Sms { .. } => {
                let (kind, otp) = match channel {
                    SendCodeChannel::Sms { factor_id } => {
                        (FactorKind::Sms, OtpChannel::Sms { factor_id })
                    }
                    _ => (FactorKind::Email, OtpChannel::Email),
                };
                if !state.required_actions.contains(&RequiredAction::VerifyMfa)
                    || !state.allows_factor(kind)
                    || is_email_confirmation(&state)
                {
                    return Err(step_not_allowed("channel not allowed"));
                }
                let delivery = self
                    .deps()
                    .mfa
                    .send_code(ctx, state.user_id, Some(state.id), otp)
                    .await?;
                Ok(serde_json::to_value(delivery).map_err(|_| AuthError::internal("delivery"))?)
            }
            SendCodeChannel::EmailConfirmation => {
                let allowed = (state.required_actions.contains(&RequiredAction::VerifyMfa)
                    && is_email_confirmation(&state))
                    || (state
                        .required_actions
                        .contains(&RequiredAction::VerifyEmail)
                        && !factor_pending(&state));
                if !allowed {
                    return Err(step_not_allowed("no e-mail confirmation outstanding"));
                }
                self.deps()
                    .rate_limiter
                    .check(
                        &RateLimitKey::user(CHALLENGE_CODE_ACTION, state.user_id),
                        RateLimitPolicy::new(CHALLENGE_CODES_PER_USER, CHALLENGE_CODE_WINDOW),
                        1,
                    )
                    .await?
                    .into_result()?;
                let user = UserRepository::find_by_id(self.pool(), state.user_id)
                    .await?
                    .ok_or_else(|| AuthError::new(codes::session::CHALLENGE_INVALID))?;
                let (recipient, locale) = recipient_of(self, &user)
                    .await?
                    .ok_or_else(|| AuthError::new(codes::session::CHALLENGE_INVALID))?;
                let (mut tx, state) = self.reopen_login(ctx, token, client, &state).await?;
                let destination = self
                    .issue_challenge_code(
                        &mut tx,
                        user.id,
                        (recipient, locale),
                        state.id,
                        state.expires_at,
                        Some(ctx.client_ip),
                    )
                    .await?;
                authn_store::commit(tx).await?;
                Ok(serde_json::json!({
                    "channel": "email",
                    "destination": destination,
                }))
            }
        }
    }

    /// Starts a passkey ceremony for the second-factor step (SES-02).
    #[cfg(feature = "passkey")]
    pub async fn start_challenge_passkey(
        &self,
        ctx: &RequestContext,
        token: &str,
        client: ClientKind,
    ) -> Result<super::PasskeyLoginStart, AuthError> {
        let state = self.peek_login(ctx, token, client).await?;
        if !state.required_actions.contains(&RequiredAction::VerifyMfa)
            || !state.allows_factor(FactorKind::Webauthn)
        {
            return Err(step_not_allowed("passkey not allowed"));
        }
        let start = self
            .deps()
            .webauthn
            .start_authentication(
                ctx,
                authn_webauthn::AuthenticationTarget::SecondFactor {
                    user_id: state.user_id,
                    challenge_id: state.id,
                },
                &authn_webauthn::PasskeyPolicy::unrestricted(),
            )
            .await?;
        Ok(super::PasskeyLoginStart {
            ceremony_id: start.ceremony_id,
            binding_token: start.binding_token,
            options: start.options,
            expires_at: start.expires_at,
        })
    }

    /// Without the `passkey` feature.
    #[cfg(not(feature = "passkey"))]
    pub async fn start_challenge_passkey(
        &self,
        _ctx: &RequestContext,
        _token: &str,
        _client: ClientKind,
    ) -> Result<super::PasskeyLoginStart, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }

    /// SES-22: performs a required action.
    pub async fn complete_challenge_step(
        &self,
        ctx: &RequestContext,
        token: &str,
        step: ChallengeStep,
        client: ClientChannel,
    ) -> Result<ChallengeOutcome, AuthError> {
        let peeked = self.peek_login(ctx, token, client.kind()).await?;
        let mut state = peeked.clone();
        if state.required_actions.contains(&RequiredAction::VerifyMfa) {
            return Err(step_not_allowed("verify the second factor first"));
        }
        let enrolling = state.required_actions.contains(&RequiredAction::EnrollMfa);
        let mut data = None;
        match step {
            ChallengeStep::ChangePassword { new_password } => {
                if enrolling
                    || !state
                        .required_actions
                        .contains(&RequiredAction::ChangePassword)
                {
                    return Err(step_not_allowed("password change not outstanding"));
                }
                // Own transaction; it revokes the user's sessions with
                // `password_changed`, which keeps this challenge open.
                self.deps()
                    .passwords
                    .apply_required_password_change(ctx, state.user_id, None, &new_password)
                    .await?;
                state
                    .required_actions
                    .retain(|a| *a != RequiredAction::ChangePassword);
            }
            ChallengeStep::AcceptTerms { accepted } => {
                if enrolling
                    || !state
                        .required_actions
                        .contains(&RequiredAction::AcceptTerms)
                {
                    return Err(step_not_allowed("terms acceptance not outstanding"));
                }
                self.deps()
                    .accounts
                    .accept_terms(ctx, state.user_id, &accepted)
                    .await?;
                let still_required = match self
                    .deps()
                    .accounts
                    .assess_login_by_id(state.user_id)
                    .await?
                {
                    Some(authn_account::LoginAssessment::Allowed {
                        required_actions, ..
                    }) => required_actions.contains(&RequiredAction::AcceptTerms),
                    _ => true,
                };
                if still_required {
                    return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                        .with_context("the current terms were not all accepted"));
                }
                state
                    .required_actions
                    .retain(|a| *a != RequiredAction::AcceptTerms);
            }
            ChallengeStep::EnrollTotp { label } => {
                self.require_enrollable(&state, FactorKind::Totp)?;
                let enrollment = self
                    .deps()
                    .mfa
                    .begin_totp_enrollment(ctx, &challenge_principal(&state), label)
                    .await?;
                state.metadata.insert(
                    PENDING_FACTOR.into(),
                    serde_json::json!(enrollment.factor.id),
                );
                data = Some(serde_json::json!({
                    "factor": enrollment.factor,
                    "secret": enrollment.provisioning.secret_base32.as_str(),
                    "otpauth_uri": enrollment.provisioning.otpauth_uri.as_str(),
                    "qr_code_svg": enrollment.provisioning.qr_svg.as_str(),
                    "expires_at": enrollment.expires_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .map_err(|_| AuthError::internal("time format"))?,
                }));
            }
            ChallengeStep::EnrollEmail => {
                self.require_enrollable(&state, FactorKind::Email)?;
                let delivery = self
                    .deps()
                    .mfa
                    .begin_email_enrollment(ctx, &challenge_principal(&state))
                    .await?;
                state
                    .metadata
                    .insert(PENDING_FACTOR.into(), serde_json::json!(delivery.factor_id));
                data = Some(
                    serde_json::to_value(delivery).map_err(|_| AuthError::internal("delivery"))?,
                );
            }
            ChallengeStep::EnrollSms { phone, label } => {
                self.require_enrollable(&state, FactorKind::Sms)?;
                let delivery = self
                    .deps()
                    .mfa
                    .begin_sms_enrollment(ctx, &challenge_principal(&state), &phone, label)
                    .await?;
                state
                    .metadata
                    .insert(PENDING_FACTOR.into(), serde_json::json!(delivery.factor_id));
                data = Some(
                    serde_json::to_value(delivery).map_err(|_| AuthError::internal("delivery"))?,
                );
            }
            ChallengeStep::ConfirmEnrollment { factor_id, code } => {
                if !enrolling {
                    return Err(step_not_allowed("no enrollment outstanding"));
                }
                let pending = state
                    .metadata
                    .get(PENDING_FACTOR)
                    .and_then(|v| serde_json::from_value::<FactorId>(v.clone()).ok());
                if pending != Some(factor_id) {
                    return Err(step_not_allowed("not the factor enrolled in this sign-in"));
                }
                let confirmed = match self
                    .deps()
                    .mfa
                    .confirm_enrollment(ctx, &challenge_principal(&state), factor_id, &code)
                    .await
                {
                    Ok(c) => c,
                    Err(err) => {
                        return Err(self.challenge_failed(&state, map_factor_error(err)).await);
                    }
                };
                state.amr = normalize_amr(&authn_mfa::amr::combine(
                    &state.amr,
                    &authn_mfa::amr::for_factor(confirmed.factor.kind),
                ))?;
                state.metadata.remove(PENDING_FACTOR);
                state.allowed_factors.clear();
                state
                    .required_actions
                    .retain(|a| *a != RequiredAction::EnrollMfa);
                data = Some(serde_json::json!({
                    "factor": confirmed.factor,
                    "recovery_codes": confirmed.recovery_codes,
                }));
            }
        }
        // The step's side effects ran without a held connection; write the
        // progress under the row lock of an unchanged challenge.
        self.warm_credentials(client.kind()).await?;
        let (tx, _) = self
            .reopen_login(ctx, token, client.kind(), &peeked)
            .await?;
        self.advance(tx, ctx, state, client, data).await
    }

    fn require_enrollable(
        &self,
        state: &ChallengeState,
        kind: FactorKind,
    ) -> Result<(), AuthError> {
        if state.required_actions.contains(&RequiredAction::EnrollMfa) && state.allows_factor(kind)
        {
            Ok(())
        } else {
            Err(step_not_allowed("factor not enrollable here"))
        }
    }

    /// Saves the progress, or — when nothing is outstanding — consumes the
    /// challenge and establishes the session in the same transaction.
    async fn advance(
        &self,
        mut tx: PgTx,
        ctx: &RequestContext,
        state: ChallengeState,
        client: ClientChannel,
        data: Option<serde_json::Value>,
    ) -> Result<ChallengeOutcome, AuthError> {
        if !state.required_actions.is_empty() {
            self.update_challenge(
                &mut tx,
                state.id,
                &ChallengeProgress {
                    amr: state.amr.clone(),
                    allowed_factors: state.allowed_factors.clone(),
                    required_actions: state.required_actions.clone(),
                    metadata: state.metadata.clone(),
                },
            )
            .await?;
            authn_store::commit(tx).await?;
            return Ok(ChallengeOutcome::Pending {
                challenge: Box::new(state),
                data,
            });
        }
        let now = self.now();
        let method = state.primary_method.unwrap_or(LoginMethod::Password);
        let user = UserRepository::lock_for_update(&mut tx, state.user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::session::CHALLENGE_INVALID))?;
        // The account may have changed since the primary authentication
        // (decided from the locked row: no second connection).
        if let Some(reason) = status_denial(&user, now) {
            return Err(reason.into_error(now));
        }
        let org = match state.requested_org {
            Some(org) => Some(
                self.verify_login_org(&mut tx, ctx, user.id, org, method)
                    .await?,
            ),
            None => None,
        };
        self.consume_challenge(&mut tx, state.id).await?;
        let established = self
            .establish(
                &mut tx,
                ctx,
                EstablishSession {
                    user_id: user.id,
                    method,
                    amr: state.amr.clone(),
                    acr: None,
                    auth_time: state.first_factor_at.unwrap_or(now).min(now),
                    client,
                    remember_me: state.remember_me,
                    shared_device: state.shared_device,
                    org: org.clone(),
                    device: DeviceInfo::from_context(ctx),
                },
            )
            .await?;
        UserRepository::record_login(&mut tx, user.id, now).await?;
        let event = self
            .login_succeeded_event(ctx, &established, method)
            .with_resource("auth_challenge", state.id);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        let trusted_devices_allowed = match &org {
            Some(org) => org_mfa_policy(org.policy()).trusted_devices_allowed,
            None => strictest_membership_policy(&mut tx, user.id)
                .await?
                .is_none_or(|p| p.trusted_devices_allowed),
        };
        authn_store::commit(tx).await?;
        self.after_login(ctx, &user, method, established.session.device_id.as_deref())
            .await;
        let wants_trust = state
            .metadata
            .get(TRUST_DEVICE)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            && established.session.amr.contains(&AuthMethodRef::Mfa);
        let trusted_device = if wants_trust {
            match self
                .deps()
                .mfa
                .trust_device(ctx, user.id, trusted_devices_allowed)
                .await
            {
                Ok(device) => device,
                Err(err) => {
                    tracing::warn!(error = %err, "trusting the device failed");
                    None
                }
            }
        } else {
            None
        };
        Ok(ChallengeOutcome::Established {
            session: Box::new(established),
            trusted_device,
            data,
        })
    }
}

/// Why the account state forbids finishing a login (the status part of
/// `AccountService::assess_login`, read from the locked row).
fn status_denial(
    user: &authn_store::UserRecord,
    now: time::OffsetDateTime,
) -> Option<authn_account::DenialReason> {
    use authn_core::domain::AccountStatus;
    match user.status {
        AccountStatus::Deleted | AccountStatus::Disabled => {
            Some(authn_account::DenialReason::Disabled)
        }
        AccountStatus::Suspended => Some(authn_account::DenialReason::Suspended),
        AccountStatus::Locked => match user.locked_until {
            Some(until) if until > now => Some(authn_account::DenialReason::Locked { until }),
            _ => None,
        },
        AccountStatus::Active
        | AccountStatus::PendingVerification
        | AccountStatus::PendingDeletion => None,
    }
}
