//! Second-factor verification for authn-session's login challenge and
//! step-up (MFA-01 … MFA-06), with per-factor and per-user attempt limits
//! (MFA-03), plus code delivery and policy evaluation (MFA-08).
//!
//! Login challenge state (`auth_challenges`, attempt counter of the
//! challenge, session issuance) belongs to authn-session; this module only
//! answers "is this proof valid for this user (and challenge)?".

use authn_core::domain::FactorKind;
use authn_core::error::{AuthError, codes as error_codes};
use authn_core::http::RequestContext;
use authn_core::id::{ChallengeId, FactorId, UserId};
use authn_core::ports::{NotificationKind, SecurityEventKind};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::otp::OtpCode;
use authn_store::{CodeVerification, OneTimeTokenRepository, TokenPurpose};
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::codes::{SendReason, code_factor_id, token_subject};
use super::enroll::stored_phone;
use super::{
    CodeDelivery, FactorProof, MfaService, OtpChannel, VerifiedFactor, after, locked_error,
};
use crate::metrics;
use crate::policy::{MfaPolicyInput, MfaRequirement, OrgMfaPolicy, evaluate};
use crate::recovery::RecoveryCode;
use crate::store::factors::{self, FactorRecord};
use crate::store::recovery;
use crate::store::settings::{self, SettingsRow};

/// Result of checking an e-mail / SMS code against `one_time_tokens`
/// (before the user's lock is taken).
enum CodeCheck {
    /// Correct code for this active factor.
    Accepted(FactorId),
    /// Wrong, expired, exhausted or foreign code.
    Rejected,
    /// Every factor of the kind is locked until.
    Locked(OffsetDateTime),
    /// No active factor of the kind.
    NoFactor,
}

/// Outcome of one attempt inside the user's lock.
enum Attempt {
    /// Verified.
    Success {
        factor: Option<FactorId>,
        recovery_remaining: Option<u32>,
    },
    /// Failed; a failure is counted on these factors (and on the user).
    Failure { factors: Vec<FactorId> },
    /// Every candidate factor is locked.
    Locked(OffsetDateTime),
}

impl MfaService {
    /// Verifies a second factor of `user` (MFA-01 … MFA-06).
    ///
    /// * `challenge` — the login challenge the e-mail / SMS code was sent
    ///   for (codes sent for a challenge only verify with it); `None` for
    ///   step-up.
    /// * Returns the RFC 8176 method references of the factor on success.
    /// * Errors: `invalid_code` (wrong / expired / unknown, counted),
    ///   `too_many_attempts` + `Retry-After` while the factor or the user is
    ///   locked (MFA-03; engaging the lock records `mfa.locked`),
    ///   `mfa_factor_not_available` when the factor kind is disabled.
    ///
    /// Concurrency: attempts of one user are serialized on the user's MFA
    /// row lock; the same TOTP step is accepted at most once (MFA-02) and a
    /// recovery code at most once (MFA-04), even under concurrent
    /// submissions.
    pub async fn verify_factor(
        &self,
        ctx: &RequestContext,
        user: UserId,
        challenge: Option<ChallengeId>,
        proof: FactorProof,
    ) -> Result<VerifiedFactor, AuthError> {
        let kind = proof.kind();
        let now = self.now();
        match kind {
            FactorKind::Email if !self.email_available() => {
                return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
            }
            FactorKind::Sms if !self.sms_available() => {
                return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
            }
            _ => {}
        }
        // Cheap pre-check: a locked user never gets a code evaluated.
        if let Some(until) = settings::find(self.pool(), user)
            .await?
            .and_then(|row| row.locked_at(now))
        {
            metrics::verification(kind.as_str(), "locked");
            return Err(locked_error(now, until));
        }
        // E-mail / SMS codes are checked first: the store verification is
        // atomic per code and commits its own transaction (its attempt
        // counter survives any rollback), so it must not run while this
        // request holds the user's row lock on another connection.
        let code_check = match &proof {
            FactorProof::EmailOtp { code } => Some(
                self.check_login_code(user, challenge, TokenPurpose::MfaEmailOtp, kind, code, now)
                    .await?,
            ),
            FactorProof::SmsOtp { code } => Some(
                self.check_login_code(user, challenge, TokenPurpose::MfaSmsOtp, kind, code, now)
                    .await?,
            ),
            FactorProof::Totp { .. } | FactorProof::RecoveryCode { .. } => None,
        };

        let mut tx = self.begin().await?;
        let current = self.lock_settings(&mut tx, user).await?;
        if let Some(until) = current.locked_at(now) {
            metrics::verification(kind.as_str(), "locked");
            return Err(locked_error(now, until));
        }
        let attempt = match (&proof, code_check) {
            (FactorProof::Totp { code, factor_id }, _) => {
                self.attempt_totp(&mut tx, user, code, *factor_id, now)
                    .await?
            }
            (FactorProof::RecoveryCode { code }, _) => {
                self.attempt_recovery(&mut tx, ctx, user, code, now).await?
            }
            (_, Some(check)) => {
                self.attempt_from_code(&mut tx, user, kind, check, now)
                    .await?
            }
            (_, None) => Attempt::Failure {
                factors: Vec::new(),
            },
        };
        match attempt {
            Attempt::Success {
                factor,
                recovery_remaining,
            } => {
                self.on_success(
                    &mut tx,
                    ctx,
                    user,
                    kind,
                    factor,
                    recovery_remaining,
                    challenge,
                    now,
                )
                .await?;
                authn_store::commit(tx).await?;
                if kind == FactorKind::RecoveryCode {
                    let event = self
                        .event(SecurityEventKind::MfaVerified, ctx, user)
                        .with_meta("factor", kind.as_str());
                    self.record_detached(event).await;
                }
                metrics::verification(kind.as_str(), "success");
                Ok(VerifiedFactor {
                    kind,
                    factor_id: factor,
                    amr: crate::amr::for_factor(kind),
                    recovery_codes_remaining: recovery_remaining,
                })
            }
            Attempt::Failure { factors: failed } => {
                let result = self
                    .on_failure(&mut tx, ctx, user, kind, &failed, &current, challenge, now)
                    .await?;
                authn_store::commit(tx).await?;
                metrics::verification(kind.as_str(), "failure");
                if let Some((until, scope)) = result {
                    let event = self
                        .event(SecurityEventKind::MfaLocked, ctx, user)
                        .failed("too_many_attempts")
                        .with_meta("factor", kind.as_str())
                        .with_meta("scope", scope)
                        .with_meta(
                            "locked_until",
                            until
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap_or_default(),
                        );
                    self.record_detached(event).await;
                    return Err(locked_error(now, until));
                }
                Err(AuthError::new(error_codes::common::INVALID_CODE))
            }
            Attempt::Locked(until) => {
                metrics::verification(kind.as_str(), "locked");
                Err(locked_error(now, until))
            }
        }
    }

    /// Sends a login / step-up code to the user's active e-mail or SMS
    /// factor (MFA-05, MFA-06). `challenge` binds the code to the login
    /// challenge. Subject to the resend cooldown, per-user budgets and (SMS)
    /// the pumping protection; refused while the user or factor is locked.
    pub async fn send_code(
        &self,
        ctx: &RequestContext,
        user: UserId,
        challenge: Option<ChallengeId>,
        channel: OtpChannel,
    ) -> Result<CodeDelivery, AuthError> {
        let now = self.now();
        let kind = match channel {
            OtpChannel::Email => FactorKind::Email,
            OtpChannel::Sms { .. } => FactorKind::Sms,
        };
        let available = match kind {
            FactorKind::Email => self.email_available(),
            _ => self.sms_available(),
        };
        if !available {
            return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
        }
        let mut tx = self.begin().await?;
        let current = self.lock_settings(&mut tx, user).await?;
        if let Some(until) = current.locked_at(now) {
            return Err(locked_error(now, until));
        }
        let candidates = factors::lock_active_of_kind(&mut tx, user, kind).await?;
        let factor = match channel {
            OtpChannel::Sms {
                factor_id: Some(id),
            } => candidates
                .into_iter()
                .find(|f| f.id == id)
                .ok_or_else(|| AuthError::new(error_codes::common::NOT_FOUND))?,
            _ => candidates
                .into_iter()
                .next()
                .ok_or_else(|| AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE))?,
        };
        if let Some(until) = factor.locked_until.filter(|t| *t > now) {
            return Err(locked_error(now, until));
        }
        let delivery = if kind == FactorKind::Email {
            let account = self.user_record(&mut tx, user).await?;
            self.email_send_limits(user).await?;
            self.issue_email_code(
                &mut tx,
                ctx,
                &account,
                factor.id,
                challenge,
                SendReason::Verification,
            )
            .await?
        } else {
            let phone = stored_phone(&factor)?;
            self.sms_send_limits(ctx, user, &phone).await?;
            self.issue_sms_code(
                &mut tx,
                ctx,
                user,
                factor.id,
                &phone,
                challenge,
                SendReason::Verification,
            )
            .await?
        };
        authn_store::commit(tx).await?;
        Ok(delivery)
    }

    /// Collects the MFA-08 policy input of `user`: active factors (+
    /// `recovery_code` while unused codes remain, + `webauthn` when the
    /// [`crate::MfaPolicySource`] reports passkeys), the user's preference,
    /// the admin flag and the deployment's available factors.
    pub async fn policy_input(
        &self,
        user: UserId,
        org_policy: Option<OrgMfaPolicy>,
        phishing_resistant_required: bool,
    ) -> Result<MfaPolicyInput, AuthError> {
        let mut conn = self.pool().acquire().await?;
        self.policy_input_excluding(
            &mut conn,
            user,
            org_policy,
            phishing_resistant_required,
            None,
        )
        .await
    }

    /// [`MfaService::policy_input`] read **through `conn`** (K-69): for
    /// module hooks that run inside another module's transaction, e.g. the
    /// server's `authn_webauthn::AccountMethodsSource::mfa_facts` while the
    /// passkey removal holds the user row lock (contracts §4: a hook reads
    /// only through the given connection; it never waits for a second
    /// pooled connection while the caller holds one, and its reads belong
    /// to the caller's transaction).
    pub async fn policy_input_in(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        org_policy: Option<OrgMfaPolicy>,
        phishing_resistant_required: bool,
    ) -> Result<MfaPolicyInput, AuthError> {
        self.policy_input_excluding(conn, user, org_policy, phishing_resistant_required, None)
            .await
    }

    /// [`evaluate`] over [`MfaService::policy_input`] (MFA-08).
    pub async fn evaluate_for_user(
        &self,
        user: UserId,
        org_policy: Option<OrgMfaPolicy>,
        phishing_resistant_required: bool,
    ) -> Result<MfaRequirement, AuthError> {
        let input = self
            .policy_input(user, org_policy, phishing_resistant_required)
            .await?;
        Ok(evaluate(&input))
    }

    /// Policy input read through `conn`, optionally as if `without` were
    /// already removed.
    pub(super) async fn policy_input_excluding(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        org_policy: Option<OrgMfaPolicy>,
        phishing_resistant_required: bool,
        without: Option<FactorId>,
    ) -> Result<MfaPolicyInput, AuthError> {
        let account = self.user_record(conn, user).await?;
        let mut enrolled: Vec<FactorKind> = factors::list(&mut *conn, user)
            .await?
            .into_iter()
            .filter(|f| f.status == crate::store::factors::FactorStatus::Active)
            .filter(|f| Some(f.id) != without)
            .map(|f| f.kind)
            .collect();
        if recovery::status(&mut *conn, user).await?.remaining > 0 {
            enrolled.push(FactorKind::RecoveryCode);
        }
        if self
            .deps()
            .policy_source
            .webauthn_factor_count(conn, user)
            .await?
            > 0
        {
            enrolled.push(FactorKind::Webauthn);
        }
        enrolled.sort();
        enrolled.dedup();
        let opted_in = settings::find(&mut *conn, user)
            .await?
            .is_some_and(|row| row.mfa_enabled);
        Ok(MfaPolicyInput {
            enrolled_factors: enrolled,
            user_opted_in: opted_in,
            org_policy,
            is_platform_admin: account.is_platform_admin,
            phishing_resistant_required,
            available_factors: Some(self.available_factors()),
        })
    }

    // --- attempts -----------------------------------------------------------

    async fn attempt_totp(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        code: &SecretString,
        only: Option<FactorId>,
        now: OffsetDateTime,
    ) -> Result<Attempt, AuthError> {
        let mut candidates = factors::lock_active_of_kind(conn, user, FactorKind::Totp).await?;
        if let Some(id) = only {
            candidates.retain(|f| f.id == id);
        }
        let (unlocked, locked_until) = split_locked(&candidates, now);
        if unlocked.is_empty() {
            return Ok(match locked_until {
                Some(until) => Attempt::Locked(until),
                None => Attempt::Failure {
                    factors: Vec::new(),
                },
            });
        }
        let code = code.expose_secret().trim();
        for factor in &unlocked {
            let (secret, totp) = self.open_totp(factor).await?;
            let last = factor.last_used_step.and_then(|s| u64::try_from(s).ok());
            if let Some(step) = totp.verify(&secret, code, now, last)? {
                let step = i64::try_from(step)
                    .map_err(|_| AuthError::internal("TOTP step out of range"))?;
                // Forward-only update (MFA-02); under the user's lock it
                // cannot lose, the condition is defence in depth.
                if factors::record_use(conn, factor.id, now, Some(step)).await? {
                    return Ok(Attempt::Success {
                        factor: Some(factor.id),
                        recovery_remaining: None,
                    });
                }
                return Ok(Attempt::Failure {
                    factors: vec![factor.id],
                });
            }
        }
        Ok(Attempt::Failure {
            factors: unlocked.iter().map(|f| f.id).collect(),
        })
    }

    async fn attempt_recovery(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        code: &SecretString,
        now: OffsetDateTime,
    ) -> Result<Attempt, AuthError> {
        let Some(code) = RecoveryCode::parse(code.expose_secret()) else {
            return Ok(Attempt::Failure {
                factors: Vec::new(),
            });
        };
        let hash = self.inner.recovery_hasher.hash(user, &code);
        if recovery::consume(conn, user, &hash, now, Some(ctx.client_ip)).await? {
            let remaining = recovery::status(&mut *conn, user).await?.remaining;
            Ok(Attempt::Success {
                factor: None,
                recovery_remaining: Some(remaining),
            })
        } else {
            Ok(Attempt::Failure {
                factors: Vec::new(),
            })
        }
    }

    async fn attempt_from_code(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        kind: FactorKind,
        check: CodeCheck,
        now: OffsetDateTime,
    ) -> Result<Attempt, AuthError> {
        match check {
            CodeCheck::Accepted(id) => {
                let factor = factors::lock(conn, user, id).await?;
                match factor {
                    Some(f)
                        if f.kind == kind
                            && f.status == crate::store::factors::FactorStatus::Active
                            && !f.is_locked(now)
                            && factors::record_use(conn, f.id, now, None).await? =>
                    {
                        Ok(Attempt::Success {
                            factor: Some(f.id),
                            recovery_remaining: None,
                        })
                    }
                    // Removed or locked meanwhile: the consumed code is void.
                    _ => Ok(Attempt::Failure {
                        factors: Vec::new(),
                    }),
                }
            }
            CodeCheck::Rejected => {
                let candidates = factors::lock_active_of_kind(conn, user, kind).await?;
                let (unlocked, _) = split_locked(&candidates, now);
                Ok(Attempt::Failure {
                    factors: unlocked.iter().map(|f| f.id).collect(),
                })
            }
            CodeCheck::Locked(until) => Ok(Attempt::Locked(until)),
            CodeCheck::NoFactor => Ok(Attempt::Failure {
                factors: Vec::new(),
            }),
        }
    }

    /// Checks an e-mail / SMS login code against `one_time_tokens` (atomic,
    /// per-code attempt limit). Runs before the user's lock is taken.
    async fn check_login_code(
        &self,
        user: UserId,
        challenge: Option<ChallengeId>,
        purpose: TokenPurpose,
        kind: FactorKind,
        code: &SecretString,
        now: OffsetDateTime,
    ) -> Result<CodeCheck, AuthError> {
        let active = factors::active_of_kind(self.pool(), user, kind).await?;
        if active.is_empty() {
            return Ok(CodeCheck::NoFactor);
        }
        let (unlocked, locked_until) = split_locked(&active, now);
        if unlocked.is_empty() {
            return Ok(match locked_until {
                Some(until) => CodeCheck::Locked(until),
                None => CodeCheck::NoFactor,
            });
        }
        let Ok(code) = OtpCode::parse(code.expose_secret()) else {
            return Ok(CodeCheck::Rejected);
        };
        let hash = self.deps().otp.hash(purpose.as_str(), &code);
        let outcome = OneTimeTokenRepository::verify_code(
            self.pool(),
            purpose,
            token_subject(user, challenge),
            &hash,
            now,
        )
        .await?;
        Ok(match outcome {
            // The store's user-only lookup (step-up, `challenge == None`)
            // also finds codes bound to a login challenge of the user; such
            // a code is only valid together with its own challenge.
            CodeVerification::Verified(record) => match code_factor_id(&record) {
                Some(id)
                    if record.challenge_id == challenge && unlocked.iter().any(|f| f.id == id) =>
                {
                    CodeCheck::Accepted(id)
                }
                _ => CodeCheck::Rejected,
            },
            CodeVerification::Invalid { .. }
            | CodeVerification::LockedOut
            | CodeVerification::NotFound => CodeCheck::Rejected,
        })
    }

    // --- outcomes -------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn on_success(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        kind: FactorKind,
        factor: Option<FactorId>,
        recovery_remaining: Option<u32>,
        challenge: Option<ChallengeId>,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        settings::reset_failures(conn, user).await?;
        let mut event = if let Some(remaining) = recovery_remaining {
            let account = self.user_record(conn, user).await?;
            self.notify_user(
                conn,
                ctx,
                &account,
                NotificationKind::RecoveryCodeUsed { remaining, at: now },
            )
            .await?;
            self.event(SecurityEventKind::RecoveryCodeUsed, ctx, user)
                .with_meta("remaining", remaining)
        } else {
            self.event(SecurityEventKind::MfaVerified, ctx, user)
                .with_meta("factor", kind.as_str())
        };
        if let Some(id) = factor {
            event = event.with_resource("mfa_factor", id);
        }
        if let Some(challenge) = challenge {
            event = event.with_meta("challenge_id", challenge.to_string());
        }
        self.deps().audit.record_in_tx(conn, event).await
    }

    /// Counts the failure on the factors and on the user; returns the lock
    /// end and its scope (`user` / `factor`) when this failure engaged a
    /// lock (MFA-03).
    #[allow(clippy::too_many_arguments)]
    async fn on_failure(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        kind: FactorKind,
        failed: &[FactorId],
        current: &SettingsRow,
        challenge: Option<ChallengeId>,
        now: OffsetDateTime,
    ) -> Result<Option<(OffsetDateTime, &'static str)>, AuthError> {
        let cfg = self.config();
        let lock_until = after(now, cfg.lockout_duration)?;
        let max = i32::try_from(cfg.max_failed_attempts).unwrap_or(i32::MAX);
        let mut factor_lock = None;
        for id in failed {
            if let Some(until) = factors::record_failure(conn, *id, max, lock_until).await? {
                factor_lock = Some(until);
            }
        }
        let user_lock = settings::record_failure(
            conn,
            user,
            current,
            now,
            cfg.per_user_failures,
            cfg.lockout_duration,
        )
        .await?;
        let mut event = self
            .event(SecurityEventKind::MfaFailed, ctx, user)
            .failed("invalid_code")
            .with_meta("factor", kind.as_str());
        if let Some(challenge) = challenge {
            event = event.with_meta("challenge_id", challenge.to_string());
        }
        self.deps().audit.record_in_tx(conn, event).await?;
        Ok(user_lock
            .map(|until| (until, "user"))
            .or(factor_lock.map(|until| (until, "factor"))))
    }
}

/// Unlocked candidates, and the earliest lock end among the locked ones.
fn split_locked(
    factors: &[FactorRecord],
    now: OffsetDateTime,
) -> (Vec<FactorRecord>, Option<OffsetDateTime>) {
    let unlocked: Vec<FactorRecord> = factors
        .iter()
        .filter(|f| !f.is_locked(now))
        .cloned()
        .collect();
    let locked_until = factors
        .iter()
        .filter_map(|f| f.locked_until.filter(|until| *until > now))
        .min();
    (unlocked, locked_until)
}
