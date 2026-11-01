//! Factor enrollment (MFA-01, MFA-05, MFA-06, MFA-07): a factor is created
//! `pending` and becomes `active` only after a valid code proves possession
//! of the authenticator app, the mailbox or the phone.

use authn_core::domain::{FactorKind, Principal};
use authn_core::error::{AuthError, codes as error_codes};
use authn_core::http::RequestContext;
use authn_core::id::{FactorId, RecoveryCodeBatchId, UserId};
use authn_core::ports::{NotificationKind, RevocationReason, SecurityEventKind};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::envelope::EnvelopeContext;
use authn_crypto::otp::OtpCode;
use authn_crypto::secret::SecretBytes;
use authn_crypto::totp::TotpSecret;
use authn_store::{
    CodeVerification, OneTimeTokenRepository, TokenPurpose, TokenSubject, UserRecord,
};
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::codes::{SendReason, code_factor_id};
use super::{
    CodeDelivery, ConfirmedFactor, GeneratedRecoveryCodes, MfaService, TotpEnrollment, after,
    locked_error, normalize_label, summary,
};
use crate::metrics;
use crate::phone::parse_allowed_phone;
use crate::recovery::{RecoveryCode, generate_batch};
use crate::store::factors::{self, FactorRecord, FactorStatus, NewFactor};
use crate::store::{recovery, settings, trusted};
use crate::totp::{provisioning, totp_for, totp_from_config};

/// Table / column of the sealed TOTP secret (CRY-08 AAD).
pub(super) const SECRET_TABLE: &str = "mfa_factors";
/// Column of the sealed TOTP secret.
pub(super) const SECRET_COLUMN: &str = "secret_ciphertext";

impl MfaService {
    /// Starts a TOTP enrollment (MFA-01): a fresh 160-bit secret, sealed
    /// with AAD = `mfa_factors/secret_ciphertext/<factor id>`, stored as a
    /// pending factor (replacing an abandoned pending TOTP enrollment).
    /// Returns the secret, the `otpauth://` URI and the QR code once.
    /// Requires step-up.
    pub async fn begin_totp_enrollment(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        label: Option<String>,
    ) -> Result<TotpEnrollment, AuthError> {
        let user = self.step_up_user(principal)?;
        let label = normalize_label(label)?;
        let totp = totp_from_config(&self.config().totp)?;
        let params = totp.params();
        let digits = i16::try_from(params.digits)
            .map_err(|_| AuthError::internal("mfa.totp.digits out of range"))?;
        let period = i16::try_from(params.period)
            .map_err(|_| AuthError::internal("mfa.totp.period out of range"))?;
        let now = self.now();

        let mut tx = self.begin().await?;
        self.lock_settings(&mut tx, user).await?;
        let account = self.user_record(&mut tx, user).await?;
        factors::delete_pending_of_kind(&mut tx, user, FactorKind::Totp).await?;
        self.check_factor_limit(&mut tx, user).await?;

        let id = FactorId::generate();
        let secret = TotpSecret::generate()?;
        let sealed = self
            .deps()
            .envelopes
            .seal(secret.expose(), &secret_context(id)?)
            .await?;
        factors::insert(
            &mut tx,
            &NewFactor {
                id,
                user_id: user,
                kind: FactorKind::Totp,
                label: label.as_deref(),
                secret_ciphertext: Some(&sealed),
                totp_digits: Some(digits),
                totp_period: Some(period),
                phone_e164: None,
                created_at: now,
            },
        )
        .await?;
        let account_label = account.email.clone().unwrap_or_else(|| user.to_string());
        let material = provisioning(&totp, &secret, &self.config().totp.issuer, &account_label)?;
        let record = factors::lock(&mut tx, user, id)
            .await?
            .ok_or_else(|| AuthError::internal("inserted factor not found"))?;
        authn_store::commit(tx).await?;
        tracing::info!(
            request_id = %ctx.request_id,
            user_id = %user,
            factor_id = %id,
            "TOTP enrollment started"
        );
        Ok(TotpEnrollment {
            factor: summary(&record, None, now),
            provisioning: material,
            expires_at: after(now, self.config().enrollment_ttl)?,
        })
    }

    /// Starts the e-mail OTP factor (MFA-05) on the account address and
    /// sends a confirmation code. Re-sends for a still-pending enrollment.
    /// Requires step-up.
    pub async fn begin_email_enrollment(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
    ) -> Result<CodeDelivery, AuthError> {
        let user = self.step_up_user(principal)?;
        if !self.email_available() {
            return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        self.lock_settings(&mut tx, user).await?;
        let account = self.user_record(&mut tx, user).await?;
        if super::recipient(&account).is_none() {
            return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
        }
        let existing = factors::list(&mut *tx, user)
            .await?
            .into_iter()
            .find(|f| f.kind == FactorKind::Email);
        let factor = match existing {
            Some(f) if f.status == FactorStatus::Active => {
                return Err(AuthError::new(
                    error_codes::mfa::MFA_FACTOR_ALREADY_ENROLLED,
                ));
            }
            Some(f) if !self.enrollment_expired(&f, now)? => f.id,
            stale => {
                if stale.is_some() {
                    factors::delete_pending_of_kind(&mut tx, user, FactorKind::Email).await?;
                }
                self.check_factor_limit(&mut tx, user).await?;
                let id = FactorId::generate();
                factors::insert(
                    &mut tx,
                    &NewFactor {
                        id,
                        user_id: user,
                        kind: FactorKind::Email,
                        label: None,
                        secret_ciphertext: None,
                        totp_digits: None,
                        totp_period: None,
                        phone_e164: None,
                        created_at: now,
                    },
                )
                .await?;
                id
            }
        };
        // Limits are checked inside the user's lock so that concurrent
        // requests cannot pass the cooldown together.
        self.email_send_limits(user).await?;
        let delivery = self
            .issue_email_code(&mut tx, ctx, &account, factor, None, SendReason::Enrollment)
            .await?;
        authn_store::commit(tx).await?;
        Ok(delivery)
    }

    /// Starts an SMS factor (MFA-06): strict E.164, country allow-list,
    /// pumping limits, then a `phone_verification` code. The number becomes
    /// a factor only after the code is confirmed. Requires step-up.
    pub async fn begin_sms_enrollment(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        phone: &str,
        label: Option<String>,
    ) -> Result<CodeDelivery, AuthError> {
        let user = self.step_up_user(principal)?;
        if !self.sms_available() {
            return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
        }
        let phone = parse_allowed_phone(phone, &self.config().sms.allowed_country_codes)?;
        let label = normalize_label(label)?;
        let now = self.now();

        let mut tx = self.begin().await?;
        self.lock_settings(&mut tx, user).await?;
        let sms_factors: Vec<FactorRecord> = factors::list(&mut *tx, user)
            .await?
            .into_iter()
            .filter(|f| f.kind == FactorKind::Sms)
            .collect();
        let same_number = sms_factors
            .iter()
            .find(|f| f.phone_e164.as_deref() == Some(phone.as_str()));
        let reuse = match same_number {
            Some(f) if f.status == FactorStatus::Active => {
                return Err(AuthError::new(
                    error_codes::mfa::MFA_FACTOR_ALREADY_ENROLLED,
                ));
            }
            Some(f) if !self.enrollment_expired(f, now)? => Some(f.id),
            _ => None,
        };
        // Every other refusal (factor limit included) comes first: the
        // pumping limits consume budget (global daily budget included) and
        // run last, right before the code is stored and queued. A refused
        // request rolls the transaction back, so nothing is stored or sent.
        let factor = if let Some(id) = reuse {
            id
        } else {
            // One pending SMS enrollment at a time.
            factors::delete_pending_of_kind(&mut tx, user, FactorKind::Sms).await?;
            self.check_factor_limit(&mut tx, user).await?;
            let id = FactorId::generate();
            factors::insert(
                &mut tx,
                &NewFactor {
                    id,
                    user_id: user,
                    kind: FactorKind::Sms,
                    label: label.as_deref(),
                    secret_ciphertext: None,
                    totp_digits: None,
                    totp_period: None,
                    phone_e164: Some(phone.as_str()),
                    created_at: now,
                },
            )
            .await?;
            id
        };
        self.sms_send_limits(ctx, user, &phone).await?;
        let delivery = self
            .issue_sms_code(
                &mut tx,
                ctx,
                user,
                factor,
                &phone,
                None,
                SendReason::Enrollment,
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(delivery)
    }

    /// Sends a new confirmation code for a pending e-mail or SMS factor
    /// (subject to the cooldown and pumping limits). Requires step-up.
    pub async fn resend_enrollment_code(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        factor_id: FactorId,
    ) -> Result<CodeDelivery, AuthError> {
        let user = self.step_up_user(principal)?;
        let now = self.now();
        let mut tx = self.begin().await?;
        self.lock_settings(&mut tx, user).await?;
        let factor = self.pending_factor(&mut tx, user, factor_id, now).await?;
        let delivery = match factor.kind {
            FactorKind::Email => {
                if !self.email_available() {
                    return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
                }
                let account = self.user_record(&mut tx, user).await?;
                self.email_send_limits(user).await?;
                self.issue_email_code(
                    &mut tx,
                    ctx,
                    &account,
                    factor.id,
                    None,
                    SendReason::Enrollment,
                )
                .await?
            }
            FactorKind::Sms => {
                if !self.sms_available() {
                    return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE));
                }
                let phone = stored_phone(&factor)?;
                self.sms_send_limits(ctx, user, &phone).await?;
                self.issue_sms_code(
                    &mut tx,
                    ctx,
                    user,
                    factor.id,
                    &phone,
                    None,
                    SendReason::Enrollment,
                )
                .await?
            }
            FactorKind::Totp | FactorKind::RecoveryCode | FactorKind::Webauthn => {
                return Err(AuthError::new(error_codes::common::VALIDATION_FAILED)
                    .with_context("TOTP enrollments have no code to resend"));
            }
        };
        authn_store::commit(tx).await?;
        Ok(delivery)
    }

    /// Confirms a pending factor with a code (TOTP from the app, or the
    /// e-mail / SMS code) and activates it (MFA-01, MFA-05, MFA-06). With
    /// the user's first factor, recovery codes are generated and returned
    /// once (MFA-04). Notification + audit (MFA-07). Requires step-up.
    ///
    /// Failed confirmations count against the pending factor; at
    /// `mfa.max_failed_attempts` the pending enrollment is discarded.
    pub async fn confirm_enrollment(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        factor_id: FactorId,
        code: &SecretString,
    ) -> Result<ConfirmedFactor, AuthError> {
        let user = self.step_up_user(principal)?;
        let now = self.now();
        // Pre-check without locks: unknown / foreign / non-pending ids fail
        // before any code is evaluated.
        let preview = factors::list(self.pool(), user)
            .await?
            .into_iter()
            .find(|f| f.id == factor_id)
            .ok_or_else(|| AuthError::new(error_codes::common::NOT_FOUND))?;
        if preview.status != FactorStatus::Pending || self.enrollment_expired(&preview, now)? {
            return Err(AuthError::new(error_codes::mfa::MFA_ENROLLMENT_NOT_PENDING));
        }
        if let Some(until) = preview.locked_until.filter(|t| *t > now) {
            return Err(locked_error(now, until));
        }
        // E-mail / SMS codes are verified (atomically, with their own
        // attempt counter) before the user's lock is taken: the store
        // verification commits its own transaction.
        let code_outcome = match preview.kind {
            FactorKind::Email => Some(
                self.check_enrollment_code(user, TokenPurpose::MfaEmailOtp, factor_id, code, now)
                    .await?,
            ),
            FactorKind::Sms => Some(
                self.check_enrollment_code(
                    user,
                    TokenPurpose::PhoneVerification,
                    factor_id,
                    code,
                    now,
                )
                .await?,
            ),
            _ => None,
        };

        let mut tx = self.begin().await?;
        self.lock_settings(&mut tx, user).await?;
        let factor = self.pending_factor(&mut tx, user, factor_id, now).await?;
        if let Some(until) = factor.locked_until.filter(|t| *t > now) {
            return Err(locked_error(now, until));
        }
        let accepted_step = match factor.kind {
            FactorKind::Totp => self.check_totp_confirmation(&factor, code, now).await?,
            _ => code_outcome.unwrap_or(None).map(|()| None),
        };
        let Some(step) = accepted_step else {
            // Wrong code: count it; discard the enrollment at the limit.
            let lock_until = after(now, self.config().lockout_duration)?;
            let max = i32::try_from(self.config().max_failed_attempts).unwrap_or(i32::MAX);
            let engaged = factors::record_failure(&mut tx, factor.id, max, lock_until).await?;
            let mut event = self
                .event(SecurityEventKind::MfaFailed, ctx, user)
                .failed("invalid_enrollment_code")
                .with_resource("mfa_factor", factor.id)
                .with_meta("factor", factor.kind.as_str())
                .with_meta("stage", "enrollment");
            if engaged.is_some() {
                factors::delete(&mut tx, user, factor.id).await?;
                event = event.with_meta("enrollment_discarded", true);
            }
            self.deps().audit.record_in_tx(&mut tx, event).await?;
            authn_store::commit(tx).await?;
            // The pending enrollment is gone: the user may start a new one
            // right away (contracts §8: every 429 carries `Retry-After`).
            return Err(match engaged {
                Some(_) => locked_error(now, now),
                None => AuthError::new(error_codes::common::INVALID_CODE),
            });
        };
        if !factors::activate(&mut tx, factor.id, now, step).await? {
            return Err(AuthError::new(error_codes::mfa::MFA_ENROLLMENT_NOT_PENDING));
        }
        let account = self.user_record(&mut tx, user).await?;
        let record = factors::lock(&mut tx, user, factor.id)
            .await?
            .ok_or_else(|| AuthError::internal("activated factor not found"))?;
        let view = summary(&record, account.email.as_deref(), now);
        // Audit is the last statement of the transaction.
        let recovery_codes = self
            .after_activation(&mut tx, ctx, &account, &factor, now)
            .await?;
        authn_store::commit(tx).await?;
        metrics::enrolled(factor.kind.as_str());
        Ok(ConfirmedFactor {
            factor: view,
            recovery_codes,
        })
    }

    /// Effects of a newly active factor, in the caller's transaction:
    /// MFA preference on, first recovery codes, trusted devices revoked
    /// (MFA change, MFA-09), notification, audit (last statement).
    async fn after_activation(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        account: &UserRecord,
        factor: &FactorRecord,
        now: OffsetDateTime,
    ) -> Result<Option<GeneratedRecoveryCodes>, AuthError> {
        let user = account.id;
        settings::set_enabled(conn, user, true).await?;
        let codes = if recovery::status(&mut *conn, user).await?.total == 0 {
            Some(self.store_new_recovery_codes(conn, user, now).await?)
        } else {
            None
        };
        trusted::revoke_all(conn, user, RevocationReason::MfaChanged.as_str(), now).await?;
        self.notify_user(
            conn,
            ctx,
            account,
            NotificationKind::MfaFactorAdded {
                factor: factor.kind,
                at: now,
            },
        )
        .await?;
        let event = self
            .event(SecurityEventKind::MfaFactorAdded, ctx, user)
            .with_resource("mfa_factor", factor.id)
            .with_meta("factor", factor.kind.as_str())
            .with_meta("recovery_codes_generated", codes.is_some());
        self.deps().audit.record_in_tx(conn, event).await?;
        Ok(codes)
    }

    /// Generates and stores a new batch of recovery codes (MFA-04),
    /// replacing every previous code.
    pub(super) async fn store_new_recovery_codes(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<GeneratedRecoveryCodes, AuthError> {
        let count = usize::try_from(self.config().recovery_codes.count)
            .map_err(|_| AuthError::internal("recovery code count"))?;
        let batch = generate_batch(count)?;
        let hashes: Vec<[u8; 32]> = batch
            .iter()
            .map(|code| self.inner.recovery_hasher.hash(user, code))
            .collect();
        recovery::replace(conn, user, RecoveryCodeBatchId::generate(), &hashes, now).await?;
        Ok(GeneratedRecoveryCodes {
            codes: batch.iter().map(RecoveryCode::display).collect(),
            generated_at: now,
        })
    }

    /// Verifies a TOTP enrollment code (no previous step: any step of the
    /// window is fresh). Returns the accepted step.
    async fn check_totp_confirmation(
        &self,
        factor: &FactorRecord,
        code: &SecretString,
        now: OffsetDateTime,
    ) -> Result<Option<Option<i64>>, AuthError> {
        let (secret, totp) = self.open_totp(factor).await?;
        let step = totp.verify(&secret, code.expose_secret().trim(), now, None)?;
        Ok(step
            .map(|s| i64::try_from(s).map_err(|_| AuthError::internal("TOTP step out of range")))
            .transpose()?
            .map(Some))
    }

    /// Verifies an e-mail / SMS enrollment code against `one_time_tokens`
    /// (own transaction, per-code attempt limit). `Some(())` only when the
    /// code is correct *and* was issued for `factor`.
    async fn check_enrollment_code(
        &self,
        user: UserId,
        purpose: TokenPurpose,
        factor: FactorId,
        code: &SecretString,
        now: OffsetDateTime,
    ) -> Result<Option<()>, AuthError> {
        let Ok(code) = OtpCode::parse(code.expose_secret()) else {
            return Ok(None);
        };
        let hash = self.deps().otp.hash(purpose.as_str(), &code);
        let outcome = OneTimeTokenRepository::verify_code(
            self.pool(),
            purpose,
            TokenSubject::user(user),
            &hash,
            now,
        )
        .await?;
        Ok(match outcome {
            // Enrollment codes are never bound to a login challenge.
            CodeVerification::Verified(record)
                if record.challenge_id.is_none() && code_factor_id(&record) == Some(factor) =>
            {
                Some(())
            }
            _ => None,
        })
    }

    /// Opens the sealed TOTP secret of a factor.
    pub(super) async fn open_totp(
        &self,
        factor: &FactorRecord,
    ) -> Result<(TotpSecret, authn_crypto::totp::Totp), AuthError> {
        let sealed = factor
            .secret_ciphertext
            .as_deref()
            .ok_or_else(|| AuthError::internal("TOTP factor without secret"))?;
        let plain: SecretBytes = self
            .deps()
            .envelopes
            .open(sealed, &secret_context(factor.id)?)
            .await?;
        let secret = TotpSecret::from_bytes(plain)?;
        let digits = factor
            .totp_digits
            .and_then(|d| u32::try_from(d).ok())
            .ok_or_else(|| AuthError::internal("TOTP factor without digits"))?;
        let period = factor
            .totp_period
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| AuthError::internal("TOTP factor without period"))?;
        let totp = totp_for(digits, period, self.config().totp.skew_steps)?;
        Ok((secret, totp))
    }

    /// The locked pending factor `factor_id` of `user`; an expired pending
    /// factor is deleted and reported as not pending.
    async fn pending_factor(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        factor_id: FactorId,
        now: OffsetDateTime,
    ) -> Result<FactorRecord, AuthError> {
        let factor = factors::lock(conn, user, factor_id)
            .await?
            .ok_or_else(|| AuthError::new(error_codes::common::NOT_FOUND))?;
        if factor.status != FactorStatus::Pending {
            return Err(AuthError::new(error_codes::mfa::MFA_ENROLLMENT_NOT_PENDING));
        }
        if self.enrollment_expired(&factor, now)? {
            factors::delete(conn, user, factor.id).await?;
            return Err(AuthError::new(error_codes::mfa::MFA_ENROLLMENT_NOT_PENDING));
        }
        Ok(factor)
    }

    fn enrollment_expired(
        &self,
        factor: &FactorRecord,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        Ok(after(factor.created_at, self.config().enrollment_ttl)? <= now)
    }

    /// Fails when the user already has `mfa.max_factors_per_user` factors.
    async fn check_factor_limit(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<(), AuthError> {
        let count = factors::count_live(conn, user).await?;
        if count >= i64::from(self.config().max_factors_per_user) {
            return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_LIMIT_REACHED));
        }
        Ok(())
    }
}

/// AAD of a factor's sealed TOTP secret (table / column / row, CRY-08).
pub(super) fn secret_context(factor: FactorId) -> Result<EnvelopeContext, AuthError> {
    EnvelopeContext::new(SECRET_TABLE, SECRET_COLUMN, factor)
        .map_err(|e| AuthError::internal("envelope context").with_source(e))
}

/// The stored number of an SMS factor.
pub(super) fn stored_phone(
    factor: &FactorRecord,
) -> Result<authn_core::domain::PhoneNumber, AuthError> {
    factor
        .phone_e164
        .as_deref()
        .and_then(|p| authn_core::domain::PhoneNumber::parse(p).ok())
        .ok_or_else(|| AuthError::internal("SMS factor without a valid phone number"))
}
