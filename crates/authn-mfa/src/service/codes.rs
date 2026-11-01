//! Issuing and delivering e-mail / SMS one-time codes (MFA-05, MFA-06),
//! including the SMS pumping protection.
//!
//! Codes are stored in `one_time_tokens` (purposes `mfa_email_otp`,
//! `mfa_sms_otp`, `phone_verification`; keyed hash only, CRY-07) with the
//! factor id in `metadata`, and delivered through the outbox
//! (`Notifier::notify_in_tx` / `notify_sms_in_tx`) in the same transaction:
//! a code exists if and only if its message is queued. A new code revokes
//! the previous ones of the same subject and purpose.

use authn_core::domain::PhoneNumber;
use authn_core::error::{AuthError, codes as error_codes};
use authn_core::http::RequestContext;
use authn_core::id::{ChallengeId, FactorId, OneTimeTokenId, UserId};
use authn_core::ports::{
    Notification, NotificationKind, RateLimitKey, RateLimitPolicy, SmsNotification,
    SmsNotificationKind,
};
use authn_core::redact::mask_email;
use authn_crypto::otp::OtpCode;
use authn_store::{
    NewOneTimeToken, OneTimeTokenRecord, OneTimeTokenRepository, TokenPurpose, TokenSubject,
    UserRecord,
};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{CodeChannel, CodeDelivery, MfaService, actions, after, recipient};
use crate::metrics;
use crate::phone::country_allowed;

/// Why a code is sent (metrics label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SendReason {
    /// Confirming a pending factor.
    Enrollment,
    /// Login challenge or step-up.
    Verification,
}

impl SendReason {
    const fn label(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::Verification => "verification",
        }
    }
}

/// The one-time-token owner: the user, plus the login challenge when given
/// (then the code can only be verified for that challenge).
pub(super) fn token_subject(user: UserId, challenge: Option<ChallengeId>) -> TokenSubject {
    match challenge {
        Some(challenge) => TokenSubject::user_and_challenge(user, challenge),
        None => TokenSubject::user(user),
    }
}

/// The factor a stored code was issued for.
pub(super) fn code_factor_id(record: &OneTimeTokenRecord) -> Option<FactorId> {
    record
        .metadata
        .get("factor_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.parse().ok())
}

impl MfaService {
    /// E-mail send limits: resend cooldown and per-user budget (MFA-05).
    pub(super) async fn email_send_limits(&self, user: UserId) -> Result<(), AuthError> {
        let cfg = &self.config().email_otp;
        self.limit(
            &RateLimitKey::user(actions::EMAIL_COOLDOWN, user),
            RateLimitPolicy::new(1, cfg.resend_cooldown),
        )
        .await?;
        self.limit(
            &RateLimitKey::user(actions::EMAIL_SENDS, user),
            cfg.sends_per_user,
        )
        .await
    }

    /// SMS pumping protection (MFA-06), checked before anything is stored
    /// or sent: country allow-list, per-user cooldown and budget, per-number
    /// and per-IP limits, then the global daily budget (last, so requests
    /// refused by a narrower limit do not burn the global budget).
    pub(super) async fn sms_send_limits(
        &self,
        ctx: &RequestContext,
        user: UserId,
        phone: &PhoneNumber,
    ) -> Result<(), AuthError> {
        let cfg = &self.config().sms;
        if !country_allowed(phone, &cfg.allowed_country_codes) {
            metrics::sms_blocked("country");
            return Err(AuthError::new(
                error_codes::mfa::MFA_PHONE_COUNTRY_NOT_ALLOWED,
            ));
        }
        let checks = [
            (
                RateLimitKey::user(actions::SMS_COOLDOWN, user),
                RateLimitPolicy::new(1, cfg.resend_cooldown),
                "cooldown",
            ),
            (
                RateLimitKey::user(actions::SMS_PER_USER, user),
                cfg.per_user,
                "per_user",
            ),
            (
                RateLimitKey::phone(actions::SMS_PER_NUMBER, phone),
                cfg.per_number,
                "per_number",
            ),
            (
                RateLimitKey::ip(actions::SMS_PER_IP, ctx.client_ip),
                cfg.per_ip,
                "per_ip",
            ),
            (
                RateLimitKey::global(actions::SMS_GLOBAL),
                cfg.global_daily_budget,
                "global",
            ),
        ];
        for (key, policy, label) in checks {
            if let Err(err) = self.limit(&key, policy).await {
                metrics::sms_blocked(label);
                if label == "global" {
                    tracing::warn!("global SMS budget exhausted; SMS codes are refused (MFA-06)");
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// Stores a fresh e-mail code for `factor` and queues the e-mail, in the
    /// caller's transaction.
    pub(super) async fn issue_email_code(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        account: &UserRecord,
        factor: FactorId,
        challenge: Option<ChallengeId>,
        reason: SendReason,
    ) -> Result<CodeDelivery, AuthError> {
        let Some(recipient) = recipient(account) else {
            return Err(AuthError::new(error_codes::mfa::MFA_FACTOR_NOT_AVAILABLE)
                .with_context("account has no usable e-mail address"));
        };
        let cfg = &self.config().email_otp;
        let now = self.now();
        let expires_at = after(now, cfg.ttl)?;
        let code = OtpCode::generate()?;
        self.store_code(
            conn,
            ctx,
            account.id,
            factor,
            challenge,
            TokenPurpose::MfaEmailOtp,
            &code,
            cfg.max_attempts,
            expires_at,
        )
        .await?;
        let destination = mask_email(recipient.email.as_str());
        self.deps()
            .notifier
            .notify_in_tx(
                conn,
                Notification {
                    recipient,
                    locale: ctx.locale,
                    kind: NotificationKind::MfaEmailCode {
                        code: code.into_sensitive(),
                        expires_at,
                    },
                },
            )
            .await?;
        metrics::code_sent("email", reason.label());
        Ok(CodeDelivery {
            factor_id: factor,
            channel: CodeChannel::Email,
            destination,
            expires_at,
        })
    }

    /// Stores a fresh SMS code for `factor` and queues the SMS, in the
    /// caller's transaction. The pumping limits must have passed already.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn issue_sms_code(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        factor: FactorId,
        phone: &PhoneNumber,
        challenge: Option<ChallengeId>,
        reason: SendReason,
    ) -> Result<CodeDelivery, AuthError> {
        let cfg = &self.config().sms;
        let now = self.now();
        let expires_at = after(now, cfg.ttl)?;
        let code = OtpCode::generate()?;
        let purpose = match reason {
            SendReason::Enrollment => TokenPurpose::PhoneVerification,
            SendReason::Verification => TokenPurpose::MfaSmsOtp,
        };
        self.store_code(
            conn,
            ctx,
            user,
            factor,
            challenge,
            purpose,
            &code,
            cfg.max_attempts,
            expires_at,
        )
        .await?;
        let code = code.into_sensitive();
        let kind = match reason {
            SendReason::Enrollment => SmsNotificationKind::PhoneVerification { code, expires_at },
            SendReason::Verification => SmsNotificationKind::MfaSmsCode { code, expires_at },
        };
        self.deps()
            .notifier
            .notify_sms_in_tx(
                conn,
                SmsNotification {
                    to: phone.clone(),
                    user_id: Some(user),
                    locale: ctx.locale,
                    kind,
                },
            )
            .await?;
        metrics::code_sent("sms", reason.label());
        Ok(CodeDelivery {
            factor_id: factor,
            channel: CodeChannel::Sms,
            destination: phone.masked(),
            expires_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn store_code(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        factor: FactorId,
        challenge: Option<ChallengeId>,
        purpose: TokenPurpose,
        code: &OtpCode,
        max_attempts: u32,
        expires_at: time::OffsetDateTime,
    ) -> Result<(), AuthError> {
        let token_hash = self.deps().otp.hash(purpose.as_str(), code);
        OneTimeTokenRepository::create(
            conn,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose,
                token_hash,
                subject: token_subject(user, challenge),
                group_id: None::<Uuid>,
                target: None,
                max_attempts,
                metadata: serde_json::json!({ "factor_id": factor.to_string() }),
                created_ip: Some(ctx.client_ip),
                created_at: self.now(),
                expires_at,
            },
            true,
        )
        .await?;
        Ok(())
    }
}
