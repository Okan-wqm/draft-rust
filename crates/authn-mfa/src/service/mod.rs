//! [`MfaService`]: every MFA use case of the system.
//!
//! | Method | Requirement | Caller |
//! |--------|-------------|--------|
//! | [`MfaService::status`] | MFA-10 | `GET /v1/me/mfa` |
//! | [`MfaService::begin_totp_enrollment`] | MFA-01 | `POST /v1/me/mfa/totp` |
//! | [`MfaService::begin_email_enrollment`] | MFA-05 | `POST /v1/me/mfa/email` |
//! | [`MfaService::begin_sms_enrollment`] | MFA-06 | `POST /v1/me/mfa/sms` |
//! | [`MfaService::resend_enrollment_code`] | MFA-05/06 | `POST /v1/me/mfa/factors/{id}/resend` |
//! | [`MfaService::confirm_enrollment`] | MFA-01/05/06/07 | `POST /v1/me/mfa/factors/{id}/confirm` |
//! | [`MfaService::remove_factor`] | MFA-07 | `DELETE /v1/me/mfa/factors/{id}` |
//! | [`MfaService::regenerate_recovery_codes`] | MFA-04 | `POST /v1/me/mfa/recovery-codes` |
//! | [`MfaService::verify_factor`] | MFA-01…06, MFA-03 | authn-session (login challenge, step-up) |
//! | [`MfaService::send_code`] | MFA-05/06 | authn-session (login challenge, step-up) |
//! | [`MfaService::policy_input`] / [`MfaService::evaluate_for_user`] | MFA-08 | authn-session |
//! | [`MfaService::policy_input_in`] | MFA-07/08, K-69 | authn-server hooks (caller's connection) |
//! | [`MfaService::trust_device`] / [`MfaService::is_trusted_device`] | MFA-09 | authn-session |
//! | [`MfaService::revoke_trusted_devices_in_tx`] | MFA-09 | authn-session (`SessionRevoker`, logout-all), password reset via it |
//! | [`MfaService::reset_user_mfa_in_tx`] | ADM-03 | authn-admin |
//! | [`MfaService::purge_expired`] | OPS-06 | authn-server background job |
//!
//! Concurrency: every verification and every factor change of a user runs
//! under the row lock of the user's `mfa_user_settings` row (created on
//! demand), with a bounded `lock_timeout`. Counters are therefore exact,
//! a TOTP step is accepted at most once and two concurrent removals can
//! never delete the last two factors of an account that must keep MFA.

mod codes;
mod enroll;
mod manage;
mod trusted;
mod types;
mod verify;

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::mfa::MfaConfig;
use authn_core::domain::{EmailAddress, FactorKind, Principal};
use authn_core::error::{AuthError, codes as error_codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, AuditSink, Clock, Notification, NotificationKind, Notifier, RateLimitKey,
    RateLimitPolicy, RateLimiter, Recipient, SecurityEvent, SecurityEventKind, SmsSender,
};
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::kdf::KeyRing;
use authn_crypto::otp::OtpHasher;
use authn_store::{PgTx, StoreError, UserRecord, UserRepository};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

pub use self::types::{
    CodeChannel, CodeDelivery, ConfirmedFactor, FactorProof, FactorState, FactorSummary,
    GeneratedRecoveryCodes, IssuedTrustedDevice, MfaResetSummary, MfaStatus, OtpChannel,
    PurgeReport, RecoveryCodesStatus, TotpEnrollment, TrustedDeviceSummary, VerifiedFactor,
};
use crate::device_token::DeviceTokenSigner;
use crate::hooks::MfaPolicySource;
use crate::recovery::RecoveryCodeHasher;
use crate::store::factors::{FactorRecord, FactorStatus};
use crate::store::settings::{self, SettingsRow};

/// Rate-limit action names (`RateLimitKey::action`).
pub mod actions {
    /// E-mail OTP resend cooldown, per user (MFA-05).
    pub const EMAIL_COOLDOWN: &str = "mfa_email_cooldown";
    /// E-mail OTP sends, per user (MFA-05).
    pub const EMAIL_SENDS: &str = "mfa_email_sends";
    /// SMS resend cooldown, per user (MFA-06).
    pub const SMS_COOLDOWN: &str = "mfa_sms_cooldown";
    /// SMS sends per user (MFA-06).
    pub const SMS_PER_USER: &str = "mfa_sms_user";
    /// SMS sends per phone number (MFA-06).
    pub const SMS_PER_NUMBER: &str = "mfa_sms_number";
    /// SMS sends per client IP (MFA-06).
    pub const SMS_PER_IP: &str = "mfa_sms_ip";
    /// Global daily SMS budget (MFA-06).
    pub const SMS_GLOBAL: &str = "mfa_sms_global";
}

/// Upper bound on waiting for a user's MFA row lock; a request that cannot
/// get it in time answers `429` instead of holding a pool connection.
const LOCK_TIMEOUT_SQL: &str = "SET LOCAL lock_timeout = '5s'";
/// SQLSTATE `lock_not_available`.
const LOCK_NOT_AVAILABLE: &str = "55P03";
/// Longest factor label (characters, matches the `mfa_factors` CHECK).
const MAX_LABEL_CHARS: usize = 64;
/// Longest device description stored for trusted devices.
const MAX_DEVICE_NAME_CHARS: usize = 128;
/// Active trusted devices kept per user; older ones are revoked.
const MAX_TRUSTED_DEVICES: i64 = 20;

/// Ports and infrastructure the service needs.
#[derive(Clone)]
pub struct MfaServiceDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Purpose sub-keys (`CryptoServices::keys`): recovery-code hashes and
    /// trusted-device tokens (CRY-11).
    pub keys: KeyRing,
    /// Keyed OTP hashes (`CryptoServices::otp`).
    pub otp: OtpHasher,
    /// Envelope encryption of TOTP secrets (`CryptoServices::envelopes`).
    pub envelopes: EnvelopeCipher,
    /// Rate limiter (authn-protect).
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Notifications: e-mail and SMS through the outbox (authn-notify).
    pub notifier: Arc<dyn Notifier>,
    /// Security audit (authn-audit).
    pub audit: Arc<dyn AuditSink>,
    /// SMS provider status (authn-notify). `None` or an unconfigured sender
    /// disables the SMS factor (ARC-11). Codes are delivered through
    /// [`Notifier::notify_sms_in_tx`].
    pub sms: Option<Arc<dyn SmsSender>>,
    /// Organization policy and passkey facts (implemented by the server).
    pub policy_source: Arc<dyn MfaPolicySource>,
}

/// Settings of the service.
#[derive(Debug, Clone)]
pub struct MfaServiceSettings {
    /// `[mfa]`.
    pub mfa: MfaConfig,
    /// Step-up window for factor changes (`session.step_up_max_age`,
    /// SES-13).
    pub step_up_max_age: Duration,
    /// Whether passkeys are available as a factor (cargo feature `passkey`
    /// of the server). Default `true`.
    pub webauthn_available: bool,
}

impl MfaServiceSettings {
    /// Settings from the application configuration.
    #[must_use]
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            mfa: config.mfa.clone(),
            step_up_max_age: config.session.step_up_max_age,
            webauthn_available: true,
        }
    }
}

/// The MFA service. Cheap to clone; handlers obtain it through `FromRef`
/// (see [`crate::router`]).
#[derive(Clone)]
pub struct MfaService {
    inner: Arc<Inner>,
}

struct Inner {
    deps: MfaServiceDeps,
    settings: MfaServiceSettings,
    recovery_hasher: RecoveryCodeHasher,
    device_signer: DeviceTokenSigner,
}

impl std::fmt::Debug for MfaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaService")
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

impl MfaService {
    /// Builds the service (derives the purpose keys).
    pub fn new(deps: MfaServiceDeps, settings: MfaServiceSettings) -> Result<Self, AuthError> {
        let recovery_hasher = RecoveryCodeHasher::new(&deps.keys)?;
        let device_signer = DeviceTokenSigner::new(&deps.keys)?;
        Ok(Self {
            inner: Arc::new(Inner {
                deps,
                settings,
                recovery_hasher,
                device_signer,
            }),
        })
    }

    /// Factor kinds this deployment offers (MFA-08 `available_factors`).
    #[must_use]
    pub fn available_factors(&self) -> Vec<FactorKind> {
        FactorKind::ALL
            .iter()
            .copied()
            .filter(|kind| match kind {
                FactorKind::Totp | FactorKind::RecoveryCode => true,
                FactorKind::Email => self.email_available(),
                FactorKind::Sms => self.sms_available(),
                FactorKind::Webauthn => self.inner.settings.webauthn_available,
            })
            .collect()
    }

    // --- shared helpers ---------------------------------------------------

    fn deps(&self) -> &MfaServiceDeps {
        &self.inner.deps
    }

    fn config(&self) -> &MfaConfig {
        &self.inner.settings.mfa
    }

    fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    fn email_available(&self) -> bool {
        self.config().email_otp.enabled
    }

    /// SMS is offered only with the `sms` feature, a configured provider and
    /// at least one allowed country (MFA-06, ARC-11).
    fn sms_available(&self) -> bool {
        cfg!(feature = "sms")
            && !self.config().sms.allowed_country_codes.is_empty()
            && self
                .deps()
                .sms
                .as_ref()
                .is_some_and(|sender| sender.is_configured())
    }

    /// Begins a transaction with a bounded lock wait.
    async fn begin(&self) -> Result<PgTx, AuthError> {
        let mut tx = authn_store::begin(self.pool()).await?;
        sqlx::query(LOCK_TIMEOUT_SQL).execute(&mut *tx).await?;
        Ok(tx)
    }

    /// Creates and row-locks the user's settings row (serializes all MFA
    /// work of the user for the rest of the transaction).
    async fn lock_settings(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<SettingsRow, AuthError> {
        settings::lock(conn, user).await.map_err(lock_error)
    }

    /// The user row (`not_found` for unknown users).
    async fn user_record(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<UserRecord, AuthError> {
        UserRepository::find_by_id(conn, user)
            .await?
            .ok_or_else(|| AuthError::new(error_codes::common::NOT_FOUND))
    }

    /// Consumes one unit of a rate limit or fails with `rate_limited` +
    /// `Retry-After` (PRT-04).
    async fn limit(&self, key: &RateLimitKey, policy: RateLimitPolicy) -> Result<(), AuthError> {
        self.deps()
            .rate_limiter
            .check(key, policy, 1)
            .await?
            .into_result()
            .map(|_| ())
    }

    /// A security event about `user`, acted by `user`.
    fn event(&self, kind: SecurityEventKind, ctx: &RequestContext, user: UserId) -> SecurityEvent {
        SecurityEvent::new(kind, self.now())
            .with_context(ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
    }

    /// Records an event outside of a transaction; failures are logged, not
    /// propagated (the business outcome already happened).
    async fn record_detached(&self, event: SecurityEvent) {
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::error!(error = %err, "failed to record MFA security event");
        }
    }

    /// Enqueues an e-mail notification to the account address in the
    /// caller's transaction; skipped (and logged) when the stored address is
    /// unusable.
    async fn notify_user(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        account: &UserRecord,
        kind: NotificationKind,
    ) -> Result<(), AuthError> {
        let Some(recipient) = recipient(account) else {
            tracing::error!(user_id = %account.id, "stored e-mail address is unusable; MFA notification skipped");
            return Ok(());
        };
        self.deps()
            .notifier
            .notify_in_tx(
                conn,
                Notification {
                    recipient,
                    locale: ctx.locale,
                    kind,
                },
            )
            .await
    }

    /// Self-service guard for factor changes (MFA-07, SES-13): a human user
    /// with a session, not impersonated, writable, re-authenticated within
    /// `step_up_max_age`.
    fn step_up_user(&self, principal: &Principal) -> Result<UserId, AuthError> {
        let user = Self::session_user(principal)?;
        principal.require_recent_authentication(self.now(), self.inner.settings.step_up_max_age)?;
        Ok(user)
    }

    /// Guard for protective writes that need no step-up (revoking trusted
    /// devices): a human user with a session, not impersonated.
    fn session_user(principal: &Principal) -> Result<UserId, AuthError> {
        let user = principal.require_user()?;
        if principal.is_impersonated() || principal.session_id().is_none() {
            return Err(AuthError::new(error_codes::common::FORBIDDEN));
        }
        principal.require_writable()?;
        Ok(user)
    }

    /// Guard for reads: a human user with a session (read-only
    /// impersonation included, API keys refused).
    fn reading_user(principal: &Principal) -> Result<UserId, AuthError> {
        let user = principal.require_user()?;
        if principal.session_id().is_none() {
            return Err(AuthError::new(error_codes::common::FORBIDDEN));
        }
        Ok(user)
    }
}

/// `now + ttl` without overflow panics.
fn after(now: OffsetDateTime, ttl: Duration) -> Result<OffsetDateTime, AuthError> {
    time::Duration::try_from(ttl)
        .ok()
        .and_then(|d| now.checked_add(d))
        .ok_or_else(|| AuthError::internal("expiry out of range"))
}

/// `Retry-After` until `until`.
fn retry_until(now: OffsetDateTime, until: OffsetDateTime) -> Duration {
    (until - now).unsigned_abs().max(Duration::from_secs(1))
}

/// `too_many_attempts` with `Retry-After` (MFA-03).
fn locked_error(now: OffsetDateTime, until: OffsetDateTime) -> AuthError {
    AuthError::new(error_codes::common::TOO_MANY_ATTEMPTS).with_retry_after(retry_until(now, until))
}

/// Maps the errors of the first row lock of a transaction: unknown users
/// are `not_found`, an exhausted lock wait is `rate_limited`.
fn lock_error(err: StoreError) -> AuthError {
    match &err {
        StoreError::ForeignKeyViolation { .. } => {
            AuthError::new(error_codes::common::NOT_FOUND).with_source(err)
        }
        StoreError::Other(inner)
            if inner
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref()
                == Some(LOCK_NOT_AVAILABLE) =>
        {
            AuthError::new(error_codes::common::RATE_LIMITED)
                .with_retry_after(Duration::from_secs(1))
                .with_source(err)
        }
        _ => AuthError::from(err),
    }
}

/// The notification recipient of an account, if its address is usable.
fn recipient(account: &UserRecord) -> Option<Recipient> {
    account
        .email
        .as_deref()
        .and_then(|e| EmailAddress::parse(e).ok())
        .map(|email| Recipient {
            email,
            user_id: Some(account.id),
            display_name: None,
        })
}

/// Validates an optional factor label: trimmed, 1–64 characters, no control
/// or bidirectional-override characters.
fn normalize_label(label: Option<String>) -> Result<Option<String>, AuthError> {
    let Some(label) = label else {
        return Ok(None);
    };
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let invalid = trimmed.chars().count() > MAX_LABEL_CHARS
        || trimmed.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
        });
    if invalid {
        return Err(AuthError::new(error_codes::common::VALIDATION_FAILED)
            .with_details(serde_json::json!({ "fields": ["label"] })));
    }
    Ok(Some(trimmed.to_owned()))
}

/// The owner-facing view of a factor (MFA-10): never a secret, contact data
/// masked.
fn summary(
    record: &FactorRecord,
    account_email: Option<&str>,
    now: OffsetDateTime,
) -> FactorSummary {
    FactorSummary {
        id: record.id,
        kind: record.kind,
        status: match record.status {
            FactorStatus::Pending => FactorState::Pending,
            FactorStatus::Active => FactorState::Active,
        },
        label: record.label.clone(),
        phone_number: record.phone_e164.as_deref().map(mask_phone),
        email: (record.kind == FactorKind::Email)
            .then(|| account_email.map(authn_core::redact::mask_email))
            .flatten(),
        weak: record.kind.is_weak(),
        phishing_resistant: record.kind.is_phishing_resistant(),
        created_at: record.created_at,
        confirmed_at: record.confirmed_at,
        last_used_at: record.last_used_at,
        locked_until: record.locked_until.filter(|until| *until > now),
    }
}

/// Masks a stored E.164 number (`+90*******233`).
fn mask_phone(e164: &str) -> String {
    authn_core::domain::PhoneNumber::parse(e164).map_or_else(|_| "***".to_owned(), |p| p.masked())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_07_labels_are_validated() {
        assert_eq!(normalize_label(None).unwrap(), None);
        assert_eq!(normalize_label(Some("  ".into())).unwrap(), None);
        assert_eq!(
            normalize_label(Some("  Work phone ".into())).unwrap(),
            Some("Work phone".to_owned())
        );
        assert_eq!(
            normalize_label(Some("Telefonum çalışma".into())).unwrap(),
            Some("Telefonum çalışma".to_owned())
        );
        for bad in ["a\nb", "x\u{202E}gnp.exe", &"y".repeat(65), "tab\there"] {
            assert!(normalize_label(Some(bad.to_owned())).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mfa_06_phone_masking() {
        assert_eq!(mask_phone("+905551112233"), "+90*******233");
        assert_eq!(mask_phone("garbage"), "***");
    }

    #[test]
    fn mfa_03_retry_after_is_at_least_one_second() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(retry_until(now, now), Duration::from_secs(1));
        assert_eq!(
            retry_until(now, now + Duration::from_secs(90)),
            Duration::from_secs(90)
        );
        let err = locked_error(now, now + Duration::from_secs(30));
        assert_eq!(err.code(), error_codes::common::TOO_MANY_ATTEMPTS);
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }
}
