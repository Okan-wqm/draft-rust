//! [`WebauthnService`]: every passkey use case of the system.
//!
//! | Method | Requirement | Caller |
//! |--------|-------------|--------|
//! | [`WebauthnService::start_registration`] / [`WebauthnService::finish_registration`] | PKY-01/02/03/08 | `POST /v1/me/passkeys/registration/{options,verify}` |
//! | [`WebauthnService::list_passkeys`] | PKY-04 | `GET /v1/me/passkeys` |
//! | [`WebauthnService::rename_passkey`] | PKY-04 | `PATCH /v1/me/passkeys/{passkey_id}` |
//! | [`WebauthnService::delete_passkey`] | PKY-04 | `DELETE /v1/me/passkeys/{passkey_id}` |
//! | [`WebauthnService::start_authentication`] / [`WebauthnService::finish_authentication`] | PKY-01/02/05/08 | authn-session (passkey login, second factor, step-up) |
//! | [`WebauthnService::passkey_count_in`] | MFA-07/08, PWD-11 | authn-server (`MfaPolicySource`, `LoginMethodInventory`) |
//! | [`WebauthnService::purge_expired_ceremonies`] | OPS-06 | authn-server background job |
//!
//! Transactions: ceremony consumption commits on its own before the
//! response is verified (single use even on failure); every credential
//! change runs in one transaction with its audit event and notification
//! (ARC-06). Removal and registration lock the user row
//! (`UserRepository::lock_for_update`) so they serialize with password
//! removal and identity unlinking (PWD-11, SOC-06).

#[cfg(feature = "passkey")]
mod authentication;
mod manage;
#[cfg(feature = "passkey")]
mod registration;
mod types;

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::webauthn::WebauthnConfig;
use authn_core::domain::{EmailAddress, FactorKind, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{SessionId, UserId};
use authn_core::ports::{
    Actor, AuditSink, Clock, Notification, NotificationKind, Notifier, RateLimiter, Recipient,
    SecurityEvent, SecurityEventKind,
};
use authn_store::{PgTx, UserRecord};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

pub use self::manage::PasskeyRemovalReason;
#[cfg(feature = "passkey")]
pub use self::registration::VerifiedEnrollment;
#[cfg(feature = "passkey")]
pub use self::types::{
    AuthenticatedPasskey, AuthenticationFinish, AuthenticationStart, AuthenticationTarget,
    ChallengeRegistrationStart, RegistrationIntent, RegistrationOptionsRequest, RegistrationStart,
    RegistrationVerifyRequest,
};
pub use self::types::{AuthenticationPurpose, PasskeySummary, PasskeyUsage};
use crate::hooks::{AccountMethodsSource, PasskeyPolicySource};
use crate::store::credentials::CredentialRow;
use crate::well_known::WellKnownDocuments;

/// Rate-limit action names (`RateLimitKey::action`).
pub mod actions {
    /// Registration ceremonies started, per user.
    pub const REGISTRATION_START: &str = "passkey_registration_start";
    /// Authentication ceremonies started, per client IP.
    pub const AUTHENTICATION_START_IP: &str = "passkey_authentication_start_ip";
    /// Second-factor / step-up ceremonies started, per user.
    pub const AUTHENTICATION_START_USER: &str = "passkey_authentication_start_user";
}

/// Upper bound on waiting for a row lock; a request that cannot get it in
/// time fails instead of holding a pool connection.
const LOCK_TIMEOUT_SQL: &str = "SET LOCAL lock_timeout = '5s'";

/// Ports and infrastructure the service needs.
#[derive(Clone)]
pub struct WebauthnServiceDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Rate limiter (authn-protect).
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Notifications through the outbox (authn-notify).
    pub notifier: Arc<dyn Notifier>,
    /// Security audit (authn-audit).
    pub audit: Arc<dyn AuditSink>,
    /// Other login methods / MFA facts for the "last login method" rule
    /// (implemented by the server; [`crate::PasswordOnlyMethods`] by
    /// default).
    pub account_methods: Arc<dyn AccountMethodsSource>,
    /// Organization passkey policy (PKY-08), applied to registration and to
    /// every authentication ceremony (implemented by the server;
    /// [`crate::UnrestrictedPolicySource`] by default).
    pub policy_source: Arc<dyn PasskeyPolicySource>,
}

/// Settings of the service.
#[derive(Debug, Clone)]
pub struct WebauthnServiceSettings {
    /// `[webauthn]`.
    pub webauthn: WebauthnConfig,
    /// Step-up window for adding / removing passkeys
    /// (`session.step_up_max_age`, SES-13).
    pub step_up_max_age: Duration,
    /// Trusted attestation roots (PKY-08), parsed from
    /// `webauthn.attestation_roots`.
    #[cfg(feature = "passkey")]
    pub attestation_roots: webauthn_rs::prelude::AttestationCaList,
}

impl WebauthnServiceSettings {
    /// Settings from the application configuration. Fails when an
    /// attestation root is not a valid certificate (fail-fast).
    pub fn from_app_config(config: &AppConfig) -> Result<Self, AuthError> {
        Ok(Self {
            webauthn: config.webauthn.clone(),
            step_up_max_age: config.session.step_up_max_age,
            #[cfg(feature = "passkey")]
            attestation_roots: crate::policy::trust::from_config(
                &config.webauthn.attestation_roots,
            )?,
        })
    }
}

/// The passkey service. Cheap to clone; handlers obtain it through
/// `FromRef` (see [`crate::router`]).
#[derive(Clone)]
pub struct WebauthnService {
    inner: Arc<Inner>,
}

struct Inner {
    deps: WebauthnServiceDeps,
    settings: WebauthnServiceSettings,
    #[cfg(feature = "passkey")]
    relying_party: webauthn_rs::prelude::Webauthn,
    well_known: WellKnownDocuments,
}

impl std::fmt::Debug for WebauthnService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebauthnService")
            .field("rp_id", &self.inner.settings.webauthn.rp_id)
            .finish_non_exhaustive()
    }
}

impl WebauthnService {
    /// Builds the service: validates the relying party (PKY-06) and renders
    /// the well-known documents (PKY-07). Fails fast on invalid
    /// configuration.
    pub fn new(
        deps: WebauthnServiceDeps,
        settings: WebauthnServiceSettings,
    ) -> Result<Self, AuthError> {
        #[cfg(feature = "passkey")]
        let relying_party = crate::rp::build(&settings.webauthn)?;
        let well_known = WellKnownDocuments::from_config(&settings.webauthn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                deps,
                settings,
                #[cfg(feature = "passkey")]
                relying_party,
                well_known,
            }),
        })
    }

    /// The well-known documents (serve them with
    /// [`crate::well_known_router`]; `impl FromRef<AppState> for
    /// WellKnownDocuments` can return this clone).
    #[must_use]
    pub fn well_known(&self) -> WellKnownDocuments {
        self.inner.well_known.clone()
    }

    // --- shared helpers ---------------------------------------------------

    fn deps(&self) -> &WebauthnServiceDeps {
        &self.inner.deps
    }

    #[cfg_attr(not(feature = "passkey"), allow(dead_code))]
    fn config(&self) -> &WebauthnConfig {
        &self.inner.settings.webauthn
    }

    fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    /// Begins a transaction with a bounded lock wait.
    async fn begin(&self) -> Result<PgTx, AuthError> {
        let mut tx = authn_store::begin(self.pool()).await?;
        sqlx::query(LOCK_TIMEOUT_SQL).execute(&mut *tx).await?;
        Ok(tx)
    }

    /// The acting human user (not a service account).
    fn reading_user(principal: &Principal) -> Result<UserId, AuthError> {
        principal.require_user()
    }

    /// The acting user and session for adding a passkey: rejects **every**
    /// impersonation, read-only or not (a passkey added by an administrator
    /// would remain a working login method after the impersonation ended,
    /// ADM-04), and principals without a session (API keys).
    #[cfg_attr(not(feature = "passkey"), allow(dead_code))]
    fn registering_session_user(principal: &Principal) -> Result<(UserId, SessionId), AuthError> {
        if principal.is_impersonated() {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        let user = principal.require_user()?;
        let session = principal
            .session_id()
            .ok_or_else(|| AuthError::new(codes::common::FORBIDDEN))?;
        Ok((user, session))
    }

    /// Step-up guard (SES-13).
    fn require_step_up(&self, principal: &Principal) -> Result<(), AuthError> {
        principal.require_recent_authentication(self.now(), self.inner.settings.step_up_max_age)
    }

    /// A security event about `user`, acted by `user` (or the impersonating
    /// admin), with request context.
    fn event(
        &self,
        kind: SecurityEventKind,
        ctx: &RequestContext,
        user: UserId,
        principal: Option<&Principal>,
    ) -> SecurityEvent {
        let mut event = SecurityEvent::new(kind, self.now())
            .with_context(ctx)
            .with_actor(if principal.is_some() {
                Actor::User(user)
            } else {
                Actor::Anonymous
            })
            .with_subject(user);
        if let Some(p) = principal {
            event.impersonator = p.impersonation.map(|i| i.admin_user_id);
            if let Some(org) = p.active_org {
                event = event.with_org(org);
            }
        }
        event
    }

    /// Records an event in its own transaction; failures are logged, never
    /// surfaced (the business outcome is already decided).
    #[cfg_attr(not(feature = "passkey"), allow(dead_code))]
    async fn record_detached(&self, event: SecurityEvent) {
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::error!(error = ?err, "failed to record passkey security event");
        }
    }

    /// Enqueues a "second factor added/removed" e-mail in the caller's
    /// transaction (NTF-01). Accounts without a deliverable address are
    /// skipped (logged).
    async fn notify_factor_change(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        account: &UserRecord,
        added: bool,
    ) -> Result<(), AuthError> {
        let Some(email) = account
            .email
            .as_deref()
            .and_then(|e| EmailAddress::parse(e).ok())
        else {
            tracing::warn!(user = %account.id, "passkey change notification skipped: no deliverable address");
            return Ok(());
        };
        let at = self.now();
        let kind = if added {
            NotificationKind::MfaFactorAdded {
                factor: FactorKind::Webauthn,
                at,
            }
        } else {
            NotificationKind::MfaFactorRemoved {
                factor: FactorKind::Webauthn,
                at,
            }
        };
        self.deps()
            .notifier
            .notify_in_tx(
                conn,
                Notification {
                    recipient: Recipient {
                        email,
                        user_id: Some(account.id),
                        display_name: None,
                    },
                    locale: ctx.locale,
                    kind,
                },
            )
            .await
    }

    /// Enqueues the "possibly cloned passkey" e-mail in the caller's
    /// transaction (PKY-05, K-19). The outbox notifier applies the
    /// per-recipient limit of this kind. Accounts without a deliverable
    /// address are skipped (logged).
    #[cfg_attr(not(feature = "passkey"), allow(dead_code))]
    async fn notify_clone_suspected(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<(), AuthError> {
        let account = authn_store::UserRepository::find_by_id(&mut *conn, user).await?;
        let Some((account, email)) = account.and_then(|a| {
            let email = a
                .email
                .as_deref()
                .and_then(|e| EmailAddress::parse(e).ok())?;
            Some((a, email))
        }) else {
            tracing::warn!(user = %user, "clone notification skipped: no deliverable address");
            return Ok(());
        };
        self.deps()
            .notifier
            .notify_in_tx(
                conn,
                Notification {
                    recipient: Recipient {
                        email,
                        user_id: Some(account.id),
                        display_name: None,
                    },
                    locale: ctx.locale,
                    kind: NotificationKind::PasskeyCloneSuspected { at: self.now() },
                },
            )
            .await
    }

    // --- facts for other modules -------------------------------------------

    /// Number of passkeys of `user`, read through `conn` (the caller's
    /// transaction). `login_capable_only` counts only passkeys usable for
    /// passwordless login. Used by the server's implementations of
    /// `authn_mfa::MfaPolicySource::webauthn_factor_count` (all passkeys)
    /// and `authn_password::LoginMethodInventory` (login-capable ones).
    pub async fn passkey_count_in(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        login_capable_only: bool,
    ) -> Result<u32, AuthError> {
        crate::store::credentials::count_for_user(conn, user, login_capable_only).await
    }

    /// Deletes ceremonies that expired before now (OPS-06 background job).
    /// Returns the number of rows removed; safe to run on several instances
    /// (`FOR UPDATE SKIP LOCKED`, bounded batches).
    pub async fn purge_expired_ceremonies(&self) -> Result<u64, AuthError> {
        const BATCH: i64 = 1000;
        let now = self.now();
        let mut total = 0;
        loop {
            let mut tx = authn_store::begin(self.pool()).await?;
            let removed = crate::store::ceremonies::purge_expired(&mut tx, now, BATCH).await?;
            authn_store::commit(tx).await?;
            total += removed;
            if removed < u64::try_from(BATCH).unwrap_or(u64::MAX) {
                return Ok(total);
            }
        }
    }
}

/// The public view of a stored credential.
pub(crate) fn summary(row: &CredentialRow) -> PasskeySummary {
    PasskeySummary {
        id: row.id,
        name: row.name.clone(),
        created_at: row.created_at,
        last_used_at: row.last_used_at,
        usage: row.usage(),
        user_verified: row.user_verified,
        backup_eligible: row.backup_eligible,
        backup_state: row.backup_state,
        discoverable: row.discoverable,
        aaguid: row.aaguid,
        transports: row.transports.clone(),
        attestation_format: row.attestation_format.clone(),
        clone_suspected_at: row.clone_suspected_at,
    }
}
