//! Building every module service in dependency order
//! (`docs/architecture/contracts.md` §15.1 – §15.3, `crates/authn-session/README.md`).
//!
//! Order (cycles are broken by late-bound hooks, [`crate::hooks::Late`]):
//!
//! 1. crypto, rate limiter, SSRF-safe HTTP client, notifications;
//! 2. audit sink + domain-event publisher (stand-alone);
//! 3. `MfaService` → `PgSessionRevoker` → `AccountService` (plain revoker) →
//!    `AccountAwareSessionRevoker` (given to every other module);
//! 4. password, passkeys, organizations, audit service (RBAC policy);
//! 5. the late hooks are bound;
//! 6. login protection, risk, `SessionService`;
//! 7. social login (`OidcClientService`, needs the session issuer) and its
//!    account hooks (erasure: provider token revocation; e-mail change
//!    revert: every added login method is removed, K-20);
//! 8. platform admin (`AdminService`).

use std::sync::Arc;

use authn_account::{
    AccountAwareSessionRevoker, AccountService, AccountServiceDeps, AccountServiceSettings,
};
use authn_admin::{AdminService, AdminServiceDeps, AdminSettings};
use authn_audit::{AuditService, AuditServiceParts, ChainKeys, OutboxEventPublisher, PgAuditSink};
use authn_core::config::AppConfig;
use authn_core::error::AuthError;
use authn_core::ports::{
    AuditSink, BreachedPasswordChecker, Clock, DataExporter, DnsTxtResolver, EventPublisher,
    HttpClient, Notifier, RateLimiter, SessionIssuer, SessionRevoker,
};
use authn_crypto::CryptoServices;
use authn_mfa::{MfaService, MfaServiceDeps, MfaServiceSettings};
use authn_notify::NotifyServices;
use authn_oidc_client::{
    OidcClientService, OidcClientServiceDeps, OidcClientSettings, ProviderRegistry,
};
use authn_org::{OrgService, OrgServiceDeps, OrgServiceSettings};
use authn_password::{
    PasswordPolicy, PasswordService, PasswordServiceDeps, PasswordServiceSettings,
};
use authn_protect::risk::{MmdbGeoIp, RiskAlerts, RiskStore};
use authn_protect::{CaptchaService, DefaultRiskEvaluator, KeyHasher, LoginProtection};
use authn_session::{PgSessionRevoker, SessionService, SessionServiceDeps, SessionSettings};
use authn_webauthn::{WebauthnService, WebauthnServiceDeps, WebauthnServiceSettings};
use sqlx::PgPool;

use crate::hooks::{
    HookAnchors, Late, LateHooks, ServerAuditAccess, ServerOidcLoginMethods, ServerOwnership,
    ServerPasskeyPolicy, ServerRevertHook, ServerSessionLiveness, ServerSigningKeyCache,
};

/// Ports that tests (and alternative deployments) may replace.
#[derive(Clone)]
pub struct Ports {
    /// Clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Outbound HTTP (SSRF-safe in production).
    pub http: Arc<dyn HttpClient>,
    /// HIBP range API (PWD-03).
    pub breach_checker: Arc<dyn BreachedPasswordChecker>,
    /// DNS TXT lookups for domain verification (ORG-06).
    pub dns: Arc<dyn DnsTxtResolver>,
    /// Notifier override (tests record notifications); `None` = the
    /// outbox notifier of authn-notify.
    pub notifier: Option<Arc<dyn Notifier>>,
    /// Rewrites the social-login provider registry before the service is
    /// built (tests point the providers at fake identity providers);
    /// `None` in production.
    pub oidc_registry: Option<RegistryOverride>,
}

/// See [`Ports::oidc_registry`].
pub type RegistryOverride = Arc<dyn Fn(&mut ProviderRegistry) + Send + Sync>;

impl Ports {
    /// The production ports from the configuration.
    pub fn from_config(config: &AppConfig, clock: Arc<dyn Clock>) -> Result<Self, AuthError> {
        let http: Arc<dyn HttpClient> = Arc::new(authn_protect::outbound::SsrfSafeHttpClient::new(
            &config.protect.outbound,
        )?);
        let breach_checker: Arc<dyn BreachedPasswordChecker> =
            Arc::new(authn_password::HibpBreachChecker::from_config(
                &config.password.breach_check,
                http.clone(),
            )?);
        let dns: Arc<dyn DnsTxtResolver> = Arc::new(
            authn_org::HickoryDnsTxtResolver::from_system_conf(config.org.dns_timeout)?,
        );
        Ok(Self {
            clock,
            http,
            breach_checker,
            dns,
            notifier: None,
            oidc_registry: None,
        })
    }
}

/// Every module service, built once at start-up. Cheap to clone.
#[derive(Clone)]
pub struct Services {
    /// Configuration.
    pub config: Arc<AppConfig>,
    /// Application database pool.
    pub pool: PgPool,
    /// Pool of the maintenance role (OPS-10: audit retention purge,
    /// checkpoints); the application pool when no separate role is
    /// configured (`database.maintenance_url`).
    pub maintenance_pool: PgPool,
    /// Clock.
    pub clock: Arc<dyn Clock>,
    /// Crypto material (keys, hashers, envelopes).
    pub crypto: CryptoServices,
    /// Rate limiter.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Outbound HTTP.
    pub http: Arc<dyn HttpClient>,
    /// Notifications (`None` when a test notifier replaced them).
    pub notify: Option<NotifyServices>,
    /// The notifier port in use.
    pub notifier: Arc<dyn Notifier>,
    /// Audit sink.
    pub audit_sink: Arc<dyn AuditSink>,
    /// Domain events.
    pub events: Arc<dyn EventPublisher>,
    /// Audit log, outbox and webhooks.
    pub audit: AuditService,
    /// CAPTCHA gate.
    pub captcha: CaptchaService,
    /// Login throttling.
    pub protection: LoginProtection,
    /// MFA.
    pub mfa: MfaService,
    /// Accounts.
    pub accounts: AccountService,
    /// Passwords.
    pub passwords: PasswordService,
    /// Passkeys.
    pub webauthn: WebauthnService,
    /// Organizations.
    pub orgs: OrgService,
    /// Sessions and login.
    pub sessions: SessionService,
    /// The `SessionRevoker` port given to the modules (account-aware).
    pub revoker: Arc<dyn SessionRevoker>,
    /// The `SessionIssuer` port (social login, admin).
    pub issuer: Arc<dyn SessionIssuer>,
    /// Social login (SOC-01 … SOC-09).
    pub oidc: OidcClientService,
    /// Platform admin API (ADM-01 … ADM-08).
    pub admin: AdminService,
    /// OAuth 2.1 / OIDC provider (OIDP-*; routes mounted only when
    /// `oidc_provider.enabled`).
    #[cfg(feature = "oidc-provider")]
    pub oidc_provider: authn_oidc_provider::OidcProviderService,
    /// The MaxMind DB GeoIP reader (RSK-05) when
    /// `protect.risk.geoip_database` is set; reloaded by a background job.
    pub geoip: Option<Arc<MmdbGeoIp>>,
    /// Strong references of the late-bound hooks (see [`crate::hooks::Late`]);
    /// held only to keep them alive as long as a `Services` handle exists.
    _anchors: Arc<HookAnchors>,
}

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Services").finish_non_exhaustive()
    }
}

impl Services {
    /// Builds every service (see the module docs for the order). Must run
    /// inside the Tokio runtime (authn-notify spawns nothing but needs it
    /// for its transports) and after the TLS provider is installed.
    pub async fn build(
        config: Arc<AppConfig>,
        pool: PgPool,
        ports: Ports,
    ) -> Result<Self, AuthError> {
        let maintenance_pool = pool.clone();
        Self::build_with_maintenance_pool(config, pool, maintenance_pool, ports).await
    }

    /// [`Services::build`] with a separate pool of the maintenance role
    /// (OPS-10).
    pub async fn build_with_maintenance_pool(
        config: Arc<AppConfig>,
        pool: PgPool,
        maintenance_pool: PgPool,
        ports: Ports,
    ) -> Result<Self, AuthError> {
        let clock = ports.clock.clone();
        let crypto = CryptoServices::from_config(&config.crypto)
            .await
            .map_err(AuthError::from)?;
        let hasher = KeyHasher::new(&crypto.keys)?;
        let rate_limiter = authn_protect::rate_limit::build_rate_limiter(
            &config.protect.rate_limit,
            pool.clone(),
            clock.clone(),
            hasher.clone(),
        )
        .await?;
        let http = ports.http.clone();
        let (notify, notifier) = match &ports.notifier {
            Some(notifier) => (None, notifier.clone()),
            None => {
                let notify = NotifyServices::from_config(
                    &config,
                    pool.clone(),
                    crypto.envelopes.clone(),
                    clock.clone(),
                    rate_limiter.clone(),
                    http.clone(),
                )
                .map_err(|e| AuthError::internal("notification setup failed").with_source(e))?;
                let port = notify.notifier_port();
                (Some(notify), port)
            }
        };
        // K-77: every audit writer MACs the chain with the chain key.
        let chain_keys = ChainKeys::from_config(&crypto.keys, &config.audit.chain)?;
        let audit_sink: Arc<dyn AuditSink> = Arc::new(PgAuditSink::keyed(
            pool.clone(),
            clock.clone(),
            chain_keys.clone(),
        ));
        let events: Arc<dyn EventPublisher> = Arc::new(OutboxEventPublisher::new(
            clock.clone(),
            config.audit.outbox.max_attempts,
        ));
        let captcha_verifier = authn_protect::captcha::build_captcha_verifier(
            &config.protect.captcha,
            http.clone(),
            pool.clone(),
            clock.clone(),
            &crypto.keys,
        )?;
        let captcha = CaptchaService::new(
            captcha_verifier.clone(),
            rate_limiter.clone(),
            audit_sink.clone(),
            clock.clone(),
            &config.protect.captcha,
        );
        let hooks = LateHooks::default();

        // 3. MFA → revoker → account → account-aware revoker.
        let mut mfa_settings = MfaServiceSettings::from_app_config(&config);
        mfa_settings.webauthn_available = cfg!(feature = "passkey");
        let sms = notify.as_ref().map(|n| n.sms.clone());
        let mfa = MfaService::new(
            MfaServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                keys: crypto.keys.clone(),
                otp: crypto.otp.clone(),
                envelopes: crypto.envelopes.clone(),
                rate_limiter: rate_limiter.clone(),
                notifier: notifier.clone(),
                audit: audit_sink.clone(),
                sms,
                policy_source: hooks.mfa_policy.clone(),
            },
            mfa_settings,
        )?;
        let plain_revoker = PgSessionRevoker::new(
            clock.clone(),
            audit_sink.clone(),
            events.clone(),
            mfa.clone(),
        );
        #[cfg_attr(not(feature = "oidc-provider"), allow(unused_mut))]
        let mut exporters: Vec<Arc<dyn DataExporter>> = vec![
            Arc::new(authn_session::SessionDataExporter),
            Arc::new(authn_mfa::MfaDataExporter),
            Arc::new(authn_webauthn::PasskeyDataExporter),
            Arc::new(authn_org::OrgDataExporter),
            Arc::new(authn_oidc_client::IdentityDataExporter),
            Arc::new(authn_admin::AdminActionsDataExporter::new(clock.clone())),
        ];
        // K-80: consents and grants (OIDP-05, ACC-10).
        #[cfg(feature = "oidc-provider")]
        exporters.push(Arc::new(authn_oidc_provider::ProviderDataExporter));
        let validator = Arc::new(PasswordPolicy::from_config(
            &config.password,
            ports.breach_checker.clone(),
        ));
        let accounts = AccountService::new(
            AccountServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                hasher: crypto.passwords.clone(),
                otp: crypto.otp.clone(),
                rate_limiter: rate_limiter.clone(),
                captcha: captcha_verifier,
                password_validator: validator,
                notifier: notifier.clone(),
                audit: audit_sink.clone(),
                events: events.clone(),
                sessions: Arc::new(plain_revoker.clone()),
                exporters,
                ownership: Arc::new(ServerOwnership),
            },
            AccountServiceSettings::from_app_config(&config)?,
        )?;
        let revoker: Arc<dyn SessionRevoker> = Arc::new(AccountAwareSessionRevoker::new(
            Arc::new(plain_revoker),
            accounts.clone(),
        ));

        // 4. The other modules.
        let passwords = PasswordService::new(
            PasswordServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                hasher: crypto.passwords.clone(),
                otp: crypto.otp.clone(),
                rate_limiter: rate_limiter.clone(),
                notifier: notifier.clone(),
                audit: audit_sink.clone(),
                sessions: revoker.clone(),
                breach_checker: ports.breach_checker.clone(),
                login_methods: hooks.login_methods.clone(),
                profiles: hooks.profiles.clone(),
            },
            PasswordServiceSettings::from_app_config(&config),
        );
        let webauthn = WebauthnService::new(
            WebauthnServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                rate_limiter: rate_limiter.clone(),
                notifier: notifier.clone(),
                audit: audit_sink.clone(),
                account_methods: hooks.account_methods.clone(),
                policy_source: Arc::new(ServerPasskeyPolicy),
            },
            WebauthnServiceSettings::from_app_config(&config)?,
        )?;
        let orgs = OrgService::new(
            OrgServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                audit: audit_sink.clone(),
                events: events.clone(),
                notifier: notifier.clone(),
                rate_limiter: rate_limiter.clone(),
                session_revoker: revoker.clone(),
                dns: ports.dns.clone(),
            },
            OrgServiceSettings::from_app_config(&config),
        );
        let audit = AuditService::new(AuditServiceParts {
            pool: pool.clone(),
            clock: clock.clone(),
            cipher: crypto.envelopes.clone(),
            policy: Arc::new(ServerAuditAccess { orgs: orgs.clone() }),
            rate_limiter: rate_limiter.clone(),
            config: config.audit,
            step_up_max_age: config.session.step_up_max_age,
            chain_keys: chain_keys.clone(),
        });

        // 5. Late hooks (weak references; the strong ones are the anchors).
        let webauthn_anchor = Arc::new(webauthn.clone());
        let mfa_anchor = Arc::new(mfa.clone());
        let accounts_anchor = Arc::new(accounts.clone());
        hooks.login_methods.webauthn.bind(&webauthn_anchor);
        hooks.mfa_policy.webauthn.bind(&webauthn_anchor);
        hooks.profiles.accounts.bind(&accounts_anchor);
        hooks.account_methods.mfa.bind(&mfa_anchor);

        // 6. Login protection, risk, sessions.
        let risk_store = RiskStore::new(pool.clone(), hasher.clone());
        let protection = LoginProtection::new(
            pool.clone(),
            clock.clone(),
            rate_limiter.clone(),
            audit_sink.clone(),
            captcha.clone(),
            risk_store,
            &config.protect,
        );
        let geoip = open_geoip(&config)?;
        let evaluator = DefaultRiskEvaluator::new(
            pool.clone(),
            hasher,
            rate_limiter.clone(),
            &config.protect.risk,
            geoip
                .clone()
                .map(|g| g as Arc<dyn authn_core::ports::GeoIpLookup>),
        )?;
        let risk_alerts = RiskAlerts::new(
            evaluator.clone(),
            notifier.clone(),
            audit_sink.clone(),
            rate_limiter.clone(),
            clock.clone(),
        );
        let sessions = SessionService::new(
            SessionServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                keys: crypto.keys.clone(),
                envelopes: crypto.envelopes.clone(),
                rate_limiter: rate_limiter.clone(),
                audit: audit_sink.clone(),
                events: events.clone(),
                notifier: notifier.clone(),
                passwords: passwords.clone(),
                mfa: mfa.clone(),
                webauthn: webauthn.clone(),
                orgs: orgs.clone(),
                accounts: accounts.clone(),
                protection: protection.clone(),
                risk: Arc::new(evaluator),
                risk_alerts,
                otp: crypto.otp.clone(),
            },
            SessionSettings::from_app_config(&config),
        )?;
        let issuer: Arc<dyn SessionIssuer> = Arc::new(sessions.clone());

        // 7. Social login (needs the session issuer) and its erasure hook.
        let oidc = build_oidc(
            &config,
            &ports,
            OidcClientServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                http: http.clone(),
                envelopes: crypto.envelopes.clone(),
                rate_limiter: rate_limiter.clone(),
                audit: audit_sink.clone(),
                events: events.clone(),
                sessions: issuer.clone(),
                accounts: accounts.clone(),
                login_methods: Arc::new(ServerOidcLoginMethods {
                    webauthn: webauthn.clone(),
                }),
                session_liveness: Arc::new(ServerSessionLiveness),
                notifier: notifier.clone(),
            },
        )
        .await?;
        accounts.register_erasure_hook(Arc::new(oidc.erasure_hook()));
        // K-20: an e-mail change revert removes every login method the
        // attacker could have added.
        let oidc_anchor = Arc::new(oidc.clone());
        let revert_hook = ServerRevertHook {
            webauthn: webauthn.clone(),
            mfa: mfa.clone(),
            oidc: Late::default(),
        };
        revert_hook.oidc.bind(&oidc_anchor);
        accounts.register_revert_hook(Arc::new(revert_hook));
        let anchors = Arc::new(HookAnchors {
            webauthn: webauthn_anchor,
            mfa: mfa_anchor,
            accounts: accounts_anchor,
            oidc: oidc_anchor,
        });

        // 8. Platform admin (needs the issuer and the account-aware revoker).
        let admin = AdminService::new(
            AdminServiceDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                audit: audit_sink.clone(),
                sessions: revoker.clone(),
                issuer: issuer.clone(),
                accounts: accounts.clone(),
                mfa: mfa.clone(),
                webauthn: webauthn.clone(),
                passwords: passwords.clone(),
                protection: protection.clone(),
                hasher: crypto.passwords.clone(),
                envelopes: crypto.envelopes.clone(),
                signing_keys: Arc::new(ServerSigningKeyCache(sessions.clone())),
                rate_limiter: rate_limiter.clone(),
                audit_chain_keys: chain_keys,
            },
            AdminSettings::from_app_config(&config),
        );
        // 9. OAuth 2.1 / OIDC provider (K-80): grants bound to the live
        // session (OIDP-12), staff-role checks of the client registry by
        // authn-admin (OIDP-01, K-93).
        #[cfg(feature = "oidc-provider")]
        let oidc_provider = authn_oidc_provider::OidcProviderService::new(
            authn_oidc_provider::OidcProviderDeps {
                pool: pool.clone(),
                clock: clock.clone(),
                audit: audit_sink.clone(),
                rate_limiter: rate_limiter.clone(),
                envelopes: crypto.envelopes.clone(),
                accounts: accounts.clone(),
                liveness: Arc::new(crate::hooks::ServerSessionLiveness),
                client_admin: Arc::new(crate::hooks::ServerClientAdmin(admin.clone())),
            },
            authn_oidc_provider::OidcProviderSettings::from_app_config(&config)?,
        );
        Ok(Self {
            config,
            pool,
            maintenance_pool,
            clock,
            crypto,
            rate_limiter,
            http,
            notify,
            notifier,
            audit_sink,
            events,
            audit,
            captcha,
            protection,
            mfa,
            accounts,
            passwords,
            webauthn,
            orgs,
            sessions,
            revoker,
            issuer,
            oidc,
            admin,
            #[cfg(feature = "oidc-provider")]
            oidc_provider,
            geoip,
            _anchors: anchors,
        })
    }
}

/// Opens `protect.risk.geoip_database` (RSK-05, K-98): `None` when unset;
/// a missing, oversized or malformed file is a start-up error.
pub fn open_geoip(config: &AppConfig) -> Result<Option<Arc<MmdbGeoIp>>, AuthError> {
    let Some(path) = &config.protect.risk.geoip_database else {
        return Ok(None);
    };
    let geoip = MmdbGeoIp::open(path)?;
    let info = geoip.info();
    tracing::info!(
        database_type = %info.database_type,
        build_epoch = info.build_epoch,
        "GeoIP database loaded (impossible-travel check on)"
    );
    Ok(Some(Arc::new(geoip)))
}

/// `OidcClientService::build` (the Apple key is decrypted and every
/// provider setting validated at start-up), with the test override of the
/// provider registry.
async fn build_oidc(
    config: &AppConfig,
    ports: &Ports,
    deps: OidcClientServiceDeps,
) -> Result<OidcClientService, AuthError> {
    let settings = OidcClientSettings::from_app_config(config);
    let Some(rewrite) = &ports.oidc_registry else {
        return OidcClientService::build(deps, settings).await;
    };
    let mut settings = settings;
    if let Some(apple) = settings.config.apple.as_mut() {
        authn_oidc_client::apple::resolve_private_key(apple, &deps.envelopes).await?;
    }
    let mut registry = ProviderRegistry::from_settings(&settings)?;
    rewrite(&mut registry);
    OidcClientService::with_registry(deps, settings, registry)
}
