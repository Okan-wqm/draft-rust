//! Shared harness of the authn-admin integration tests: the real wave-A
//! services (accounts, MFA, passwords, login protection) and the real
//! audit sink over one database, testkit fakes for the remaining ports, and
//! the admin router behind a fixed `Principal`.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_account::{AccountService, AccountServiceDeps, AccountServiceSettings, NoOrganizations};
use authn_admin::{AdminService, AdminServiceDeps, AdminSettings, SigningKeyCache};
use authn_audit::PgAuditSink;
use authn_core::config::AppConfig;
use authn_core::domain::{
    AccountStatus, AuthMethodRef, ClientKind, EmailAddress, Impersonation, Locale, Principal,
    PrincipalCredential, Subject,
};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{RequestId, SessionId, UserId};
use authn_core::ports::{
    Actor, AuditSink, Clock, ImpersonationRequest, IssuedSession, LoginOutcome,
    PrimaryAuthentication, SecurityEvent, SecurityEventKind, SessionIssuer,
};
use authn_core::secret::{SecretString, SensitiveString};
use authn_crypto::CryptoServices;
use authn_mfa::{MfaService, MfaServiceDeps, MfaServiceSettings, StaticMfaPolicySource};
use authn_password::{
    NoOtherLoginMethods, NoProfiles, PasswordService, PasswordServiceDeps, PasswordServiceSettings,
};
use authn_store::{NewPasswordHash, NewUser, SigningKeyRepository, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::http::{TestRequest, TestResponse, with_request_context};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Router};
use sqlx::PgPool;
use time::OffsetDateTime;

/// A password accepted by every policy.
pub const PASSWORD: &str = "tramway galaxy orchid lantern 47";
/// Client IP of test requests.
pub const ADMIN_IP: &str = "203.0.113.10";

/// Counts signing-key cache invalidations.
#[derive(Debug, Default)]
pub struct CountingKeyCache(pub Mutex<u32>);

impl SigningKeyCache for CountingKeyCache {
    fn invalidate_signing_keys(&self) {
        *self.0.lock().unwrap() += 1;
    }
}

/// A `SessionIssuer` standing in for authn-session: issues fake sessions
/// and, like the real implementation, records `admin.impersonation_started`
/// (resource = the new session).
pub struct TestIssuer {
    pub clock: Arc<dyn Clock>,
    pub audit: Arc<dyn AuditSink>,
    pub requests: Mutex<Vec<(ImpersonationRequest, ClientKind, Option<SessionId>)>>,
}

#[async_trait]
impl SessionIssuer for TestIssuer {
    async fn complete_primary_authentication(
        &self,
        _ctx: &RequestContext,
        _auth: PrimaryAuthentication,
    ) -> Result<LoginOutcome, AuthError> {
        Err(AuthError::internal("not used"))
    }

    fn login_response(&self, outcome: LoginOutcome, _return_to: Option<&str>) -> Response {
        match outcome {
            LoginOutcome::Authenticated(s) => axum::Json(serde_json::json!({
                "session_id": s.session_id,
                "user_id": s.user_id,
                "client": s.client.as_str(),
                "has_access_token": s.access_token.is_some(),
                "absolute_expires_at": s.absolute_expires_at.unix_timestamp(),
            }))
            .into_response(),
            LoginOutcome::ChallengeRequired(_) => axum::http::StatusCode::CONFLICT.into_response(),
        }
    }

    async fn start_impersonation(
        &self,
        ctx: &RequestContext,
        request: ImpersonationRequest,
    ) -> Result<IssuedSession, AuthError> {
        self.start_impersonation_with(ctx, request, ClientKind::Web, None)
            .await
    }

    async fn start_impersonation_with(
        &self,
        ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        admin_session: Option<SessionId>,
    ) -> Result<IssuedSession, AuthError> {
        let now = self.clock.now();
        let session_id = SessionId::generate();
        let expires = now + request.ttl;
        let mut event = SecurityEvent::new(SecurityEventKind::ImpersonationStarted, now)
            .with_context(ctx)
            .with_actor(Actor::User(request.admin_user_id))
            .with_subject(request.target_user_id)
            .with_resource("session", session_id)
            .with_meta("read_only", request.read_only);
        event.impersonator = Some(request.admin_user_id);
        self.audit.record(event).await?;
        let user_id = request.target_user_id;
        self.requests
            .lock()
            .unwrap()
            .push((request, client, admin_session));
        Ok(IssuedSession {
            session_id,
            user_id,
            client,
            session_token: (client == ClientKind::Web)
                .then(|| SensitiveString::new(format!("fake-{session_id}"))),
            access_token: (client == ClientKind::Native)
                .then(|| SensitiveString::new(format!("fake-access-{session_id}"))),
            access_token_expires_at: None,
            refresh_token: None,
            idle_expires_at: expires,
            absolute_expires_at: expires,
            browser_session_only: true,
        })
    }
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub crypto: CryptoServices,
    pub config: AppConfig,
    pub service: AdminService,
    pub issuer: Arc<TestIssuer>,
    pub keys: Arc<CountingKeyCache>,
    pub mfa: MfaService,
    pub passwords: PasswordService,
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut AdminSettings)) -> Self {
        authn_testkit::init_tracing();
        let config = authn_testkit::config::test_config();
        let crypto = CryptoServices::from_config(&config.crypto).await.unwrap();
        let ports = TestPorts::new();
        let audit: Arc<dyn AuditSink> =
            Arc::new(PgAuditSink::new(pool.clone(), ports.clock.clone()));
        {
            let mut conn = pool.acquire().await.unwrap();
            SigningKeyRepository::rotate_if_due(
                &mut conn,
                &crypto.envelopes,
                ports.clock.now(),
                &config.crypto.signing_keys,
            )
            .await
            .unwrap();
        }
        let mfa = MfaService::new(
            MfaServiceDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                keys: crypto.keys.clone(),
                otp: crypto.otp.clone(),
                envelopes: crypto.envelopes.clone(),
                rate_limiter: ports.rate_limiter.clone(),
                notifier: ports.notifier.clone(),
                audit: audit.clone(),
                sms: None,
                policy_source: Arc::new(StaticMfaPolicySource::default()),
            },
            MfaServiceSettings::from_app_config(&config),
        )
        .unwrap();
        let accounts = AccountService::new(
            AccountServiceDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                hasher: crypto.passwords.clone(),
                otp: crypto.otp.clone(),
                rate_limiter: ports.rate_limiter.clone(),
                captcha: ports.captcha.clone(),
                password_validator: ports.password_validator.clone(),
                notifier: ports.notifier.clone(),
                audit: audit.clone(),
                events: ports.events.clone(),
                sessions: ports.session_revoker.clone(),
                exporters: Vec::new(),
                ownership: Arc::new(NoOrganizations),
            },
            AccountServiceSettings::from_app_config(&config).unwrap(),
        )
        .unwrap();
        let passwords = PasswordService::new(
            PasswordServiceDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                hasher: crypto.passwords.clone(),
                otp: crypto.otp.clone(),
                rate_limiter: ports.rate_limiter.clone(),
                notifier: ports.notifier.clone(),
                audit: audit.clone(),
                sessions: ports.session_revoker.clone(),
                breach_checker: ports.breached_passwords.clone(),
                login_methods: Arc::new(NoOtherLoginMethods),
                profiles: Arc::new(NoProfiles),
            },
            PasswordServiceSettings::from_app_config(&config),
        );
        let protect_hasher = authn_protect::KeyHasher::new(&crypto.keys).unwrap();
        let captcha = authn_protect::CaptchaService::new(
            ports.captcha.clone(),
            ports.rate_limiter.clone(),
            audit.clone(),
            ports.clock.clone(),
            &config.protect.captcha,
        );
        let risk_store = authn_protect::risk::RiskStore::new(pool.clone(), protect_hasher);
        let protection = authn_protect::LoginProtection::new(
            pool.clone(),
            ports.clock.clone(),
            ports.rate_limiter.clone(),
            audit.clone(),
            captcha,
            risk_store,
            &config.protect,
        );
        let issuer = Arc::new(TestIssuer {
            clock: ports.clock.clone(),
            audit: audit.clone(),
            requests: Mutex::new(Vec::new()),
        });
        let keys = Arc::new(CountingKeyCache::default());
        let mut settings = AdminSettings::from_app_config(&config);
        tweak(&mut settings);
        let service = AdminService::new(
            AdminServiceDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                audit,
                sessions: ports.session_revoker.clone(),
                issuer: issuer.clone(),
                accounts,
                mfa: mfa.clone(),
                passwords: passwords.clone(),
                protection,
                hasher: crypto.passwords.clone(),
                envelopes: crypto.envelopes.clone(),
                signing_keys: keys.clone(),
            },
            settings,
        );
        Self {
            pool,
            ports,
            crypto,
            config,
            service,
            issuer,
            keys,
            mfa,
            passwords,
        }
    }

    /// Waits for background reset e-mails.
    pub async fn service_passwords_drain(&self) {
        self.passwords.drain_background_jobs().await;
    }

    pub fn now(&self) -> OffsetDateTime {
        self.ports.clock.now()
    }

    pub fn advance(&self, by: Duration) {
        self.ports.clock.advance(by);
    }

    pub fn ctx(&self) -> RequestContext {
        let ip: IpAddr = ADMIN_IP.parse().unwrap();
        RequestContext {
            request_id: RequestId::generate(),
            client_ip: ip,
            peer_ip: ip,
            user_agent: Some("admin-test".into()),
            device_id: None,
            locale: Locale::En,
        }
    }

    /// The admin router behind `principal` (or no principal at all).
    pub fn app(&self, principal: Option<Principal>) -> Router {
        let router = authn_admin::router::<AdminService>()
            .fallback(authn_core::http::not_found_fallback)
            .with_state(self.service.clone());
        let router = match principal {
            Some(p) => router.layer(Extension(p)),
            None => router,
        };
        with_request_context(router)
    }

    /// Sends `request` from the default admin IP as `principal`.
    pub async fn send(&self, principal: &Principal, request: TestRequest) -> TestResponse {
        request
            .peer_ip(ADMIN_IP.parse().unwrap())
            .send(&self.app(Some(principal.clone())))
            .await
    }

    /// A user with a password in the given status (verified unless
    /// `pending_verification`).
    pub async fn user_with_status(&self, email: &str, status: AccountStatus) -> UserId {
        let id = UserId::generate();
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status,
                created_at: self.now(),
            },
        )
        .await
        .unwrap();
        if status != AccountStatus::PendingVerification {
            UserRepository::mark_email_verified(&mut conn, id, self.now())
                .await
                .unwrap();
        }
        let record = self
            .crypto
            .passwords
            .hash(&SecretString::from(PASSWORD.to_owned()))
            .await
            .unwrap();
        UserRepository::set_password(
            &mut conn,
            id,
            &NewPasswordHash {
                password_hash: &record.hash,
                algorithm: record.algorithm.as_str(),
                pepper_version: record.pepper_version,
            },
            false,
            self.now(),
        )
        .await
        .unwrap();
        id
    }

    /// An active, verified user with a password.
    pub async fn user(&self, email: &str) -> UserId {
        self.user_with_status(email, AccountStatus::Active).await
    }

    /// Flags a user as platform admin (and break-glass).
    pub async fn make_admin(&self, user: UserId, break_glass: bool) {
        sqlx::query("UPDATE users SET is_platform_admin = true, is_break_glass = $2 WHERE id = $1")
            .bind(user)
            .bind(break_glass)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// An active platform admin and a principal for it: passkey session
    /// with UV (`hwk`, `user`, `mfa`), authenticated a minute ago.
    pub async fn admin(&self, email: &str) -> (UserId, Principal) {
        let id = self.user(email).await;
        self.make_admin(id, false).await;
        (id, self.principal(id, true))
    }

    /// A principal for `user` as authn-session would build it.
    pub fn principal(&self, user: UserId, is_platform_admin: bool) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Hwk, AuthMethodRef::User, AuthMethodRef::Mfa],
            acr: None,
            auth_time: Some(self.now() - Duration::from_secs(60)),
            scopes: vec![],
            impersonation: None,
            is_platform_admin,
        }
    }

    /// `principal` impersonating (as authn-session marks it).
    pub fn impersonated(&self, mut principal: Principal, read_only: bool) -> Principal {
        principal.impersonation = Some(Impersonation {
            admin_user_id: principal.user_id().unwrap(),
            read_only,
            expires_at: self.now() + Duration::from_secs(900),
        });
        principal
    }

    /// The authorized caller of `principal` (service-level tests).
    pub async fn caller(&self, principal: &Principal) -> authn_admin::AdminCaller {
        self.service
            .authorize(principal, &self.ctx())
            .await
            .unwrap()
    }

    /// Audit events of `kind` (stored rows) with their metadata, oldest
    /// first.
    pub async fn events(&self, kind: &str) -> Vec<StoredEvent> {
        sqlx::query_as::<_, StoredEvent>(
            "SELECT id, kind, outcome, reason, metadata FROM audit_events \
             WHERE kind = $1 ORDER BY seq",
        )
        .bind(kind)
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    /// `admin.action` / `admin.emergency_action` events with `action`.
    pub async fn admin_events(&self, action: &str) -> Vec<StoredEvent> {
        sqlx::query_as::<_, StoredEvent>(
            "SELECT id, kind, outcome, reason, metadata FROM audit_events \
             WHERE kind LIKE 'admin.%' AND metadata->>'action' = $1 ORDER BY seq",
        )
        .bind(action)
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    /// The stored justification of an event.
    pub async fn justification(&self, event: uuid::Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT reason FROM admin_action_reasons WHERE event_id = $1")
            .bind(event)
            .fetch_optional(&self.pool)
            .await
            .unwrap()
    }

    pub async fn record(&self, user: UserId) -> authn_store::UserRecord {
        UserRepository::find_by_id(&self.pool, user)
            .await
            .unwrap()
            .unwrap()
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredEvent {
    pub id: uuid::Uuid,
    pub kind: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub metadata: serde_json::Value,
}
