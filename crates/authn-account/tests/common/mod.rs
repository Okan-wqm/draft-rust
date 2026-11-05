//! Shared harness of the authn-account integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_account::{
    AccountService, AccountServiceDeps, AccountServiceSettings, CredentialConfirmation,
    LinkConfirmation, OrganizationOwnership, SignupInput, router,
};
use authn_core::config::common::CaptchaPolicy;
use authn_core::domain::{
    AuthMethodRef, EmailAddress, Locale, Principal, PrincipalCredential, Subject,
};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, RequestId, SessionId, UserId};
use authn_core::ports::{
    AuditSink, Clock, DataExporter, Notification, NotificationKind, RateLimitPolicy, SecurityEvent,
};
use authn_core::secret::SecretString;
use authn_crypto::CryptoServices;
use authn_store::{UserRecord, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::fakes::RecordingAuditSink;
use authn_testkit::http::with_request_context;
use axum::{Extension, Router};
use sqlx::{PgConnection, PgPool};

/// A password the fake validator accepts.
pub const PASSWORD: &str = "tramway galaxy orchid lantern 47";
/// Another acceptable password.
pub const PASSWORD_2: &str = "quiet velvet harbor sunrise 1923";

/// Audit sink that also records `pseudonymize_subject` calls.
#[derive(Default)]
pub struct TestAudit {
    pub events: RecordingAuditSink,
    pub pseudonymized: Mutex<Vec<UserId>>,
}

#[async_trait]
impl AuditSink for TestAudit {
    async fn record(&self, event: SecurityEvent) -> Result<(), AuthError> {
        self.events.record(event).await
    }

    async fn record_in_tx(
        &self,
        conn: &mut PgConnection,
        event: SecurityEvent,
    ) -> Result<(), AuthError> {
        self.events.record_in_tx(conn, event).await
    }

    async fn pseudonymize_subject(
        &self,
        _conn: &mut PgConnection,
        user: UserId,
    ) -> Result<(), AuthError> {
        self.pseudonymized.lock().unwrap().push(user);
        Ok(())
    }
}

/// Organizations in which a user is the sole owner.
#[derive(Default)]
pub struct FakeOwnership(pub Mutex<HashMap<UserId, Vec<OrgId>>>);

#[async_trait]
impl OrganizationOwnership for FakeOwnership {
    async fn sole_owner_organizations(
        &self,
        _conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<OrgId>, AuthError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&user)
            .cloned()
            .unwrap_or_default())
    }
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub crypto: CryptoServices,
    pub audit: Arc<TestAudit>,
    pub ownership: Arc<FakeOwnership>,
    pub service: AccountService,
    pub settings: AccountServiceSettings,
}

#[derive(Default)]
pub struct Options {
    pub production_argon2: bool,
    pub exporters: Vec<Arc<dyn DataExporter>>,
    /// Replaces the in-memory rate limiter (pool-pattern tests).
    pub rate_limiter: Option<Arc<dyn authn_core::ports::RateLimiter>>,
}

/// Generous limits so that only tests about limits hit them.
fn relaxed(settings: &mut AccountServiceSettings) {
    let generous = RateLimitPolicy::new(10_000, Duration::from_secs(3600));
    let a = &mut settings.account;
    a.registration_per_ip = generous;
    a.registration_captcha = CaptchaPolicy::Never;
    a.verification.verify_per_ip = generous;
    a.verification.resend_per_ip = generous;
    a.verification.code_attempts_per_email = generous;
    a.link_actions_per_ip = generous;
    a.email_change_per_user = generous;
    a.export_per_user = generous;
    settings.code_failure_floor = Duration::from_millis(5);
    settings.registration_code_guesses = generous;
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut AccountServiceSettings)) -> Self {
        Self::build(pool, Options::default(), tweak).await
    }

    pub async fn build(
        pool: PgPool,
        options: Options,
        tweak: impl FnOnce(&mut AccountServiceSettings),
    ) -> Self {
        authn_testkit::init_tracing();
        let mut builder = authn_testkit::config::TestConfigBuilder::new();
        if options.production_argon2 {
            builder = builder.production_argon2();
        }
        let config = builder.build();
        let crypto = CryptoServices::from_config(&config.crypto).await.unwrap();
        let ports = TestPorts::new();
        let mut settings = AccountServiceSettings::from_app_config(&config).unwrap();
        relaxed(&mut settings);
        tweak(&mut settings);
        let audit = Arc::new(TestAudit::default());
        let ownership = Arc::new(FakeOwnership::default());
        let deps = AccountServiceDeps {
            pool: pool.clone(),
            clock: ports.clock.clone(),
            hasher: crypto.passwords.clone(),
            otp: crypto.otp.clone(),
            rate_limiter: options
                .rate_limiter
                .unwrap_or_else(|| ports.rate_limiter.clone()),
            captcha: ports.captcha.clone(),
            password_validator: ports.password_validator.clone(),
            notifier: ports.notifier.clone(),
            audit: audit.clone(),
            events: ports.events.clone(),
            sessions: ports.session_revoker.clone(),
            exporters: options.exporters,
            ownership: ownership.clone(),
        };
        let service = AccountService::new(deps, settings.clone()).unwrap();
        Self {
            pool,
            ports,
            crypto,
            audit,
            ownership,
            service,
            settings,
        }
    }

    pub fn ctx(&self) -> RequestContext {
        RequestContext {
            request_id: RequestId::generate(),
            client_ip: "198.51.100.7".parse().unwrap(),
            peer_ip: "198.51.100.7".parse().unwrap(),
            user_agent: Some("account-tests/1.0".to_owned()),
            device_id: None,
            locale: Locale::En,
        }
    }

    /// Router without a principal (public endpoints).
    pub fn app(&self) -> Router {
        with_request_context(router().with_state(self.service.clone()))
    }

    /// Router whose requests carry `principal`.
    pub fn app_as(&self, principal: &Principal) -> Router {
        with_request_context(
            router()
                .with_state(self.service.clone())
                .layer(Extension(principal.clone())),
        )
    }

    /// A session principal for `user` who authenticated `age` ago.
    pub fn principal(&self, user: UserId, age: Duration) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time: Some(self.ports.clock.now() - age),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
            login_method: None,
            mfa_factors: Vec::new(),
        }
    }

    /// A principal with a fresh step-up.
    pub fn fresh(&self, user: UserId) -> Principal {
        self.principal(user, Duration::from_secs(30))
    }

    /// A principal whose authentication is older than the step-up window.
    pub fn stale(&self, user: UserId) -> Principal {
        self.principal(user, Duration::from_secs(3600))
    }

    pub fn signup_input(email: &str, password: &str) -> SignupInput {
        serde_json::from_value(serde_json::json!({
            "email": email,
            "password": password,
        }))
        .unwrap()
    }

    /// Registers through the service, waits for the background job and
    /// returns the registration handle the client received.
    pub async fn signup(&self, email: &str) -> String {
        self.signup_with(email, PASSWORD).await
    }

    /// [`Self::signup`] with a chosen password.
    pub async fn signup_with(&self, email: &str, password: &str) -> String {
        let receipt = self
            .service
            .signup(&self.ctx(), Self::signup_input(email, password))
            .await
            .unwrap();
        self.drain().await;
        receipt.handle().expose().to_owned()
    }

    pub async fn drain(&self) {
        self.service.drain_background_jobs().await;
    }

    pub async fn user(&self, email: &str) -> Option<UserRecord> {
        UserRepository::find_by_email(&self.pool, &EmailAddress::parse(email).unwrap())
            .await
            .unwrap()
    }

    pub async fn user_by_id(&self, id: UserId) -> Option<UserRecord> {
        UserRepository::find_by_id(&self.pool, id).await.unwrap()
    }

    /// Notifications of one template sent to `email`.
    pub fn mails(&self, template: &str, email: &str) -> Vec<Notification> {
        let wanted = EmailAddress::parse(email).unwrap();
        self.ports
            .notifier
            .with_template(template)
            .into_iter()
            .filter(|n| n.recipient.email.normalized() == wanted.normalized())
            .collect()
    }

    /// Link token and code of the latest verification e-mail to `email`.
    pub fn verification(&self, email: &str) -> (String, String) {
        let mail = self
            .mails("email_verification", email)
            .pop()
            .unwrap_or_else(|| panic!("no verification e-mail to {email}"));
        match mail.kind {
            NotificationKind::EmailVerification { token, code, .. } => {
                (token.expose().to_owned(), code.expose().to_owned())
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Registers and verifies (link opened by the registering client) an
    /// account; returns its id.
    pub async fn active_user(&self, email: &str) -> UserId {
        let handle = self.signup(email).await;
        let (token, _) = self.verification(email);
        self.verify_link(&token, Some(&handle), None).await.unwrap();
        self.user(email).await.unwrap().id
    }

    /// Opens a verification link with the given handle / credentials.
    pub async fn verify_link(
        &self,
        token: &str,
        handle: Option<&str>,
        credentials: Option<CredentialConfirmation>,
    ) -> Result<(), AuthError> {
        self.service
            .verify_email_link(
                &self.ctx(),
                &secret(token),
                &LinkConfirmation {
                    registration: handle.map(secret),
                    signed_in_user: None,
                    credentials,
                },
            )
            .await
    }

    /// Submits a verification code with the given handle.
    pub async fn verify_code(&self, handle: Option<&str>, code: &str) -> Result<(), AuthError> {
        self.service
            .verify_email_code(
                &self.ctx(),
                handle.map(secret).as_ref(),
                None,
                &secret(code),
            )
            .await
    }

    /// An unverified account that already has a password — as written by
    /// older code, imports or other modules, and the only kind that can
    /// sign in with `account.unverified_login = "limited"`. Registrations
    /// never create such accounts any more (ADR 0002).
    pub async fn unverified_with_password(&self, email: &str, password: &str) -> UserId {
        let now = self.ports.clock.now();
        let id = UserId::generate();
        let hash = self.crypto.passwords.hash(&secret(password)).await.unwrap();
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &authn_store::NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status: authn_core::domain::AccountStatus::PendingVerification,
                created_at: now,
            },
        )
        .await
        .unwrap();
        UserRepository::set_password(
            &mut conn,
            id,
            &authn_store::NewPasswordHash {
                password_hash: &hash.hash,
                algorithm: hash.algorithm.as_str(),
                pepper_version: hash.pepper_version,
            },
            false,
            now,
        )
        .await
        .unwrap();
        id
    }

    /// Whether `password` verifies against the stored hash.
    pub async fn password_matches(&self, user: UserId, password: &str) -> bool {
        let Some(stored) = UserRepository::find_password(&self.pool, user)
            .await
            .unwrap()
        else {
            return false;
        };
        let stored = authn_crypto::password::StoredPasswordHash::new(
            &stored.password_hash,
            &stored.algorithm,
            stored.pepper_version,
        );
        self.crypto
            .passwords
            .verify(&secret(password), Some(&stored))
            .await
            .unwrap()
            .is_valid()
    }

    pub async fn count(&self, sql: &'static str, user: UserId) -> i64 {
        let (n,): (i64,) = sqlx::query_as(sql)
            .bind(user)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        n
    }
}

pub fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

/// The "password you chose" confirmation.
pub fn chosen(password: &str) -> CredentialConfirmation {
    CredentialConfirmation::ChosenPassword(secret(password))
}

/// A new password chosen on the link page.
pub fn new_password(password: &str) -> CredentialConfirmation {
    CredentialConfirmation::NewPassword {
        password: secret(password),
        accepted_terms: Vec::new(),
    }
}

/// Number of live registrations of a user.
pub async fn registrations(pool: &PgPool, user: UserId) -> i64 {
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM pending_registrations WHERE user_id = $1")
            .bind(user)
            .fetch_one(pool)
            .await
            .unwrap();
    n
}
