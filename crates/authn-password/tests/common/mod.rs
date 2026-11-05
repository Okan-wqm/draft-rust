//! Shared harness of the authn-password integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_core::domain::{
    AccountStatus, AuthMethodRef, EmailAddress, Locale, LoginMethod, Principal,
    PrincipalCredential, Subject,
};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{SessionId, UserId};
use authn_core::ports::{Clock, NotificationKind};
use authn_crypto::CryptoServices;
use authn_password::{
    LoginMethodInventory, PasswordService, PasswordServiceDeps, PasswordServiceSettings,
    ProfileHints, ProfileLookup, router,
};
use authn_store::{NewPasswordHash, NewUser, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::http::with_request_context;
use axum::{Extension, Router};
use sqlx::{PgConnection, PgPool};

/// zxcvbn score 4, 32 characters, no composition tricks.
pub const STRONG: &str = "tramway galaxy orchid lantern 47";
/// Another strong password.
pub const STRONG_2: &str = "quiet velvet harbor sunrise 1923";
/// A third strong password.
pub const STRONG_3: &str = "copper meadow whistle fjord 2210";

/// Login methods reported to the service (PWD-11).
#[derive(Debug, Default)]
pub struct FakeMethods(pub Mutex<Vec<LoginMethod>>);

#[async_trait]
impl LoginMethodInventory for FakeMethods {
    async fn other_login_methods(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// Profile hints per user.
#[derive(Debug, Default)]
pub struct FakeProfiles(pub Mutex<HashMap<UserId, ProfileHints>>);

#[async_trait]
impl ProfileLookup for FakeProfiles {
    async fn profile(&self, user: UserId) -> Result<ProfileHints, AuthError> {
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
    pub service: PasswordService,
    pub settings: PasswordServiceSettings,
    pub methods: Arc<FakeMethods>,
    pub profiles: Arc<FakeProfiles>,
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut PasswordServiceSettings)) -> Self {
        Self::build(pool, tweak, None).await
    }

    /// A harness whose service reads profiles through `profiles` (used to
    /// inject concurrent changes deterministically: the reset job looks up
    /// the profile between its unlocked lookup and its locked re-check).
    pub async fn with_profiles(pool: PgPool, profiles: Arc<dyn ProfileLookup>) -> Self {
        Self::build(pool, |_| {}, Some(profiles)).await
    }

    async fn build(
        pool: PgPool,
        tweak: impl FnOnce(&mut PasswordServiceSettings),
        profile_override: Option<Arc<dyn ProfileLookup>>,
    ) -> Self {
        authn_testkit::init_tracing();
        let config = authn_testkit::config::test_config();
        let crypto = CryptoServices::from_config(&config.crypto).await.unwrap();
        let ports = TestPorts::new();
        let mut settings = PasswordServiceSettings::from_app_config(&config);
        settings.code_failure_floor = Duration::from_millis(5);
        tweak(&mut settings);
        let methods = Arc::new(FakeMethods::default());
        let profiles = Arc::new(FakeProfiles::default());
        let deps = PasswordServiceDeps {
            pool: pool.clone(),
            clock: ports.clock.clone(),
            hasher: crypto.passwords.clone(),
            otp: crypto.otp.clone(),
            rate_limiter: ports.rate_limiter.clone(),
            notifier: ports.notifier.clone(),
            audit: ports.audit.clone(),
            sessions: ports.session_revoker.clone(),
            breach_checker: ports.breached_passwords.clone(),
            login_methods: methods.clone(),
            profiles: profile_override
                .unwrap_or_else(|| profiles.clone() as Arc<dyn ProfileLookup>),
        };
        let service = PasswordService::new(deps, settings.clone());
        Self {
            pool,
            ports,
            crypto,
            service,
            settings,
            methods,
            profiles,
        }
    }

    /// An active user with an optional password.
    pub async fn user(&self, email: &str, password: Option<&str>) -> UserId {
        self.user_with_status(email, password, AccountStatus::Active)
            .await
    }

    pub async fn user_with_status(
        &self,
        email: &str,
        password: Option<&str>,
        status: AccountStatus,
    ) -> UserId {
        let id = UserId::generate();
        let mut conn = self.pool.acquire().await.unwrap();
        let now = self.ports.clock.now();
        let initial = if status == AccountStatus::Locked {
            AccountStatus::Active
        } else {
            status
        };
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status: initial,
                created_at: now,
            },
        )
        .await
        .unwrap();
        if status == AccountStatus::Locked {
            let until = now + time::Duration::hours(1);
            assert!(
                UserRepository::update_status(
                    &mut conn,
                    id,
                    AccountStatus::Active,
                    AccountStatus::Locked,
                    Some("soft_lock"),
                    Some(until),
                    now
                )
                .await
                .unwrap()
            );
        }
        if let Some(password) = password {
            self.set_password(id, password, false).await;
        }
        id
    }

    pub async fn set_password(&self, user: UserId, password: &str, must_change: bool) {
        let record = self.crypto.passwords.hash(&secret(password)).await.unwrap();
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::set_password(
            &mut conn,
            user,
            &NewPasswordHash {
                password_hash: &record.hash,
                algorithm: record.algorithm.as_str(),
                pepper_version: record.pepper_version,
            },
            must_change,
            self.ports.clock.now(),
        )
        .await
        .unwrap();
    }

    /// Whether `password` is the user's current password.
    pub async fn password_is(&self, user: UserId, password: &str) -> bool {
        self.service
            .verify_login_password(&self.ctx(), Some(user), &secret(password))
            .await
            .unwrap()
            .is_valid()
    }

    pub fn app(&self) -> Router {
        with_request_context(router().with_state(self.service.clone()))
    }

    pub fn app_as(&self, principal: Principal) -> Router {
        with_request_context(
            router()
                .with_state(self.service.clone())
                .layer(Extension(principal)),
        )
    }

    /// A session principal that authenticated `auth_age` ago.
    pub fn principal(&self, user: UserId, auth_age: Duration) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time: Some(self.ports.clock.now() - auth_age),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
            login_method: None,
            mfa_factors: Vec::new(),
        }
    }

    pub fn ctx(&self) -> RequestContext {
        RequestContext::system(Locale::En)
    }

    /// Requests a reset through the service, waits for the background job
    /// and returns the e-mailed `(token, code)`.
    pub async fn forgot(&self, email: &str) -> (String, Option<String>) {
        self.ports.notifier.take();
        self.service
            .request_reset(&self.ctx(), &EmailAddress::parse(email).unwrap())
            .await
            .unwrap();
        self.service.drain_background_jobs().await;
        let sent = self.ports.notifier.with_template("password_reset");
        let last = sent.last().expect("reset e-mail sent");
        match &last.kind {
            NotificationKind::PasswordReset { token, code, .. } => (
                token.expose().to_owned(),
                code.as_ref().map(|c| c.expose().to_owned()),
            ),
            other => panic!("unexpected notification {other:?}"),
        }
    }
}

pub fn secret(value: &str) -> authn_core::secret::SecretString {
    authn_core::secret::SecretString::from(value)
}

pub fn email(value: &str) -> EmailAddress {
    EmailAddress::parse(value).unwrap()
}
