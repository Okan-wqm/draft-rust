//! Shared harness of the authn-webauthn integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_core::domain::{
    AccountStatus, AuthMethodRef, EmailAddress, Impersonation, Locale, LoginMethod, Principal,
    PrincipalCredential, Subject,
};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{ApiKeyId, ChallengeId, CredentialId, OrgId, RequestId, SessionId, UserId};
use authn_core::ports::Clock;
use authn_core::secret::SensitiveString;
use authn_store::{NewPasswordHash, NewUser, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::http::with_request_context;
use authn_webauthn::service::RegistrationIntent;
use authn_webauthn::{
    AccountMethodsSource, AuthenticatedPasskey, AuthenticationFinish, AuthenticationStart,
    AuthenticationTarget, MfaFacts, PasskeyPolicy, PasskeyPolicySource, PasskeySummary,
    PasswordOnlyMethods, RegistrationOptionsRequest, RegistrationStart, RegistrationVerifyRequest,
    WebauthnService, WebauthnServiceDeps, WebauthnServiceSettings, router,
};
use axum::{Extension, Router};
use serde_json::Value;
use sqlx::{PgConnection, PgPool};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::{
    AllowCredentials, CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, UserVerificationPolicy,
};

/// The relying-party origin of the test configuration.
pub const ORIGIN: &str = "https://auth.test.example";

/// Configurable other login methods / MFA facts (the real password lookup
/// of [`PasswordOnlyMethods`] plus a "social identity" switch).
#[derive(Debug, Default)]
pub struct TestMethods {
    pub social: AtomicBool,
    pub mfa: Mutex<MfaFacts>,
}

#[async_trait]
impl AccountMethodsSource for TestMethods {
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError> {
        let mut methods = PasswordOnlyMethods.other_login_methods(conn, user).await?;
        if self.social.load(Ordering::SeqCst) {
            methods.push(LoginMethod::Social);
        }
        Ok(methods)
    }

    async fn mfa_facts(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<MfaFacts, AuthError> {
        Ok(*self.mfa.lock().unwrap())
    }
}

/// Mutable organization passkey policy.
#[derive(Debug, Default)]
pub struct TestPolicy {
    pub policy: Mutex<PasskeyPolicy>,
}

#[async_trait]
impl PasskeyPolicySource for TestPolicy {
    async fn policy_for_user(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
        _active_org: Option<OrgId>,
    ) -> Result<PasskeyPolicy, AuthError> {
        Ok(self.policy.lock().unwrap().clone())
    }
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub service: WebauthnService,
    pub settings: WebauthnServiceSettings,
    pub methods: Arc<TestMethods>,
    pub policy: Arc<TestPolicy>,
}

/// A user with a live session.
#[derive(Debug, Clone, Copy)]
pub struct Account {
    pub user: UserId,
    pub session: SessionId,
}

/// A registered passkey and what the client knows about it.
#[derive(Debug, Clone)]
pub struct Registered {
    pub summary: PasskeySummary,
    pub raw_id: Vec<u8>,
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut WebauthnServiceSettings)) -> Self {
        authn_testkit::init_tracing();
        let config = authn_testkit::config::test_config();
        let mut settings = WebauthnServiceSettings::from_app_config(&config).unwrap();
        tweak(&mut settings);
        let ports = TestPorts::new();
        let methods = Arc::new(TestMethods::default());
        let policy = Arc::new(TestPolicy::default());
        let service = Self::build(&pool, &ports, &methods, &policy, settings.clone());
        Self {
            pool,
            ports,
            service,
            settings,
            methods,
            policy,
        }
    }

    fn build(
        pool: &PgPool,
        ports: &TestPorts,
        methods: &Arc<TestMethods>,
        policy: &Arc<TestPolicy>,
        settings: WebauthnServiceSettings,
    ) -> WebauthnService {
        let deps = WebauthnServiceDeps {
            pool: pool.clone(),
            clock: ports.clock.clone(),
            rate_limiter: ports.rate_limiter.clone(),
            notifier: ports.notifier.clone(),
            audit: ports.audit.clone(),
            account_methods: methods.clone(),
            policy_source: policy.clone(),
        };
        WebauthnService::new(deps, settings).unwrap()
    }

    /// The same harness (database, ports) with other settings.
    pub fn service_with(
        &self,
        tweak: impl FnOnce(&mut WebauthnServiceSettings),
    ) -> WebauthnService {
        let mut settings = self.settings.clone();
        tweak(&mut settings);
        Self::build(
            &self.pool,
            &self.ports,
            &self.methods,
            &self.policy,
            settings,
        )
    }

    pub fn now(&self) -> time::OffsetDateTime {
        self.ports.clock.now()
    }

    pub fn advance(&self, by: Duration) {
        self.ports.clock.advance(by);
    }

    pub async fn user(&self, email: &str) -> UserId {
        let id = UserId::generate();
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status: AccountStatus::Active,
                created_at: self.now(),
            },
        )
        .await
        .unwrap();
        id
    }

    /// A session row (owned by authn-session; fixture only).
    pub async fn session(&self, user: UserId) -> SessionId {
        let id = SessionId::generate();
        let token_hash = authn_crypto::sha256(id.to_string().as_bytes());
        let now = self.now();
        sqlx::query(
            "INSERT INTO sessions (id, user_id, client_kind, token_hash, amr, auth_time, \
             created_at, last_seen_at, idle_expires_at, absolute_expires_at) \
             VALUES ($1, $2, 'web', $3, ARRAY['pwd'], $4, $4, $4, $5, $6)",
        )
        .bind(id)
        .bind(user)
        .bind(token_hash.as_slice())
        .bind(now)
        .bind(now + Duration::from_secs(7200))
        .bind(now + Duration::from_secs(43_200))
        .execute(&self.pool)
        .await
        .unwrap();
        id
    }

    /// A login challenge row (owned by authn-session; fixture only).
    pub async fn challenge(&self, user: UserId) -> ChallengeId {
        let id = ChallengeId::generate();
        let token_hash = authn_crypto::sha256(id.to_string().as_bytes());
        sqlx::query(
            "INSERT INTO auth_challenges (id, kind, user_id, token_hash, client_kind, created_at, \
             expires_at) VALUES ($1, 'login', $2, $3, 'web', $4, $5)",
        )
        .bind(id)
        .bind(user)
        .bind(token_hash.as_slice())
        .bind(self.now())
        .bind(self.now() + Duration::from_secs(300))
        .execute(&self.pool)
        .await
        .unwrap();
        id
    }

    pub async fn account(&self, email: &str) -> Account {
        let user = self.user(email).await;
        let session = self.session(user).await;
        Account { user, session }
    }

    pub async fn set_password(&self, user: UserId) {
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::set_password(
            &mut conn,
            user,
            &NewPasswordHash {
                password_hash: &SensitiveString::new(
                    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
                ),
                algorithm: "argon2id",
                pepper_version: Some(1),
            },
            false,
            self.now(),
        )
        .await
        .unwrap();
    }

    /// A session principal that authenticated `auth_age` ago.
    pub fn principal(&self, account: Account, auth_age: Duration) -> Principal {
        Principal {
            subject: Subject::User {
                user_id: account.user,
            },
            credential: PrincipalCredential::SessionCookie {
                session_id: account.session,
            },
            active_org: None,
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time: Some(self.now() - auth_age),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
            login_method: None,
            mfa_factors: Vec::new(),
        }
    }

    /// A step-up-fresh principal.
    pub fn fresh(&self, account: Account) -> Principal {
        self.principal(account, Duration::from_secs(5))
    }

    /// A principal whose authentication is older than the step-up window.
    pub fn stale(&self, account: Account) -> Principal {
        self.principal(account, Duration::from_secs(3600))
    }

    pub fn impersonated(&self, account: Account, read_only: bool) -> Principal {
        let mut p = self.fresh(account);
        p.impersonation = Some(Impersonation {
            admin_user_id: UserId::generate(),
            read_only,
            expires_at: self.now() + Duration::from_secs(900),
        });
        p
    }

    pub fn api_key_principal(&self, user: UserId) -> Principal {
        let mut p = self.fresh(Account {
            user,
            session: SessionId::generate(),
        });
        p.credential = PrincipalCredential::ApiKey {
            api_key_id: ApiKeyId::generate(),
        };
        p
    }

    pub fn ctx(&self) -> RequestContext {
        self.ctx_from("203.0.113.10".parse().unwrap())
    }

    pub fn ctx_from(&self, ip: IpAddr) -> RequestContext {
        RequestContext {
            request_id: RequestId::generate(),
            client_ip: ip,
            peer_ip: ip,
            user_agent: Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0".to_owned()),
            device_id: None,
            locale: Locale::En,
        }
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

    // --- ceremonies ---------------------------------------------------------

    pub async fn start_registration(
        &self,
        principal: &Principal,
        intent: RegistrationIntent,
    ) -> Result<RegistrationStart, AuthError> {
        self.service
            .start_registration(
                &self.ctx(),
                principal,
                RegistrationOptionsRequest {
                    name: None,
                    usage: Some(intent),
                },
            )
            .await
    }

    pub async fn finish_registration(
        &self,
        principal: &Principal,
        start: &RegistrationStart,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<PasskeySummary, AuthError> {
        self.service
            .finish_registration(
                &self.ctx(),
                principal,
                RegistrationVerifyRequest {
                    ceremony_id: start.ceremony_id,
                    credential: serde_json::to_value(credential).unwrap(),
                    name: None,
                },
            )
            .await
    }

    /// Registers a passkey with `authenticator` (step-up-fresh session).
    pub async fn register(
        &self,
        authenticator: &mut impl WebauthnAuthenticator,
        account: Account,
        intent: RegistrationIntent,
    ) -> Registered {
        let principal = self.fresh(account);
        let start = self.start_registration(&principal, intent).await.unwrap();
        let credential = create(authenticator, &start.options, ORIGIN);
        let summary = self
            .finish_registration(&principal, &start, &credential)
            .await
            .unwrap();
        Registered {
            summary,
            raw_id: credential.raw_id.clone(),
        }
    }

    pub async fn start_auth(&self, target: AuthenticationTarget) -> AuthenticationStart {
        self.service
            .start_authentication(&self.ctx(), target, &PasskeyPolicy::unrestricted())
            .await
            .unwrap()
    }

    pub async fn finish_auth(
        &self,
        start: &AuthenticationStart,
        target: AuthenticationTarget,
        credential: &PublicKeyCredential,
    ) -> Result<AuthenticatedPasskey, AuthError> {
        self.service
            .finish_authentication(
                &self.ctx(),
                AuthenticationFinish {
                    ceremony_id: start.ceremony_id,
                    binding_token: start.binding_token.clone(),
                    target,
                    credential: serde_json::to_value(credential).unwrap(),
                },
            )
            .await
    }

    /// The stored user handle of a user.
    pub async fn user_handle(&self, user: UserId) -> Vec<u8> {
        let (handle,): (Vec<u8>,) =
            sqlx::query_as("SELECT user_handle FROM webauthn_user_handles WHERE user_id = $1")
                .bind(user)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        handle
    }

    /// Stored signature counter of a passkey.
    pub async fn sign_count(&self, id: CredentialId) -> i64 {
        let (count,): (i64,) =
            sqlx::query_as("SELECT sign_count FROM webauthn_credentials WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        count
    }

    /// Simulates another copy of the authenticator having been used: moves
    /// the stored counter (column and serialized credential) forward.
    pub async fn bump_stored_counter(&self, id: CredentialId, counter: u32) {
        sqlx::query(
            "UPDATE webauthn_credentials SET sign_count = $2, \
             passkey = jsonb_set(passkey, '{counter}', to_jsonb($2::bigint)) WHERE id = $1",
        )
        .bind(id)
        .bind(i64::from(counter))
        .execute(&self.pool)
        .await
        .unwrap();
    }
}

/// Runs `navigator.credentials.create()` with the software authenticator.
pub fn create(
    authenticator: &mut impl WebauthnAuthenticator,
    options: &Value,
    origin: &str,
) -> RegisterPublicKeyCredential {
    let ccr: CreationChallengeResponse = serde_json::from_value(options.clone()).unwrap();
    authenticator
        .do_registration(Url::parse(origin).unwrap(), ccr)
        .expect("authenticator registration")
}

/// Runs `navigator.credentials.get()` with the software authenticator.
pub fn get(
    authenticator: &mut impl WebauthnAuthenticator,
    options: &Value,
    origin: &str,
) -> PublicKeyCredential {
    let rcr: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
    authenticator
        .do_authentication(Url::parse(origin).unwrap(), rcr)
        .expect("authenticator assertion")
}

/// Discoverable login with the software authenticator. `SoftPasskey`
/// cannot store resident keys, so the platform's choice of the resident
/// credential is simulated: the credential id is presented to the
/// authenticator and the user handle is returned with the assertion, as a
/// discoverable authenticator does (the user handle is not signed).
pub fn get_discoverable(
    authenticator: &mut SoftPasskey,
    options: &Value,
    raw_id: &[u8],
    user_handle: &[u8],
    origin: &str,
) -> PublicKeyCredential {
    let mut rcr: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
    assert!(rcr.public_key.allow_credentials.is_empty());
    rcr.public_key.allow_credentials = vec![AllowCredentials {
        type_: "public-key".to_owned(),
        id: raw_id.to_vec(),
        transports: None,
    }];
    let mut credential = authenticator
        .do_authentication(Url::parse(origin).unwrap(), rcr)
        .expect("authenticator assertion");
    credential.response.user_handle = Some(user_handle.to_vec());
    credential
}

/// Options with the user-verification requirement downgraded by a
/// malicious / legacy client.
pub fn downgrade_uv(options: &Value) -> Value {
    let mut rcr: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
    rcr.public_key.user_verification = UserVerificationPolicy::Preferred;
    serde_json::to_value(rcr).unwrap()
}

/// Runs the futures concurrently as separate tasks and collects their
/// results (race tests).
pub async fn spawn_all<T, F>(futures: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for future in futures {
        set.spawn(future);
    }
    let mut results = Vec::new();
    while let Some(result) = set.join_next().await {
        results.push(result.unwrap());
    }
    results
}
