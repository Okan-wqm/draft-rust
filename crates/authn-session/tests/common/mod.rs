//! Shared harness of the authn-session integration tests: the real wave-A
//! services (password, MFA, passkeys, organizations, accounts) over one
//! database, the testkit fakes for the ports, and the session router behind
//! the authentication middleware.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod browser;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use authn_account::{AccountService, AccountServiceDeps, AccountServiceSettings, NoOrganizations};
use authn_core::config::AppConfig;
use authn_core::domain::{
    AccountStatus, AuthMethodRef, EmailAddress, Locale, LoginMethod, Principal,
    PrincipalCredential, Subject,
};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, RequestId, SessionId, UserId};
use authn_core::ports::Clock;
use authn_core::secret::SecretString;
use authn_crypto::CryptoServices;
use authn_crypto::token::OpaqueToken;
use authn_mfa::{MfaService, MfaServiceDeps, MfaServiceSettings, StaticMfaPolicySource};
use authn_org::{OrgPolicyInput, OrgService, OrgServiceDeps, OrgServiceSettings};
use authn_password::{
    NoOtherLoginMethods, NoProfiles, PasswordService, PasswordServiceDeps, PasswordServiceSettings,
};
use authn_session::cookies::{PRE_SESSION_COOKIE, SESSION_COOKIE};
use authn_session::{
    ClientChannel, DeviceInfo, EstablishSession, EstablishedSession, IssuedCredentials,
    PgSessionRevoker, SessionService, SessionServiceDeps, SessionSettings, VerifiedOrg,
};
use authn_store::{NewPasswordHash, NewUser, SigningKeyRepository, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::http::{TestRequest, TestResponse, with_request_context};
use authn_webauthn::{
    PasswordOnlyMethods, UnrestrictedPolicySource, WebauthnService, WebauthnServiceDeps,
    WebauthnServiceSettings,
};
use axum::Router;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::get;
use sqlx::PgPool;

/// Origin of `server.public_base_url` in the test configuration.
pub const ORIGIN: &str = "https://auth.test.example";
/// A password accepted by every policy.
pub const PASSWORD: &str = "tramway galaxy orchid lantern 47";

/// A web session as a browser holds it.
#[derive(Debug, Clone)]
pub struct WebLogin {
    pub user: UserId,
    pub session_id: SessionId,
    pub cookie: String,
    pub csrf: String,
}

/// A native session as an app holds it.
#[derive(Debug, Clone)]
pub struct NativeLogin {
    pub user: UserId,
    pub session_id: SessionId,
    pub access: String,
    pub refresh: String,
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub crypto: CryptoServices,
    pub config: AppConfig,
    pub service: SessionService,
    pub mfa: MfaService,
    pub orgs: OrgService,
    pub accounts: AccountService,
    pub webauthn: WebauthnService,
    pub revoker: PgSessionRevoker,
    pub app: Router,
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut AppConfig)) -> Self {
        authn_testkit::init_tracing();
        let mut config = authn_testkit::config::test_config();
        tweak(&mut config);
        let crypto = CryptoServices::from_config(&config.crypto).await.unwrap();
        let ports = TestPorts::new();
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
                audit: ports.audit.clone(),
                sms: None,
                policy_source: Arc::new(StaticMfaPolicySource::default()),
            },
            MfaServiceSettings::from_app_config(&config),
        )
        .unwrap();
        let revoker = PgSessionRevoker::new(
            ports.clock.clone(),
            ports.audit.clone(),
            ports.events.clone(),
            mfa.clone(),
        );
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
                audit: ports.audit.clone(),
                events: ports.events.clone(),
                sessions: Arc::new(revoker.clone()),
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
                audit: ports.audit.clone(),
                sessions: Arc::new(revoker.clone()),
                breach_checker: ports.breached_passwords.clone(),
                login_methods: Arc::new(NoOtherLoginMethods),
                profiles: Arc::new(NoProfiles),
            },
            PasswordServiceSettings::from_app_config(&config),
        );
        let webauthn = WebauthnService::new(
            WebauthnServiceDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                rate_limiter: ports.rate_limiter.clone(),
                notifier: ports.notifier.clone(),
                audit: ports.audit.clone(),
                account_methods: Arc::new(PasswordOnlyMethods),
                policy_source: Arc::new(UnrestrictedPolicySource),
            },
            WebauthnServiceSettings::from_app_config(&config).unwrap(),
        )
        .unwrap();
        let orgs = OrgService::new(
            OrgServiceDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                audit: ports.audit.clone(),
                events: ports.events.clone(),
                notifier: ports.notifier.clone(),
                rate_limiter: ports.rate_limiter.clone(),
                session_revoker: Arc::new(revoker.clone()),
                dns: ports.dns.clone(),
            },
            OrgServiceSettings::from_app_config(&config),
        );
        let protect_hasher = authn_protect::KeyHasher::new(&crypto.keys).unwrap();
        let captcha = authn_protect::CaptchaService::new(
            ports.captcha.clone(),
            ports.rate_limiter.clone(),
            ports.audit.clone(),
            ports.clock.clone(),
            &config.protect.captcha,
        );
        let risk_store = authn_protect::risk::RiskStore::new(pool.clone(), protect_hasher.clone());
        let protection = authn_protect::LoginProtection::new(
            pool.clone(),
            ports.clock.clone(),
            ports.rate_limiter.clone(),
            ports.audit.clone(),
            captcha,
            risk_store,
            &config.protect,
        );
        let evaluator = authn_protect::DefaultRiskEvaluator::new(
            pool.clone(),
            protect_hasher,
            ports.rate_limiter.clone(),
            &config.protect.risk,
            None,
        )
        .unwrap();
        let risk_alerts = authn_protect::RiskAlerts::new(
            evaluator,
            ports.notifier.clone(),
            ports.audit.clone(),
            ports.rate_limiter.clone(),
            ports.clock.clone(),
        );
        let service = SessionService::new(
            SessionServiceDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                keys: crypto.keys.clone(),
                envelopes: crypto.envelopes.clone(),
                rate_limiter: ports.rate_limiter.clone(),
                audit: ports.audit.clone(),
                events: ports.events.clone(),
                notifier: ports.notifier.clone(),
                passwords,
                mfa: mfa.clone(),
                webauthn: webauthn.clone(),
                orgs: orgs.clone(),
                accounts: accounts.clone(),
                protection,
                risk: ports.risk.clone(),
                risk_alerts,
                otp: crypto.otp.clone(),
            },
            SessionSettings::from_app_config(&config),
        )
        .unwrap();
        // The session router plus two probe routes standing in for other
        // modules' endpoints.
        let probes: Router<SessionService> = Router::new()
            .route("/v1/probe", get(probe).post(probe))
            .route("/v1/orgs/{org_id}/probe", get(probe));
        let app = with_request_context(
            authn_session::router::<SessionService>()
                .merge(probes)
                .fallback(authn_core::http::not_found_fallback)
                .with_state(service.clone())
                .layer(axum::middleware::from_fn_with_state(
                    service.clone(),
                    authn_session::authenticate,
                )),
        );
        Self {
            pool,
            ports,
            crypto,
            config,
            service,
            mfa,
            orgs,
            accounts,
            webauthn,
            revoker,
            app,
        }
    }

    pub fn now(&self) -> time::OffsetDateTime {
        self.ports.clock.now()
    }

    pub fn advance(&self, by: Duration) {
        self.ports.clock.advance(by);
    }

    pub fn ctx(&self) -> RequestContext {
        self.ctx_from("203.0.113.10".parse().unwrap(), None)
    }

    pub fn ctx_from(&self, ip: IpAddr, device: Option<&str>) -> RequestContext {
        RequestContext {
            request_id: RequestId::generate(),
            client_ip: ip,
            peer_ip: ip,
            user_agent: Some(
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".into(),
            ),
            device_id: device.map(str::to_owned),
            locale: Locale::En,
        }
    }

    /// An active, verified user with a password.
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
        UserRepository::mark_email_verified(&mut conn, id, self.now())
            .await
            .unwrap();
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

    pub async fn make_admin(&self, user: UserId) {
        sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
            .bind(user)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// Headers of a browser login request that passed `GET /v1/csrf`.
    pub fn login_headers(&self) -> HeaderMap {
        let secret = OpaqueToken::generate().unwrap();
        let token = self.service.csrf().pre_session_token(&secret).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static(ORIGIN));
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{PRE_SESSION_COOKIE}={}", secret.expose())).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-csrf-token"),
            HeaderValue::from_str(&token).unwrap(),
        );
        headers
    }

    pub fn web_channel(&self) -> ClientChannel {
        ClientChannel::Web(
            self.service
                .verify_login_csrf(&self.login_headers())
                .unwrap(),
        )
    }

    pub fn request(&self, user: UserId, client: ClientChannel) -> EstablishSession {
        EstablishSession {
            user_id: user,
            method: LoginMethod::Password,
            amr: vec![AuthMethodRef::Pwd],
            mfa_factors: Vec::new(),
            acr: None,
            auth_time: self.now(),
            client,
            remember_me: false,
            shared_device: false,
            org: None,
            device: DeviceInfo::from_context(&self.ctx()),
        }
    }

    pub async fn establish(&self, request: EstablishSession) -> EstablishedSession {
        let mut tx = self.service.begin().await.unwrap();
        let established = self
            .service
            .establish(&mut tx, &self.ctx(), request)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        established
    }

    pub async fn verified_org(&self, user: UserId, org: OrgId) -> VerifiedOrg {
        let mut conn = self.pool.acquire().await.unwrap();
        self.service
            .verify_login_org(&mut conn, &self.ctx(), user, org, LoginMethod::Password)
            .await
            .unwrap()
    }

    pub async fn web_login(&self, user: UserId) -> WebLogin {
        let request = self.request(user, self.web_channel());
        web_of(self.establish(request).await)
    }

    pub async fn native_login(&self, user: UserId) -> NativeLogin {
        let request = self.request(user, ClientChannel::Native);
        native_of(self.establish(request).await)
    }

    /// A state-changing browser request with session cookie, origin and
    /// CSRF token.
    pub fn web_post(&self, path: &str, login: &WebLogin) -> TestRequest {
        TestRequest::post(path)
            .cookie(SESSION_COOKIE, &login.cookie)
            .header("origin", ORIGIN)
            .header("x-csrf-token", &login.csrf)
    }

    pub fn web_get(&self, path: &str, login: &WebLogin) -> TestRequest {
        TestRequest::get(path).cookie(SESSION_COOKIE, &login.cookie)
    }

    pub async fn send(&self, request: TestRequest) -> TestResponse {
        request.send(&self.app).await
    }

    /// A step-up-fresh principal for calling other services directly.
    pub fn fresh(&self, user: UserId) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time: Some(self.now()),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
            login_method: None,
            mfa_factors: Vec::new(),
        }
    }

    /// An organization owned by `owner`.
    pub async fn org(&self, owner: UserId, slug: &str) -> OrgId {
        self.orgs
            .create_organization(
                &self.ctx(),
                &self.fresh(owner),
                authn_org::service::orgs::CreateOrganization {
                    name: format!("Org {slug}"),
                    slug: slug.to_owned(),
                },
            )
            .await
            .unwrap()
            .id
    }

    pub async fn add_member(&self, org: OrgId, user: UserId) {
        sqlx::query(
            "INSERT INTO memberships (id, org_id, user_id, role_id, status) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(org)
        .bind(user)
        .bind(authn_org::BuiltinRole::Member.id())
        .execute(&self.pool)
        .await
        .unwrap();
    }

    /// Sets an organization policy as `owner` with a phishing-resistant
    /// session from `198.51.100.7` (so the lock-out guard never trips).
    pub async fn set_policy(&self, owner: UserId, org: OrgId, input: OrgPolicyInput) {
        let mut principal = self.fresh(owner);
        principal.amr = vec![AuthMethodRef::Hwk, AuthMethodRef::User, AuthMethodRef::Mfa];
        // A login method the new policy allows (K-57 lock-out guard).
        principal.login_method = Some(
            input
                .allowed_login_methods
                .as_ref()
                .and_then(|methods| methods.first().copied())
                .unwrap_or(authn_core::domain::LoginMethod::Passkey),
        );
        self.orgs
            .update_policy(
                &self.ctx_from("198.51.100.7".parse().unwrap(), None),
                &principal,
                org,
                input,
            )
            .await
            .unwrap();
    }

    /// Enrolls and confirms a TOTP factor; returns its secret.
    pub async fn enroll_totp(&self, user: UserId) -> authn_crypto::totp::TotpSecret {
        let enrollment = self
            .mfa
            .begin_totp_enrollment(&self.ctx(), &self.fresh(user), Some("Phone".into()))
            .await
            .unwrap();
        let secret =
            authn_crypto::totp::TotpSecret::from_base32(&enrollment.provisioning.secret_base32)
                .unwrap();
        let code = self.totp_code(&secret);
        self.mfa
            .confirm_enrollment(
                &self.ctx(),
                &self.fresh(user),
                enrollment.factor.id,
                &SecretString::from(code),
            )
            .await
            .unwrap();
        self.advance(Duration::from_secs(30));
        secret
    }

    /// The current TOTP code.
    pub fn totp_code(&self, secret: &authn_crypto::totp::TotpSecret) -> String {
        let totp =
            authn_crypto::totp::Totp::new(authn_crypto::totp::TotpParams::default()).unwrap();
        let step = totp.time_step(self.now()).unwrap();
        totp.code_for_step(secret, step).unwrap().to_string()
    }

    pub async fn api_key(&self, owner: UserId, org: OrgId) -> String {
        let created = self
            .orgs
            .create_api_key(
                &self.ctx(),
                &self.fresh(owner),
                org,
                authn_org::service::api_keys::CreateApiKey {
                    name: "resource server".into(),
                    scopes: vec!["org:read".into()],
                    expires_at: None,
                    service_account_id: None,
                },
            )
            .await
            .unwrap();
        created.key.expose().to_owned()
    }

    pub async fn count(&self, sql: &'static str, id: uuid::Uuid) -> i64 {
        sqlx::query_scalar(sql)
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// A committed pending challenge of `user` (no device binding);
    /// returns its id and token.
    pub async fn pending_challenge(
        &self,
        user: UserId,
        kind: authn_session::ChallengeKind,
        session: Option<SessionId>,
    ) -> (authn_core::id::ChallengeId, String) {
        let mut tx = self.service.begin().await.unwrap();
        let issued = self
            .service
            .create_challenge(
                &mut tx,
                &self.ctx(),
                authn_session::NewChallenge {
                    kind,
                    user_id: user,
                    client_kind: authn_core::domain::ClientKind::Web,
                    primary_method: Some(LoginMethod::Password),
                    amr: vec![AuthMethodRef::Pwd],
                    first_factor_at: Some(self.now()),
                    allowed_factors: vec![authn_core::domain::FactorKind::Totp],
                    required_actions: vec![authn_core::ports::RequiredAction::VerifyMfa],
                    remember_me: false,
                    shared_device: false,
                    requested_org: None,
                    risk_level: None,
                    session_id: session,
                    metadata: serde_json::Map::new(),
                },
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (issued.challenge.id, issued.token.expose().to_owned())
    }

    /// Whether the challenge of `token` can still be opened (the opening
    /// transaction is rolled back).
    pub async fn challenge_open(&self, token: &str, kind: authn_session::ChallengeKind) -> bool {
        let mut tx = self.service.begin().await.unwrap();
        self.service
            .open_challenge(
                &mut tx,
                &self.ctx(),
                token,
                kind,
                authn_core::domain::ClientKind::Web,
            )
            .await
            .is_ok()
    }

    pub async fn revoked_reason(&self, session: SessionId) -> Option<String> {
        sqlx::query_scalar("SELECT revoked_reason FROM sessions WHERE id = $1")
            .bind(session)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

pub fn empty_policy() -> OrgPolicyInput {
    OrgPolicyInput {
        mfa_required: false,
        phishing_resistant_mfa_required: false,
        allowed_login_methods: None,
        allowed_mfa_factors: None,
        max_session_lifetime_seconds: None,
        ip_allowlist: None,
        trusted_devices_allowed: true,
        allowed_passkey_aaguids: None,
    }
}

pub fn web_of(established: EstablishedSession) -> WebLogin {
    let IssuedCredentials::Web {
        session_token,
        csrf_token,
        ..
    } = established.credentials
    else {
        panic!("expected web credentials")
    };
    WebLogin {
        user: established.session.user_id,
        session_id: established.session.id,
        cookie: session_token.expose().to_owned(),
        csrf: csrf_token,
    }
}

pub fn native_of(established: EstablishedSession) -> NativeLogin {
    let IssuedCredentials::Native {
        access_token,
        refresh_token,
        ..
    } = established.credentials
    else {
        panic!("expected native credentials")
    };
    NativeLogin {
        user: established.session.user_id,
        session_id: established.session.id,
        access: access_token.expose().to_owned(),
        refresh: refresh_token.expose().to_owned(),
    }
}

/// The value of `name` in the `Set-Cookie` headers, if set.
pub fn set_cookie<'a>(cookies: &'a [String], name: &str) -> Option<&'a String> {
    cookies.iter().find(|c| c.starts_with(&format!("{name}=")))
}

/// The cookie value of a `Set-Cookie` header line.
pub fn cookie_value(line: &str) -> String {
    let first = line.split(';').next().unwrap();
    first.split_once('=').unwrap().1.to_owned()
}

/// The principal echoed by the probe route.
async fn probe(principal: Option<Principal>) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "authenticated": principal.is_some(),
        "user_id": principal.as_ref().and_then(Principal::user_id),
        "session_id": principal.as_ref().and_then(Principal::session_id),
        "active_org": principal.as_ref().and_then(|p| p.active_org),
        "amr": principal.as_ref().map(|p| p.amr.clone()),
        "impersonated": principal.as_ref().is_some_and(Principal::is_impersonated),
        "is_platform_admin": principal.as_ref().is_some_and(|p| p.is_platform_admin),
    }))
}

/// Decodes the payload of a JWT without verification (tests only).
pub fn jwt_payload(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).unwrap();
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Session row columns used by the tests.
pub async fn session_row(
    pool: &PgPool,
    id: SessionId,
) -> (bool, time::OffsetDateTime, time::OffsetDateTime) {
    sqlx::query_as::<_, (bool, time::OffsetDateTime, time::OffsetDateTime)>(
        "SELECT revoked_at IS NOT NULL, idle_expires_at, absolute_expires_at FROM sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}
