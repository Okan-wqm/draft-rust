#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)] // integration-test helpers
//! Test harness: the provider over a real database with fake ports, an
//! injected browser-session principal, a controllable session liveness and
//! an **independent** JWT verifier (ed25519-dalek directly, not
//! authn-crypto's verifier) for ID tokens.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use authn_account::{AccountService, AccountServiceDeps, AccountServiceSettings, NoOrganizations};
use authn_core::domain::{
    AccountStatus, AuthMethodRef, EmailAddress, LoginMethod, Principal, PrincipalCredential,
    Subject,
};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{SessionId, UserId};
use authn_core::ports::Clock;
use authn_crypto::CryptoServices;
use authn_oidc_provider::service::ClientInput;
use authn_oidc_provider::{
    ClientAdminAccess, ClientAdminAuthorizer, OidcProviderDeps, OidcProviderService,
    OidcProviderSettings, SessionLiveness, protocol_router, router,
};
use authn_store::{NewUser, SigningKeyRepository, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::config::TestConfigBuilder;
use authn_testkit::http::{TestRequest, TestResponse, with_request_context};
use axum::{Extension, Router};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::Value;
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

pub const ISSUER: &str = "https://auth.test.example";
pub const INTERACTION: &str = "https://app.test.example/oauth/consent";
pub const WEB_REDIRECT: &str = "https://rp.example.com/cb";
pub const NATIVE_REDIRECT: &str = "http://127.0.0.1/callback";
pub const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Sessions considered live.
#[derive(Default)]
pub struct FakeLiveness {
    live: Mutex<HashSet<SessionId>>,
}

impl FakeLiveness {
    pub fn set(&self, session: SessionId, live: bool) {
        let mut set = self.live.lock().unwrap();
        if live {
            set.insert(session);
        } else {
            set.remove(&session);
        }
    }
}

#[async_trait]
impl SessionLiveness for FakeLiveness {
    async fn is_active(
        &self,
        _conn: &mut PgConnection,
        session: SessionId,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        Ok(self.live.lock().unwrap().contains(&session))
    }
}

/// Staff authorizer: allows everything unless `deny` is set.
#[derive(Default)]
pub struct FakeAdmin {
    pub deny: Mutex<bool>,
    pub calls: Mutex<Vec<ClientAdminAccess>>,
}

#[async_trait]
impl ClientAdminAuthorizer for FakeAdmin {
    async fn authorize(
        &self,
        _principal: &Principal,
        _ctx: &RequestContext,
        access: ClientAdminAccess,
    ) -> Result<(), AuthError> {
        self.calls.lock().unwrap().push(access);
        if *self.deny.lock().unwrap() {
            Err(AuthError::new(authn_core::error::codes::common::FORBIDDEN))
        } else {
            Ok(())
        }
    }
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub service: OidcProviderService,
    pub live: Arc<FakeLiveness>,
    pub admin: Arc<FakeAdmin>,
    pub user: UserId,
    pub session: SessionId,
}

pub struct Client {
    pub client_id: String,
    pub secret: Option<String>,
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        authn_core::tls::install_crypto_provider();
        let mut config = TestConfigBuilder::new().build();
        config.oidc_provider.enabled = true;
        config.oidc_provider.interaction_url = Some(INTERACTION.to_owned());
        config.oidc_provider.custom_scopes = vec!["orders:read".to_owned()];
        let ports = TestPorts::new();
        let crypto = CryptoServices::from_config(&config.crypto).await.unwrap();
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
                sessions: ports.session_revoker.clone(),
                exporters: Vec::new(),
                ownership: Arc::new(NoOrganizations),
            },
            AccountServiceSettings::from_app_config(&config).unwrap(),
        )
        .unwrap();
        // One active signing key.
        let mut conn = pool.acquire().await.unwrap();
        let key = SigningKeyRepository::create_pending(
            &mut conn,
            &crypto.envelopes,
            ports.clock.now(),
            std::time::Duration::ZERO,
        )
        .await
        .unwrap();
        SigningKeyRepository::activate(
            &mut conn,
            key.id,
            ports.clock.now(),
            std::time::Duration::from_secs(86_400),
            true,
        )
        .await
        .unwrap();
        let user = UserId::generate();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id: user,
                email: EmailAddress::parse("alice@example.com").unwrap(),
                status: AccountStatus::Active,
                created_at: ports.clock.now(),
            },
        )
        .await
        .unwrap();
        UserRepository::mark_email_verified(&mut conn, user, ports.clock.now())
            .await
            .unwrap();
        drop(conn);
        let live = Arc::new(FakeLiveness::default());
        let admin = Arc::new(FakeAdmin::default());
        let session = SessionId::generate();
        live.set(session, true);
        let service = OidcProviderService::new(
            OidcProviderDeps {
                pool: pool.clone(),
                clock: ports.clock.clone(),
                audit: ports.audit.clone(),
                rate_limiter: ports.rate_limiter.clone(),
                envelopes: crypto.envelopes.clone(),
                accounts,
                liveness: live.clone(),
                client_admin: admin.clone(),
            },
            OidcProviderSettings::from_app_config(&config).unwrap(),
        );
        Self {
            pool,
            ports,
            service,
            live,
            admin,
            user,
            session,
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        self.ports.clock.now()
    }

    /// The browser-session principal of the test user.
    pub fn principal(&self) -> Principal {
        self.principal_with(&[AuthMethodRef::Pwd], self.now())
    }

    pub fn principal_with(&self, amr: &[AuthMethodRef], auth_time: OffsetDateTime) -> Principal {
        Principal {
            subject: Subject::User { user_id: self.user },
            credential: PrincipalCredential::SessionCookie {
                session_id: self.session,
            },
            active_org: None,
            amr: amr.to_vec(),
            acr: None,
            auth_time: Some(auth_time),
            scopes: Vec::new(),
            impersonation: None,
            is_platform_admin: false,
            login_method: Some(LoginMethod::Password),
            mfa_factors: Vec::new(),
        }
    }

    fn routes(&self) -> Router<OidcProviderService> {
        router::<OidcProviderService>()
    }

    /// The app without a browser session.
    pub fn anonymous(&self) -> Router {
        with_request_context(
            self.routes()
                .merge(protocol_router())
                .with_state(self.service.clone()),
        )
    }

    /// The app with `principal` injected (as the session middleware would).
    pub fn as_principal(&self, principal: Principal) -> Router {
        let authenticated = self.routes().layer(Extension(principal));
        with_request_context(
            authenticated
                .merge(protocol_router())
                .with_state(self.service.clone()),
        )
    }

    /// The app as the signed-in test user.
    pub fn signed_in(&self) -> Router {
        self.as_principal(self.principal())
    }

    pub async fn register(&self, input: Value) -> Client {
        let input: ClientInput = serde_json::from_value(input).unwrap();
        let created = self
            .service
            .create_client_unchecked(&RequestContext::system(Default::default()), None, input)
            .await
            .unwrap();
        Client {
            client_id: created.client.client_id,
            secret: created.client_secret.map(|s| s.expose().to_owned()),
        }
    }

    /// A confidential web client (`openid profile email orders:read`).
    pub async fn web_client(&self) -> Client {
        self.register(serde_json::json!({
            "name": "Shop",
            "client_type": "confidential",
            "application_type": "web",
            "redirect_uris": [WEB_REDIRECT],
            "allowed_scopes": ["openid", "profile", "email", "orders:read"],
            "allowed_resources": ["https://api.example.com"],
        }))
        .await
    }

    /// A public native client with a loopback redirect.
    pub async fn native_client(&self) -> Client {
        self.register(serde_json::json!({
            "name": "Mobile",
            "client_type": "public",
            "application_type": "native",
            "redirect_uris": [NATIVE_REDIRECT, "com.example.app:/oauth"],
            "allowed_scopes": ["openid", "email"],
        }))
        .await
    }

    pub async fn grant_consent(&self, client: &Client, scopes: &str) {
        // Accepting one interaction records the consent.
        let location = self
            .authorize(&self.signed_in(), client, WEB_REDIRECT, scopes, &[])
            .await;
        let (r, binding) = location;
        let id = interaction_id(&r);
        let accepted = TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
            .cookie("__Host-authn_oidc_browser", &binding.unwrap())
            .send(&self.signed_in())
            .await;
        assert_eq!(accepted.status, 200, "{}", accepted.text());
    }

    /// `GET /authorize`; returns the `Location` and the binding cookie.
    pub async fn authorize(
        &self,
        app: &Router,
        client: &Client,
        redirect_uri: &str,
        scope: &str,
        extra: &[(&str, &str)],
    ) -> (String, Option<String>) {
        let mut params: Vec<(String, String)> = vec![
            ("client_id".into(), client.client_id.clone()),
            ("redirect_uri".into(), redirect_uri.into()),
            ("response_type".into(), "code".into()),
            ("scope".into(), scope.into()),
            ("state".into(), "st-123".into()),
            ("nonce".into(), "n-456".into()),
            ("code_challenge".into(), CHALLENGE.into()),
            ("code_challenge_method".into(), "S256".into()),
        ];
        for (k, v) in extra {
            params.retain(|(name, _)| name != k || *k == "resource");
            if !v.is_empty() {
                params.push(((*k).into(), (*v).into()));
            }
        }
        let query = serde_urlencoded::to_string(&params).unwrap();
        let r = TestRequest::get(&format!("/v1/oauth2/authorize?{query}"))
            .send(app)
            .await;
        assert_eq!(r.status, 303, "{}", r.text());
        let binding = r
            .set_cookies()
            .iter()
            .find_map(|c| c.strip_prefix("__Host-authn_oidc_browser="))
            .map(|c| c.split(';').next().unwrap().to_owned());
        (r.header("location").unwrap().to_owned(), binding)
    }

    /// Runs `/authorize` as the signed-in user (accepting the interaction
    /// if one is needed); returns the code.
    pub async fn code_for(&self, client: &Client, redirect_uri: &str, scope: &str) -> String {
        let (location, binding) = self
            .authorize(&self.signed_in(), client, redirect_uri, scope, &[])
            .await;
        if !location.starts_with(INTERACTION) {
            return query_param(&location, "code").unwrap();
        }
        let id = interaction_id(&location);
        let r = TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
            .cookie("__Host-authn_oidc_browser", &binding.unwrap())
            .send(&self.signed_in())
            .await;
        assert_eq!(r.status, 200, "{}", r.text());
        query_param(r.json::<Value>()["redirect_to"].as_str().unwrap(), "code").unwrap()
    }

    /// `POST /token` with form `fields`; `basic`: client_secret_basic.
    pub async fn token(
        &self,
        client: &Client,
        fields: &[(&str, &str)],
        basic: bool,
    ) -> TestResponse {
        let mut form: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let mut request = TestRequest::post("/v1/oauth2/token")
            .header("content-type", "application/x-www-form-urlencoded");
        match (&client.secret, basic) {
            (Some(secret), true) => {
                let creds = STANDARD.encode(format!("{}:{secret}", client.client_id));
                request = request.header("authorization", &format!("Basic {creds}"));
            }
            (Some(secret), false) => {
                form.push(("client_id".into(), client.client_id.clone()));
                form.push(("client_secret".into(), secret.clone()));
            }
            (None, _) => form.push(("client_id".into(), client.client_id.clone())),
        }
        request
            .body(serde_urlencoded::to_string(&form).unwrap())
            .send(&self.anonymous())
            .await
    }

    pub async fn exchange(&self, client: &Client, code: &str, redirect_uri: &str) -> TestResponse {
        self.token(
            client,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", VERIFIER),
            ],
            true,
        )
        .await
    }

    pub async fn userinfo(&self, access_token: &str) -> TestResponse {
        TestRequest::get("/v1/oauth2/userinfo")
            .bearer(access_token)
            .send(&self.anonymous())
            .await
    }

    pub async fn form_post(
        &self,
        path: &str,
        client: &Client,
        fields: &[(&str, &str)],
    ) -> TestResponse {
        let mut form: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let mut request =
            TestRequest::post(path).header("content-type", "application/x-www-form-urlencoded");
        match &client.secret {
            Some(secret) => {
                let creds = STANDARD.encode(format!("{}:{secret}", client.client_id));
                request = request.header("authorization", &format!("Basic {creds}"));
            }
            None => form.push(("client_id".into(), client.client_id.clone())),
        }
        request
            .body(serde_urlencoded::to_string(&form).unwrap())
            .send(&self.anonymous())
            .await
    }

    /// The JWKS as `kid → public key`, from the store.
    pub async fn jwks(&self) -> BTreeMap<String, ed25519_dalek::VerifyingKey> {
        let set = SigningKeyRepository::jwks(&self.pool, self.now())
            .await
            .unwrap();
        let value = serde_json::to_value(set).unwrap();
        value["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| {
                assert_eq!(k["kty"], "OKP");
                assert_eq!(k["crv"], "Ed25519");
                let x = URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap();
                (
                    k["kid"].as_str().unwrap().to_owned(),
                    ed25519_dalek::VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap(),
                )
            })
            .collect()
    }

    /// Independent JWS verification: returns (header, claims).
    pub async fn verify_independently(&self, jwt: &str) -> (Value, Value) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        let keys = self.jwks().await;
        let key = keys
            .get(header["kid"].as_str().unwrap())
            .expect("kid in JWKS");
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        key.verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .expect("signature verifies");
        (header, claims)
    }
}

pub fn query_param(location: &str, name: &str) -> Option<String> {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

pub fn interaction_id(location: &str) -> String {
    assert!(location.starts_with(INTERACTION), "{location}");
    query_param(location, "interaction_id").unwrap()
}

/// OIDC Core §3.1.3.6 `at_hash` for EdDSA/Ed25519 (SHA-512), computed
/// independently of the provider.
pub fn expected_at_hash(access_token: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha512::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..32])
}
