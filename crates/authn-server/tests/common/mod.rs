//! The real application (every module, every layer) over PostgreSQL, with
//! testkit fakes for the outside world (clock, notifications, DNS, HIBP,
//! outbound HTTP). No network (TST-08).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod idp;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::ports::{Clock, NotificationKind};
use authn_server::app::build_router;
use authn_server::services::{Ports, Services};
use authn_server::state::AppState;
use authn_testkit::TestPorts;
use authn_testkit::http::{TestRequest, TestResponse};
use axum::Router;
use serde_json::Value;
use sqlx::PgPool;

/// `server.public_base_url` of the test configuration.
pub const ORIGIN: &str = "https://auth.test.example";
pub const HOST: &str = "auth.test.example";
/// A password every policy accepts.
pub const PASSWORD: &str = "tramway galaxy orchid lantern 47";

pub struct App {
    pub ports: TestPorts,
    pub services: Services,
    pub router: Router,
    pub pool: PgPool,
}

impl App {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut AppConfig)) -> Self {
        Self::with_ports(pool, tweak, |_| {}).await
    }

    /// [`App::with`], also replacing ports (real HTTP client and fake
    /// identity providers for the social-login tests).
    pub async fn with_ports(
        pool: PgPool,
        tweak: impl FnOnce(&mut AppConfig),
        tweak_ports: impl FnOnce(&mut Ports),
    ) -> Self {
        authn_core::tls::install_crypto_provider();
        authn_testkit::init_tracing();
        let mut config = authn_testkit::config::test_config();
        tweak(&mut config);
        let ports = TestPorts::new();
        let clock: Arc<dyn Clock> = ports.clock.clone();
        let mut service_ports = Ports {
            clock,
            http: ports.http.clone(),
            breach_checker: ports.breached_passwords.clone(),
            dns: ports.dns.clone(),
            notifier: Some(ports.notifier.clone()),
            oidc_registry: None,
        };
        tweak_ports(&mut service_ports);
        let services = Services::build(Arc::new(config), pool.clone(), service_ports)
            .await
            .unwrap();
        authn_server::jobs::rotate_signing_keys(&services)
            .await
            .unwrap();
        services.accounts.sync_terms_versions().await.unwrap();
        let router = build_router(AppState::new(services.clone())).unwrap();
        Self {
            ports,
            services,
            router,
            pool,
        }
    }

    pub fn advance(&self, by: Duration) {
        self.ports.clock.advance(by);
    }

    pub async fn send(&self, request: TestRequest) -> TestResponse {
        request.header("host", HOST).send(&self.router).await
    }

    /// Waits for every background job (reset mails, passwordless mails).
    pub async fn drain(&self) {
        self.services.passwords.drain_background_jobs().await;
        self.services.accounts.drain_background_jobs().await;
        self.services.sessions.drain_background_jobs().await;
    }

    /// The last notification of `template`, as JSON of its kind.
    pub fn last_notification(&self, template: &str) -> NotificationKind {
        self.ports
            .notifier
            .with_template(template)
            .pop()
            .unwrap_or_else(|| {
                panic!(
                    "no `{template}` notification; have: {:?}",
                    self.ports
                        .notifier
                        .recorded()
                        .iter()
                        .map(|n| n.kind.template_name())
                        .collect::<Vec<_>>()
                )
            })
            .kind
    }

    /// An active, verified user with [`PASSWORD`], created directly.
    pub async fn user(&self, email: &str) -> authn_core::id::UserId {
        use authn_core::domain::{AccountStatus, EmailAddress};
        use authn_store::{NewPasswordHash, NewUser, UserRepository};
        let id = authn_core::id::UserId::generate();
        let now = authn_core::ports::Clock::now(self.ports.clock.as_ref());
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status: AccountStatus::Active,
                created_at: now,
            },
        )
        .await
        .unwrap();
        UserRepository::mark_email_verified(&mut conn, id, now)
            .await
            .unwrap();
        let record = self
            .services
            .crypto
            .passwords
            .hash(&authn_core::secret::SecretString::from(PASSWORD.to_owned()))
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
            now,
        )
        .await
        .unwrap();
        id
    }

    pub fn browser(&self) -> Browser {
        Browser::default()
    }

    pub fn native(&self) -> Native {
        Native::default()
    }
}

/// A browser: cookies, CSRF token, `Origin`.
#[derive(Default, Clone)]
pub struct Browser {
    pub cookies: BTreeMap<String, String>,
    pub csrf: Option<String>,
}

impl Browser {
    fn with_cookies(&self, mut request: TestRequest) -> TestRequest {
        for (name, value) in &self.cookies {
            request = request.cookie(name, value);
        }
        request
    }

    pub fn get(&self, path: &str) -> TestRequest {
        self.with_cookies(TestRequest::get(path))
    }

    pub fn post(&self, path: &str, body: &Value) -> TestRequest {
        self.write(TestRequest::post(path).json(body))
    }

    pub fn delete(&self, path: &str) -> TestRequest {
        self.write(TestRequest::delete(path))
    }

    pub fn patch(&self, path: &str, body: &Value) -> TestRequest {
        self.write(TestRequest::patch(path).json(body))
    }

    fn write(&self, request: TestRequest) -> TestRequest {
        let mut request = self.with_cookies(request.header("origin", ORIGIN));
        if let Some(csrf) = &self.csrf {
            request = request.header("x-csrf-token", csrf);
        }
        request
    }

    pub fn absorb(&mut self, response: &TestResponse) {
        for line in response.set_cookies() {
            let first = line.split(';').next().unwrap();
            let (name, value) = first.split_once('=').unwrap();
            if line.contains("Max-Age=0") || value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        if let Ok(body) = serde_json::from_slice::<Value>(&response.body)
            && let Some(csrf) = body.get("csrf_token").and_then(Value::as_str)
        {
            self.csrf = Some(csrf.to_owned());
        }
    }

    pub async fn send(&mut self, app: &App, request: TestRequest) -> TestResponse {
        let response = app.send(request).await;
        self.absorb(&response);
        response
    }

    /// `GET /v1/csrf` (login forms / signed-in token).
    pub async fn csrf(&mut self, app: &App) {
        let response = self.send(app, self.get("/v1/csrf")).await;
        response.assert_status(axum::http::StatusCode::OK);
        self.csrf = Some(
            response.json::<Value>()["csrf_token"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }

    /// Password login; returns the response body.
    pub async fn login(&mut self, app: &App, email: &str, password: &str) -> Value {
        self.csrf(app).await;
        let response = self
            .send(
                app,
                self.post(
                    "/v1/login/password",
                    &serde_json::json!({"email": email, "password": password}),
                ),
            )
            .await;
        response.json()
    }
}

/// A native app: bearer tokens.
#[derive(Default, Clone)]
pub struct Native {
    pub access: Option<String>,
    pub refresh: Option<String>,
    pub challenge: Option<String>,
}

impl Native {
    pub fn post(&self, path: &str, body: &Value) -> TestRequest {
        let mut request = TestRequest::post(path)
            .json(body)
            .header("x-authn-client", "native");
        if let Some(token) = &self.challenge {
            request = request.header("x-authn-challenge", token);
        }
        request
    }

    pub fn get(&self, path: &str) -> TestRequest {
        let request = TestRequest::get(path);
        match &self.access {
            Some(token) => request.bearer(token),
            None => request,
        }
    }

    pub fn absorb(&mut self, body: &Value) {
        if let Some(t) = body.get("access_token").and_then(Value::as_str) {
            self.access = Some(t.to_owned());
        }
        if let Some(t) = body.get("refresh_token").and_then(Value::as_str) {
            self.refresh = Some(t.to_owned());
        }
        if let Some(t) = body.get("challenge_token").and_then(Value::as_str) {
            self.challenge = Some(t.to_owned());
        }
    }
}

pub fn totp_code(app: &App, secret_base32: &str) -> String {
    let secret = authn_crypto::totp::TotpSecret::from_base32(secret_base32).unwrap();
    let totp = authn_crypto::totp::Totp::new(authn_crypto::totp::TotpParams::default()).unwrap();
    let step = totp.time_step(app.ports.clock.now()).unwrap();
    totp.code_for_step(&secret, step).unwrap().to_string()
}
