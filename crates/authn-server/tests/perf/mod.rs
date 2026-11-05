//! Shared fixtures of the performance programme (K-70): the query budget
//! test, the load test and the `hot_paths` bench target build the same
//! production-shaped application with these helpers.
//!
//! Production shape = the real router and every middleware, the
//! **PostgreSQL** rate limiter (the default backend; the test configuration
//! uses the in-memory one) and, where it matters, the production Argon2id
//! parameters (CRY-01).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};

use authn_core::config::AppConfig;
use authn_core::config::crypto::Argon2Config;
use authn_core::config::protect::RateLimitBackend;
use authn_core::domain::{AuthMethodRef, Principal, PrincipalCredential, Subject};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, SessionId, UserId};
use authn_testkit::http::TestRequest;
use serde_json::{Value, json};

use crate::common::{App, PASSWORD};

/// Production-shaped configuration tweaks: PostgreSQL rate limiter and,
/// with `production_argon2`, the default Argon2id parameters.
pub fn production_shape(config: &mut AppConfig, production_argon2: bool) {
    config.protect.rate_limit.backend = RateLimitBackend::Postgres;
    if production_argon2 {
        config.crypto.argon2 = Argon2Config::default();
    }
}

/// A distinct client IP per index (TEST-NET-3 and beyond, never the
/// default peer): load generators must not share one per-IP bucket.
pub fn client_ip(i: usize) -> IpAddr {
    let i = u32::try_from(i).unwrap();
    IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + 0x100 + i))
}

/// The `n`-th address of fixture user `user`'s home network: each user
/// has its own `/24` (risk-based login, RSK-02/RSK-03, attributes logins
/// to `/24` networks, so a user's later logins come from a known network
/// as in real life), the host part rotates so per-IP limits see many
/// clients behind it.
pub fn user_ip(user: usize, n: usize) -> IpAddr {
    let user = u32::try_from(user).unwrap();
    let host = u32::try_from(n % 254).unwrap() + 1;
    IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + (user << 8) + host))
}

/// E-mail address of the `i`-th fixture user.
pub fn email(i: usize) -> String {
    format!("perf{i}@example.com")
}

/// Native password login body.
pub fn login_body(i: usize) -> Value {
    json!({"email": email(i), "password": PASSWORD})
}

/// `POST /v1/login/password` as a native client from `ip`, on the user's
/// own device (`x-device-id`): after the first login both device and
/// network are known, so the risk score stays low (RSK-02, RSK-03) — the
/// common case of a returning user.
pub fn native_login_request(i: usize, ip: IpAddr) -> TestRequest {
    TestRequest::post("/v1/login/password")
        .json(&login_body(i))
        .header("x-authn-client", "native")
        .header("x-device-id", &format!("perf-device-{i:08}"))
        .peer_ip(ip)
}

/// `POST /v1/token/refresh` as a native client from `ip`.
pub fn refresh_request(refresh: &str, ip: IpAddr) -> TestRequest {
    TestRequest::post("/v1/token/refresh")
        .json(&json!({"refresh_token": refresh}))
        .header("x-authn-client", "native")
        .peer_ip(ip)
}

/// A bearer `GET` from `ip`.
pub fn bearer_get(path: &str, access: &str, ip: IpAddr) -> TestRequest {
    TestRequest::get(path).bearer(access).peer_ip(ip)
}

/// Native tokens.
#[derive(Debug, Clone)]
pub struct Tokens {
    pub access: String,
    pub refresh: String,
}

impl Tokens {
    pub fn from_body(body: &Value) -> Self {
        Self {
            access: body["access_token"]
                .as_str()
                .expect("access_token")
                .to_owned(),
            refresh: body["refresh_token"]
                .as_str()
                .expect("refresh_token")
                .to_owned(),
        }
    }
}

/// Logs the `i`-th fixture user in natively; panics unless authenticated.
pub async fn native_login(app: &App, i: usize) -> Tokens {
    let r = app.send(native_login_request(i, user_ip(i, 0))).await;
    assert!(r.status.is_success(), "login: {}", r.text());
    let body: Value = r.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    Tokens::from_body(&body)
}

/// Creates `count` fixture users (`perf0@…` …).
pub async fn users(app: &App, count: usize) -> Vec<UserId> {
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        ids.push(app.user(&email(i)).await);
    }
    ids
}

fn context(ip: IpAddr) -> RequestContext {
    let mut ctx = RequestContext::system(authn_core::domain::Locale::default());
    ctx.client_ip = ip;
    ctx.peer_ip = ip;
    ctx
}

/// A step-up-fresh principal for calling services directly (fixtures).
fn fresh(app: &App, user: UserId) -> Principal {
    Principal {
        subject: Subject::User { user_id: user },
        credential: PrincipalCredential::SessionCookie {
            session_id: SessionId::generate(),
        },
        active_org: None,
        amr: vec![AuthMethodRef::Pwd],
        acr: None,
        auth_time: Some(authn_core::ports::Clock::now(app.ports.clock.as_ref())),
        scopes: vec![],
        impersonation: None,
        is_platform_admin: false,
    }
}

/// An organization owned by `owner` and an API key of it (introspection
/// client credential).
pub async fn org_with_api_key(app: &App, owner: UserId) -> (OrgId, String) {
    let ctx = context(client_ip(0));
    let org = app
        .services
        .orgs
        .create_organization(
            &ctx,
            &fresh(app, owner),
            authn_org::service::orgs::CreateOrganization {
                name: "Perf Org".into(),
                slug: "perf-org".into(),
            },
        )
        .await
        .unwrap()
        .id;
    let key = app
        .services
        .orgs
        .create_api_key(
            &ctx,
            &fresh(app, owner),
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
    (org, key.key.expose().to_owned())
}

/// Switches the native session of `tokens` to `org`; returns the
/// organization-scoped tokens.
pub async fn switch_org(app: &App, tokens: &Tokens, org: OrgId, ip: IpAddr) -> Tokens {
    let r = app
        .send(
            TestRequest::post("/v1/session/org")
                .bearer(&tokens.access)
                .header("x-authn-client", "native")
                .json(&json!({"org_id": org}))
                .peer_ip(ip),
        )
        .await;
    assert!(r.status.is_success(), "switch org: {}", r.text());
    Tokens::from_body(&r.json())
}

/// `POST /v1/token/introspect` with an API key.
pub fn introspect_request(key: &str, token: &str, ip: IpAddr) -> TestRequest {
    TestRequest::post("/v1/token/introspect")
        .header("authorization", &format!("Bearer {key}"))
        .json(&json!({"token": token}))
        .peer_ip(ip)
}

/// A throw-away database with every migration applied (bench targets and
/// the load test run outside `#[sqlx::test]`). Drop it with
/// [`ScratchDatabase::drop_database`].
pub struct ScratchDatabase {
    admin: sqlx::PgPool,
    name: String,
    /// URL of the scratch database.
    pub url: String,
}

/// `DATABASE_URL` (default of `.cargo/config.toml` when unset).
pub fn base_database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/authn".to_owned())
}

impl ScratchDatabase {
    /// Creates `authn_perf_<random>` next to `DATABASE_URL` and migrates it.
    pub async fn create() -> Self {
        let base = base_database_url();
        let admin = sqlx::PgPool::connect(&base).await.expect("DATABASE_URL");
        let name = format!("authn_perf_{}", uuid::Uuid::new_v4().simple());
        // The name is generated above from hex digits only.
        let create = format!("CREATE DATABASE {name}");
        sqlx::raw_sql(sqlx::AssertSqlSafe(create))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        let url = url.to_string();
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        authn_testkit::MIGRATOR.run(&pool).await.unwrap();
        pool.close().await;
        Self { admin, name, url }
    }

    /// A production-shaped pool (`authn_store::connect`) of `size`
    /// connections.
    pub async fn pool(&self, size: u32) -> sqlx::PgPool {
        let mut config = authn_core::config::database::DatabaseConfig::with_url(
            authn_core::secret::SecretString::from(self.url.clone()),
        );
        config.max_connections = size;
        config.min_connections = size.min(4);
        authn_store::connect(&config).await.unwrap()
    }

    /// Drops the database (closing other sessions first).
    pub async fn drop_database(self) {
        let drop = format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name);
        sqlx::raw_sql(sqlx::AssertSqlSafe(drop))
            .execute(&self.admin)
            .await
            .unwrap();
    }
}

/// The application over `pool` in production shape (the per-API-key
/// introspection limit lifted), driven by the **real** clock (rate limits drain, tokens expire as in production). The fixture
/// clock is moved to "now" as well, so fixture users and principals are
/// created at the real time.
pub async fn production_app(pool: sqlx::PgPool, production_argon2: bool) -> App {
    production_app_with(pool, production_argon2, |_| {}).await
}

/// [`production_app`] with a further configuration tweak (load-test
/// experiments: rate-limit backend, …).
pub async fn production_app_with(
    pool: sqlx::PgPool,
    production_argon2: bool,
    tweak: impl FnOnce(&mut AppConfig),
) -> App {
    let app = App::with_ports(
        pool,
        |c| {
            production_shape(c, production_argon2);
            tweak(c);
            // One API key drives every introspection here; production's
            // per-client budget (600/min) would only measure the limiter.
            c.session.introspection_per_client = authn_core::ports::RateLimitPolicy::new(
                1_000_000_000,
                std::time::Duration::from_secs(60),
            );
        },
        |p| p.clock = std::sync::Arc::new(authn_core::ports::SystemClock),
    )
    .await;
    app.ports.clock.set(time::OffsetDateTime::now_utc());
    app
}
