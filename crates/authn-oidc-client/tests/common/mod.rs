//! Shared harness of the authn-oidc-client integration tests: a real
//! PostgreSQL pool, the testkit fakes, the real SSRF-safe HTTP client and a
//! wiremock server playing every provider.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use authn_account::{AccountService, AccountServiceDeps, AccountServiceSettings, NoOrganizations};
use authn_core::config::AppConfig;
use authn_core::config::oidc_client::{
    AppleProvider, GenericOidcProvider, MicrosoftProvider, ProviderClient,
};
use authn_core::domain::{AccountStatus, EmailAddress, Principal, PrincipalCredential, Subject};
use authn_core::http::RequestContext;
use authn_core::id::{RequestId, SessionId, UserId};
use authn_core::ports::{Clock, OutboundTarget};
use authn_core::secret::SecretString;
use authn_crypto::CryptoServices;
use authn_oidc_client::{
    Endpoints, IssuerRule, LoginMethodInventory, NoReservations, OidcClientService,
    OidcClientServiceDeps, OidcClientSettings, PasswordOnlyInventory, ProviderRegistry,
    TenantPolicy, TokenAuthMethod, router,
};
use authn_store::{NewUser, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::config::TestConfigBuilder;
use authn_testkit::http::{TestRequest, TestResponse, with_request_context};
use axum::{Extension, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey as _};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const KEY_A: &str = include_str!("../fixtures/test_rsa_a.pem");
pub const KEY_B: &str = include_str!("../fixtures/test_rsa_b.pem");
pub const EC_KEY: &str = include_str!("../fixtures/test_ec_p256.pem");

pub const GOOGLE_WEB: &str = "google-web-client";
pub const GOOGLE_NATIVE: &str = "google-ios-client";
pub const MS_WEB: &str = "ms-web-client";
pub const MS_NATIVE: &str = "ms-native-client";
pub const APPLE_WEB: &str = "com.example.web";
pub const APPLE_NATIVE: &str = "com.example.app";
pub const GITHUB_WEB: &str = "github-client";
pub const ACME_WEB: &str = "acme-client";
pub const ACME_NATIVE: &str = "acme-native";
pub const MS_TENANT: &str = "11111111-1111-1111-1111-111111111111";
pub const MS_CONSUMERS: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// A fake identity provider (one wiremock server, one path prefix per
/// provider).
pub struct FakeIdp {
    pub server: MockServer,
}

impl FakeIdp {
    pub async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{path}", self.uri())).unwrap()
    }

    /// JWKS of `prefix` with the given (pem, kid) keys.
    pub async fn mount_jwks(&self, prefix: &str, keys: &[(&str, &str)]) {
        let keys: Vec<Value> = keys.iter().map(|(pem, kid)| public_jwk(pem, kid)).collect();
        Mock::given(method("GET"))
            .and(path(format!("{prefix}/jwks")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": keys })))
            .mount(&self.server)
            .await;
    }

    /// One token-endpoint answer for `prefix`.
    pub async fn mount_token_once(&self, prefix: &str, body: Value) {
        Mock::given(method("POST"))
            .and(path(format!("{prefix}/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    pub async fn mount_token_error(&self, prefix: &str, status: u16) {
        Mock::given(method("POST"))
            .and(path(format!("{prefix}/token")))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(json!({ "error": "invalid_grant" })),
            )
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Requests received on `path`.
    pub async fn requests_to(&self, p: &str) -> Vec<wiremock::Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path() == p)
            .collect()
    }

    pub fn endpoints(&self, prefix: &str) -> Endpoints {
        Endpoints {
            authorization: self.url(&format!("{prefix}/authorize")),
            token: self.url(&format!("{prefix}/token")),
            jwks: Some(self.url(&format!("{prefix}/jwks"))),
            api_base: Some(self.url(&format!("{prefix}/api/"))),
            token_auth: TokenAuthMethod::ClientSecretPost,
            target: OutboundTarget::Trusted,
        }
    }

    pub fn issuer(&self, prefix: &str) -> String {
        format!("{}{prefix}", self.uri())
    }
}

/// The public JWK of an RSA test key.
pub fn public_jwk(pem: &str, kid: &str) -> Value {
    let key =
        CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(kid.to_owned()))).unwrap();
    let mut jwk = serde_json::to_value(key.as_verification_key()).unwrap();
    jwk["alg"] = json!("RS256");
    jwk
}

fn b64(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}

/// An RS256 JWS over `claims`.
pub fn sign_rs256(pem: &str, kid: &str, claims: &Value) -> String {
    let key =
        CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(kid.to_owned()))).unwrap();
    let header = json!({ "alg": "RS256", "kid": kid, "typ": "JWT" });
    let input = format!("{}.{}", b64(&header), b64(claims));
    let sig = key
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            input.as_bytes(),
        )
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// A token with an arbitrary header, signed with HMAC-SHA256 under `secret`.
pub fn sign_hs256_with(secret: &[u8], kid: &str, claims: &Value) -> String {
    use openidconnect::core::CoreHmacKey;
    let header = json!({ "alg": "HS256", "kid": kid });
    let input = format!("{}.{}", b64(&header), b64(claims));
    let sig = CoreHmacKey::new(secret.to_vec())
        .sign(&CoreJwsSigningAlgorithm::HmacSha256, input.as_bytes())
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// `alg: none`, empty signature.
pub fn unsigned(kid: &str, claims: &Value) -> String {
    format!(
        "{}.{}.",
        b64(&json!({ "alg": "none", "kid": kid })),
        b64(claims)
    )
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub config: AppConfig,
    pub settings: OidcClientSettings,
    pub idp: FakeIdp,
    pub accounts: AccountService,
    pub service: OidcClientService,
    pub crypto: CryptoServices,
    pub deps: OidcClientServiceDeps,
}

pub struct Options {
    pub inventory: Arc<dyn LoginMethodInventory>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            inventory: Arc::new(PasswordOnlyInventory),
        }
    }
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut OidcClientSettings)) -> Self {
        Self::with_options(pool, tweak, Options::default()).await
    }

    pub async fn with_options(
        pool: PgPool,
        tweak: impl FnOnce(&mut OidcClientSettings),
        options: Options,
    ) -> Self {
        authn_testkit::init_tracing();
        authn_core::tls::install_crypto_provider();
        let idp = FakeIdp::start().await;
        let ports = TestPorts::new();
        let mut config = TestConfigBuilder::new().build();
        let client = |id: &str, native: &[&str]| ProviderClient {
            client_id: id.to_owned(),
            client_secret: SecretString::from(format!("{id}-secret")),
            native_client_ids: native.iter().map(|s| (*s).to_owned()).collect(),
        };
        config.oidc_client.google = Some(client(GOOGLE_WEB, &[GOOGLE_NATIVE]));
        config.oidc_client.microsoft = Some(MicrosoftProvider {
            client: client(MS_WEB, &[MS_NATIVE]),
            tenant: "common".to_owned(),
        });
        config.oidc_client.apple = Some(AppleProvider {
            client_id: APPLE_WEB.to_owned(),
            team_id: "TEAMID1234".to_owned(),
            key_id: "APPLEKEY01".to_owned(),
            private_key_pem: SecretString::from(EC_KEY.to_owned()),
            native_client_ids: vec![APPLE_NATIVE.to_owned()],
        });
        config.oidc_client.github = Some(client(GITHUB_WEB, &[]));
        config.oidc_client.generic = vec![GenericOidcProvider {
            slug: "acme".to_owned(),
            display_name: "Acme SSO".to_owned(),
            issuer_url: idp.issuer("/acme"),
            client: client(ACME_WEB, &[ACME_NATIVE]),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        }];
        config.protect.redirect_allow_list = vec!["https://app.example.com/after".to_owned()];

        let mut settings = OidcClientSettings::from_app_config(&config);
        tweak(&mut settings);
        config.oidc_client = settings.config.clone();

        let mut registry = ProviderRegistry::from_settings(&settings).unwrap();
        for prefix in ["google", "apple", "github"] {
            let _ = registry.override_endpoints(
                prefix,
                idp.endpoints(&format!("/{prefix}")),
                Some(IssuerRule::Exact(vec![idp.issuer(&format!("/{prefix}"))])),
            );
        }
        let _ = registry.override_endpoints(
            "microsoft",
            idp.endpoints("/ms"),
            Some(IssuerRule::MicrosoftTenant {
                prefix: format!("{}/ms/", idp.uri()),
                suffix: "/v2.0".to_owned(),
                policy: TenantPolicy {
                    configured: "common".to_owned(),
                    allowed: settings
                        .microsoft_allowed_tenants
                        .iter()
                        .map(|t| t.to_ascii_lowercase())
                        .collect(),
                },
            }),
        );

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
        let http =
            authn_protect::outbound::SsrfSafeHttpClient::new(&config.protect.outbound).unwrap();
        let deps = OidcClientServiceDeps {
            pool: pool.clone(),
            clock: ports.clock.clone(),
            http: Arc::new(http),
            envelopes: crypto.envelopes.clone(),
            rate_limiter: ports.rate_limiter.clone(),
            audit: ports.audit.clone(),
            events: ports.events.clone(),
            sessions: ports.session_issuer.clone(),
            accounts: accounts.clone(),
            login_methods: options.inventory,
            reservations: Arc::new(NoReservations),
        };
        let service = OidcClientService::with_registry(deps.clone(), settings.clone(), registry);
        for prefix in ["/google", "/apple", "/ms", "/acme"] {
            idp.mount_jwks(prefix, &[(KEY_A, "key-a")]).await;
        }
        Mock::given(method("GET"))
            .and(path("/acme/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": idp.issuer("/acme"),
                "authorization_endpoint": format!("{}/acme/authorize", idp.uri()),
                "token_endpoint": format!("{}/acme/token", idp.uri()),
                "jwks_uri": format!("{}/acme/jwks", idp.uri()),
            })))
            .mount(&idp.server)
            .await;
        Self {
            pool,
            ports,
            config,
            settings,
            idp,
            accounts,
            service,
            crypto,
            deps,
        }
    }

    pub fn service_deps(&self) -> OidcClientServiceDeps {
        self.deps.clone()
    }

    pub fn now(&self) -> i64 {
        self.ports.clock.now().unix_timestamp()
    }

    pub fn ctx(&self) -> RequestContext {
        RequestContext {
            request_id: RequestId::generate(),
            client_ip: "203.0.113.10".parse().unwrap(),
            peer_ip: "203.0.113.10".parse().unwrap(),
            user_agent: Some("test".to_owned()),
            device_id: None,
            locale: authn_core::domain::Locale::En,
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

    pub async fn user(&self, email: &str, status: AccountStatus, verified: bool) -> UserId {
        let id = UserId::generate();
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status,
                created_at: self.ports.clock.now(),
            },
        )
        .await
        .unwrap();
        if verified {
            UserRepository::mark_email_verified(&mut conn, id, self.ports.clock.now())
                .await
                .unwrap();
        }
        id
    }

    pub fn principal(&self, user: UserId, auth_age: Duration) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: Vec::new(),
            acr: None,
            auth_time: Some(self.ports.clock.now() - auth_age),
            scopes: Vec::new(),
            impersonation: None,
            is_platform_admin: false,
        }
    }

    pub fn fresh(&self, user: UserId) -> Principal {
        self.principal(user, Duration::from_secs(5))
    }

    /// Standard OIDC claims for `prefix`'s issuer.
    pub fn claims(&self, iss: &str, aud: &str, sub: &str, nonce: &str, email: &str) -> Value {
        json!({
            "iss": iss,
            "sub": sub,
            "aud": aud,
            "exp": self.now() + 600,
            "iat": self.now() - 5,
            "nonce": nonce,
            "email": email,
            "email_verified": true,
            "name": "Test User",
        })
    }

    /// Runs `GET /v1/oauth/{provider}/start`; returns the authorization URL
    /// parameters and the binding cookie.
    pub async fn start(&self, provider: &str, return_to: Option<&str>) -> Started {
        let uri = match return_to {
            Some(rt) => format!(
                "/v1/oauth/{provider}/start?return_to={}",
                url::form_urlencoded::byte_serialize(rt.as_bytes()).collect::<String>()
            ),
            None => format!("/v1/oauth/{provider}/start"),
        };
        let res = TestRequest::get(&uri).send(&self.app()).await;
        assert_eq!(res.status, 303, "{}", res.text());
        Started::from_response(&res)
    }

    /// Mounts the token answer for a started OIDC flow.
    pub async fn token_for(&self, prefix: &str, started: &Started, claims: &Value) {
        let mut claims = claims.clone();
        if claims.get("nonce").is_some_and(|n| n == "AUTO") {
            claims["nonce"] = json!(started.param("nonce"));
        }
        let id_token = sign_rs256(KEY_A, "key-a", &claims);
        self.idp
            .mount_token_once(
                prefix,
                json!({
                    "access_token": "provider-access-token",
                    "refresh_token": "provider-refresh-token",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "id_token": id_token,
                }),
            )
            .await;
    }

    /// Runs the callback with the binding cookie of `started`.
    pub async fn callback(&self, provider: &str, started: &Started) -> TestResponse {
        let state = started.param("state");
        TestRequest::get(&format!(
            "/v1/oauth/{provider}/callback?code=the-code&state={state}"
        ))
        .cookie("__Host-authn_oauth", &started.binding)
        .send(&self.app())
        .await
    }

    /// A native nonce for `provider`.
    pub async fn native_nonce(&self, provider: &str) -> String {
        let res = TestRequest::post("/v1/oauth/nonce")
            .json(&json!({ "provider": provider }))
            .send(&self.app())
            .await;
        assert_eq!(res.status, 200, "{}", res.text());
        res.json::<Value>()["nonce"].as_str().unwrap().to_owned()
    }

    pub async fn native(&self, provider: &str, id_token: &str) -> TestResponse {
        TestRequest::post(&format!("/v1/oauth/{provider}/native"))
            .json(&json!({ "id_token": id_token }))
            .send(&self.app())
            .await
    }

    pub async fn identity_count(&self) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identities")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    pub async fn identity_owner(&self, provider: &str, subject: &str) -> Option<UserId> {
        sqlx::query_scalar::<_, UserId>(
            "SELECT user_id FROM identities WHERE provider = $1 AND subject = $2",
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .unwrap()
    }
}

/// A started browser flow.
#[derive(Debug, Clone)]
pub struct Started {
    pub location: Url,
    pub params: HashMap<String, String>,
    pub binding: String,
    pub set_cookie: String,
}

impl Started {
    pub fn from_response(res: &TestResponse) -> Self {
        let location = Url::parse(res.headers["location"].to_str().unwrap()).unwrap();
        let params = location.query_pairs().into_owned().collect();
        let set_cookie = res.headers["set-cookie"].to_str().unwrap().to_owned();
        let binding = set_cookie
            .strip_prefix("__Host-authn_oauth=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        Self {
            location,
            params,
            binding,
            set_cookie,
        }
    }

    pub fn param(&self, name: &str) -> String {
        self.params
            .get(name)
            .unwrap_or_else(|| panic!("{name} missing in {}", self.location))
            .clone()
    }
}

/// Form-urlencoded body of a received request as a map.
pub fn form_of(request: &wiremock::Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
}
