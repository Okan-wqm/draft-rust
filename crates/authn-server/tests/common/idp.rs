//! Fake identity providers for the social-login tests (TST-08: no
//! network): one wiremock server, one path prefix per provider, the real
//! SSRF-safe HTTP client and the real provider registry with its endpoints
//! pointed at the fake.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;

use authn_core::config::AppConfig;
use authn_core::config::oidc_client::{
    AppleProvider, GenericOidcProvider, MicrosoftProvider, ProviderClient,
};
use authn_core::ports::OutboundTarget;
use authn_core::secret::SecretString;
use authn_oidc_client::{Endpoints, IssuerRule, ProviderRegistry, TenantPolicy, TokenAuthMethod};
use authn_server::services::{Ports, RegistryOverride};
use authn_testkit::http::TestResponse;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey as _};
use serde_json::{Value, json};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test-only keys of authn-oidc-client (`tests/fixtures/README.md` there).
pub const KEY_A: &str = include_str!("../../../authn-oidc-client/tests/fixtures/test_rsa_a.pem");
pub const EC_KEY: &str = include_str!("../../../authn-oidc-client/tests/fixtures/test_ec_p256.pem");

pub const GOOGLE_WEB: &str = "google-web-client";
pub const GOOGLE_NATIVE: &str = "google-ios-client";
pub const MS_WEB: &str = "ms-web-client";
pub const APPLE_WEB: &str = "com.example.web";
pub const APPLE_NATIVE: &str = "com.example.app";
pub const GITHUB_WEB: &str = "github-client";
pub const ACME_WEB: &str = "acme-client";
pub const MS_TENANT: &str = "11111111-1111-1111-1111-111111111111";
pub const RETURN_TO: &str = "https://app.example.com/after";

pub struct FakeIdp {
    pub server: MockServer,
}

impl FakeIdp {
    pub async fn start() -> Self {
        let idp = Self {
            server: MockServer::start().await,
        };
        for prefix in ["/google", "/apple", "/ms", "/acme"] {
            let jwk = public_jwk(KEY_A, "key-a");
            Mock::given(method("GET"))
                .and(path(format!("{prefix}/jwks")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
                .mount(&idp.server)
                .await;
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
        idp
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn issuer(&self, prefix: &str) -> String {
        format!("{}{prefix}", self.uri())
    }

    fn url(&self, p: &str) -> Url {
        Url::parse(&format!("{}{p}", self.uri())).unwrap()
    }

    fn endpoints(&self, prefix: &str) -> Endpoints {
        Endpoints {
            authorization: self.url(&format!("{prefix}/authorize")),
            token: self.url(&format!("{prefix}/token")),
            jwks: Some(self.url(&format!("{prefix}/jwks"))),
            api_base: Some(self.url(&format!("{prefix}/api/"))),
            revocation: Some(self.url(&format!("{prefix}/revoke"))),
            token_auth: TokenAuthMethod::ClientSecretPost,
            target: OutboundTarget::Trusted,
        }
    }

    /// Every provider in the configuration (Google, Microsoft with a tenant
    /// allow-list, Apple, GitHub, a generic OIDC provider).
    pub fn configure(&self, config: &mut AppConfig) {
        let client = |id: &str, native: &[&str]| ProviderClient {
            client_id: id.to_owned(),
            client_secret: SecretString::from(format!("{id}-secret")),
            native_client_ids: native.iter().map(|s| (*s).to_owned()).collect(),
        };
        config.oidc_client.google = Some(client(GOOGLE_WEB, &[GOOGLE_NATIVE]));
        config.oidc_client.microsoft = Some(MicrosoftProvider {
            client: client(MS_WEB, &[]),
            tenant: "organizations".to_owned(),
            allowed_tenants: vec![MS_TENANT.to_owned()],
            trust_personal_account_email: false,
        });
        config.oidc_client.apple = Some(AppleProvider {
            client_id: APPLE_WEB.to_owned(),
            team_id: "TEAMID1234".to_owned(),
            key_id: "APPLEKEY01".to_owned(),
            private_key_pem: Some(SecretString::from(EC_KEY.to_owned())),
            private_key_file: None,
            private_key_ciphertext: None,
            native_client_ids: vec![APPLE_NATIVE.to_owned()],
            revoke_tokens_on_deletion: true,
        });
        config.oidc_client.github = Some(client(GITHUB_WEB, &[]));
        config.oidc_client.generic = vec![GenericOidcProvider {
            slug: "acme".to_owned(),
            display_name: "Acme SSO".to_owned(),
            issuer_url: self.issuer("/acme"),
            client: client(ACME_WEB, &[]),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            trust_email_verified: true,
        }];
        config.protect.redirect_allow_list = vec![RETURN_TO.to_owned()];
    }

    /// The registry rewrite pointing the built-in providers at the fake.
    pub fn registry_override(&self) -> RegistryOverride {
        let uri = self.uri();
        let endpoints: HashMap<&'static str, Endpoints> = [
            ("google", self.endpoints("/google")),
            ("apple", self.endpoints("/apple")),
            ("github", self.endpoints("/github")),
            ("microsoft", self.endpoints("/ms")),
        ]
        .into_iter()
        .collect();
        Arc::new(move |registry: &mut ProviderRegistry| {
            for slug in ["google", "apple", "github"] {
                assert!(registry.override_endpoints(
                    slug,
                    endpoints[slug].clone(),
                    Some(IssuerRule::Exact(vec![format!("{uri}/{slug}")])),
                ));
            }
            assert!(registry.override_endpoints(
                "microsoft",
                endpoints["microsoft"].clone(),
                Some(IssuerRule::MicrosoftTenant {
                    prefix: format!("{uri}/ms/"),
                    suffix: "/v2.0".to_owned(),
                    policy: TenantPolicy {
                        configured: "organizations".to_owned(),
                        allowed: vec![MS_TENANT.to_owned()],
                    },
                }),
            ));
        })
    }

    /// The ports: the real SSRF-safe client and the registry rewrite.
    pub fn ports(&self, config: &AppConfig) -> impl FnOnce(&mut Ports) {
        let http =
            authn_protect::outbound::SsrfSafeHttpClient::new(&config.protect.outbound).unwrap();
        let rewrite = self.registry_override();
        move |ports: &mut Ports| {
            ports.http = Arc::new(http);
            ports.oidc_registry = Some(rewrite);
        }
    }

    /// One token-endpoint answer of `prefix` carrying an ID token over
    /// `claims` (and a refresh token).
    pub async fn token_once(&self, prefix: &str, claims: &Value) {
        let id_token = sign_rs256(KEY_A, "key-a", claims);
        Mock::given(method("POST"))
            .and(path(format!("{prefix}/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "provider-access-token",
                "refresh_token": "provider-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "id_token": id_token,
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// GitHub: token (no ID token), `/user` and `/user/emails`.
    pub async fn github_once(&self, id: u64, email: &str) {
        Mock::given(method("POST"))
            .and(path("/github/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "gh-access", "token_type": "bearer", "scope": "read:user,user:email"
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/github/api/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": id, "login": "octo", "name": "Octo Cat"
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/github/api/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "email": email, "primary": true, "verified": true }
            ])))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }

    /// Apple's revocation endpoint (K-35).
    pub async fn apple_revoke_ok(&self) {
        Mock::given(method("POST"))
            .and(path("/apple/revoke"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&self.server)
            .await;
    }

    pub async fn requests_to(&self, p: &str) -> Vec<wiremock::Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path() == p)
            .collect()
    }
}

/// Standard claims for an issuer.
pub fn claims(iss: &str, aud: &str, sub: &str, nonce: &str, email: &str, now: i64) -> Value {
    json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": now + 600,
        "iat": now - 5,
        "nonce": nonce,
        "email": email,
        "email_verified": true,
        "name": "Social User",
    })
}

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

/// A started browser flow (`303` to the provider + binding cookie).
#[derive(Debug, Clone)]
pub struct Started {
    pub location: Url,
    pub params: HashMap<String, String>,
    pub binding: String,
}

impl Started {
    pub fn from_response(res: &TestResponse) -> Self {
        assert_eq!(res.status, 303, "{}", res.text());
        let location = Url::parse(res.headers["location"].to_str().unwrap()).unwrap();
        let params = location.query_pairs().into_owned().collect();
        let binding = res
            .set_cookies()
            .into_iter()
            .find_map(|c| {
                c.strip_prefix("__Host-authn_oauth=")
                    .map(|v| v.split(';').next().unwrap().to_owned())
            })
            .expect("binding cookie");
        Self {
            location,
            params,
            binding,
        }
    }

    pub fn param(&self, name: &str) -> String {
        self.params
            .get(name)
            .unwrap_or_else(|| panic!("{name} missing in {}", self.location))
            .clone()
    }
}
