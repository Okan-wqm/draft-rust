//! A valid, deterministic configuration for tests.
//!
//! All keys below are **publicly known test constants**. They exist so tests
//! are deterministic (TST-08); `Environment::Test` marks the configuration.

use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::common::{Environment, VersionedKey};
use authn_core::config::crypto::{Argon2Config, CryptoConfig, KekConfig};
use authn_core::config::database::DatabaseConfig;
use authn_core::config::notify::EmailTransportKind;
use authn_core::config::protect::RateLimitBackend;
use authn_core::config::server::ServerConfig;
use authn_core::secret::SecretString;
use url::Url;

/// Base64 of bytes 0..32 — test pepper v1.
pub const TEST_PEPPER_V1: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/// Base64 of bytes 32..64 — test KEK `test-kek-1`.
pub const TEST_KEK_1: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
/// Base64 of bytes 64..96 — test HMAC root key.
pub const TEST_HMAC_ROOT_KEY: &str = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=";
/// Public base URL used by the test configuration.
pub const TEST_PUBLIC_BASE_URL: &str = "https://auth.test.example";

/// Builds a valid [`AppConfig`] for tests.
///
/// Differences from production defaults: `environment = test`, log e-mail
/// transport, in-memory rate limiting, private outbound destinations allowed
/// (wiremock), and *cheap* Argon2 parameters unless
/// [`TestConfigBuilder::production_argon2`] is called.
#[derive(Debug, Clone)]
pub struct TestConfigBuilder {
    database_url: String,
    production_argon2: bool,
}

impl Default for TestConfigBuilder {
    fn default() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/authn".to_owned()),
            production_argon2: false,
        }
    }
}

impl TestConfigBuilder {
    /// A builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses the given database URL (e.g. from a `#[sqlx::test]` pool).
    #[must_use]
    pub fn database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = url.into();
        self
    }

    /// Keeps the production Argon2 parameters (CRY-01) instead of cheap ones.
    #[must_use]
    pub fn production_argon2(mut self) -> Self {
        self.production_argon2 = true;
        self
    }

    /// Builds and validates the configuration (panics if invalid).
    #[must_use]
    pub fn build(self) -> AppConfig {
        let mut server =
            ServerConfig::with_public_base_url(Url::parse(TEST_PUBLIC_BASE_URL).unwrap());
        server.environment = Environment::Test;
        server.metrics_bind_addr = None;

        let argon2 = if self.production_argon2 {
            Argon2Config::default()
        } else {
            Argon2Config {
                memory_kib: 7_168,
                iterations: 1,
                parallelism: 1,
            }
        };
        let crypto = CryptoConfig {
            argon2,
            peppers: vec![VersionedKey {
                version: 1,
                key: secret(TEST_PEPPER_V1),
            }],
            current_pepper_version: 1,
            keks: vec![KekConfig {
                id: "test-kek-1".to_owned(),
                key: secret(TEST_KEK_1),
            }],
            current_kek_id: "test-kek-1".to_owned(),
            hmac_root_key: secret(TEST_HMAC_ROOT_KEY),
            jwt_leeway: Duration::from_secs(30),
            signing_keys: Default::default(),
            max_concurrent_hashes: 4,
        };

        let mut config = AppConfig {
            server,
            database: DatabaseConfig::with_url(secret(&self.database_url)),
            crypto,
            password: Default::default(),
            account: Default::default(),
            session: Default::default(),
            mfa: Default::default(),
            webauthn: Default::default(),
            oidc_client: Default::default(),
            org: Default::default(),
            protect: Default::default(),
            audit: Default::default(),
            notify: Default::default(),
            admin: Default::default(),
        };
        config.notify.email.transport = EmailTransportKind::Log;
        config.notify.email.from_address = "no-reply@test.example".to_owned();
        config.protect.rate_limit.backend = RateLimitBackend::Memory;
        config.protect.outbound.allow_private_networks = true;
        config.password.breach_check.enabled = false;
        config.webauthn.rp_id = "auth.test.example".to_owned();
        config.webauthn.allowed_origins = vec![TEST_PUBLIC_BASE_URL.to_owned()];

        if let Err(err) = config.validate() {
            panic!("test configuration is invalid: {err}");
        }
        config
    }
}

/// Shorthand for `TestConfigBuilder::new().build()`.
#[must_use]
pub fn test_config() -> AppConfig {
    TestConfigBuilder::new().build()
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_07_test_config_is_valid_and_marked_as_test() {
        let config = test_config();
        assert_eq!(config.server.environment, Environment::Test);
        assert_eq!(config.crypto.peppers.len(), 1);
        assert_eq!(config.protect.rate_limit.backend, RateLimitBackend::Memory);
        let prod = TestConfigBuilder::new().production_argon2().build();
        assert_eq!(prod.crypto.argon2, Argon2Config::default());
    }
}
