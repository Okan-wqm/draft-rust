//! Typed configuration (ARC-07).
//!
//! * Sources: an optional TOML file, then environment variables with the
//!   `AUTHN__` prefix and `__` as the nesting separator
//!   (`AUTHN__SESSION__ACCESS_TOKEN_TTL=5m`). Later sources win.
//! * Every duration, limit and policy is configurable; defaults are the
//!   values of `docs/spec/requirements.md` and are documented on each field.
//! * [`AppConfig::validate`] collects *all* problems; the server refuses to
//!   start on any of them (fail-fast). Problems never include secret values.
//! * Secrets are [`SecretString`](crate::secret::SecretString) and never
//!   appear in `Debug` output.
//! * Unknown keys are rejected so typos do not silently fall back to
//!   defaults.
//!
//! Each module owns exactly one file here (`config/<module>.rs`); the
//! aggregation in this file, `common.rs`, `duration.rs`, `server.rs` and
//! `database.rs` are owned by the architect / authn-server / authn-store
//! respectively (see `docs/architecture/contracts.md`).

pub mod account;
pub mod admin;
pub mod audit;
pub mod common;
pub mod crypto;
pub mod database;
pub mod duration;
pub mod mfa;
pub mod notify;
pub mod oidc_client;
pub mod org;
pub mod password;
pub mod protect;
pub mod server;
pub mod session;
pub mod webauthn;

use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;

pub use common::{ConfigError, ConfigProblems, Environment};

/// Environment variable prefix.
pub const ENV_PREFIX: &str = "AUTHN__";

/// Key material that is published in this repository (`config/example.toml`,
/// `authn-testkit`). Refused in production and staging.
pub const KNOWN_PUBLIC_KEYS: &[&str] = &[
    // config/example.toml
    "frPESZ3qTpEEALVDfUItL7NHnr7OR1e8HrBSx+cu6Ag=",
    "EmFt2e6K4mRNa00b7YSb9pmCX5Ak+/U7pL0JNQfO7wk=",
    "JE2nrKQpPUu9s2UxCzfpV0U6/ovFYb3UL1T692VsZpo=",
    // authn-testkit
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
    "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=",
];

/// The complete application configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// HTTP server, environment, logging, proxies (authn-server). Required:
    /// `server.public_base_url`.
    pub server: server::ServerConfig,
    /// PostgreSQL connection pool (authn-store). Required: `database.url`.
    pub database: database::DatabaseConfig,
    /// Keys and crypto parameters (authn-crypto). Required: peppers, KEKs,
    /// HMAC root key.
    pub crypto: crypto::CryptoConfig,
    /// Password policy and reset (authn-password).
    #[serde(default)]
    pub password: password::PasswordConfig,
    /// Registration and account lifecycle (authn-account).
    #[serde(default)]
    pub account: account::AccountConfig,
    /// Sessions and tokens (authn-session).
    #[serde(default)]
    pub session: session::SessionConfig,
    /// MFA (authn-mfa).
    #[serde(default)]
    pub mfa: mfa::MfaConfig,
    /// Passkeys (authn-webauthn).
    #[serde(default)]
    pub webauthn: webauthn::WebauthnConfig,
    /// Social login (authn-oidc-client).
    #[serde(default)]
    pub oidc_client: oidc_client::OidcClientConfig,
    /// Organizations, RBAC, API keys (authn-org).
    #[serde(default)]
    pub org: org::OrgConfig,
    /// Abuse protection, web security, risk (authn-protect).
    #[serde(default)]
    pub protect: protect::ProtectConfig,
    /// Audit log, outbox, webhooks (authn-audit).
    #[serde(default)]
    pub audit: audit::AuditConfig,
    /// Notifications (authn-notify).
    #[serde(default)]
    pub notify: notify::NotifyConfig,
    /// Admin API (authn-admin).
    #[serde(default)]
    pub admin: admin::AdminConfig,
}

impl AppConfig {
    /// Loads configuration from an optional TOML file plus `AUTHN__*`
    /// environment variables, then validates it.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut figment = Figment::new();
        if let Some(path) = path {
            figment = figment.merge(Toml::file_exact(path));
        }
        figment = figment.merge(Env::prefixed(ENV_PREFIX).split("__"));
        Self::from_figment(&figment)
    }

    /// Extracts and validates a configuration from any figment (tests,
    /// embedding).
    pub fn from_figment(figment: &Figment) -> Result<Self, ConfigError> {
        let config: Self = figment
            .extract()
            .map_err(|e| ConfigError::from_figment(&e))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates every section and the cross-section rules.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut p = ConfigProblems::default();
        self.server.validate(&mut p);
        self.database.validate(&mut p);
        self.crypto.validate(&mut p);
        self.password.validate(&mut p);
        self.account.validate(&mut p);
        self.session.validate(&mut p);
        self.mfa.validate(&mut p);
        self.webauthn.validate(&mut p);
        self.oidc_client.validate(&mut p);
        self.org.validate(&mut p);
        self.protect.validate(&mut p);
        self.audit.validate(&mut p);
        self.notify.validate(&mut p);
        self.admin.validate(&mut p);
        self.validate_cross_section(&mut p);
        p.into_result()
    }

    fn validate_cross_section(&self, p: &mut ConfigProblems) {
        // K-111: staging runs every production security rule. A staging
        // deployment is usually reachable from outside and often holds a
        // copy of real data; it is also where the production configuration
        // is rehearsed. Only two rules legitimately differ, both relaxations
        // that a single-person, never-mailing staging copy needs:
        // `admin.four_eyes = false` and `notify.email.transport =
        // "disabled"` (docs/operations/configuration.md).
        let production = self.server.environment == Environment::Production;
        let hardened = matches!(
            self.server.environment,
            Environment::Production | Environment::Staging
        );
        if hardened {
            self.reject_public_keys(p);
            p.require(
                self.server.public_base_url.scheme() == "https",
                "server.public_base_url",
                "must use https in production and staging",
            );
            p.require(
                self.webauthn
                    .allowed_origins
                    .iter()
                    .all(|o| o.starts_with("https://") || o.starts_with("android:apk-key-hash:")),
                "webauthn.allowed_origins",
                "web origins must use https in production and staging",
            );
            p.require(
                !self.protect.outbound.allow_private_networks,
                "protect.outbound.allow_private_networks",
                "must be false in production and staging (SSRF protection, PRT-12)",
            );
            p.require(
                self.protect.rate_limit.backend != protect::RateLimitBackend::Memory,
                "protect.rate_limit.backend",
                "the in-memory backend is per instance; use postgres or redis in production and staging",
            );
            // K-58: without the per-request session check a revoked or
            // suspended session keeps working until its access token
            // expires (up to access_token_ttl). The check costs one
            // primary-key lookup per bearer request.
            p.require(
                self.session.access_token_session_check,
                "session.access_token_session_check",
                "must stay true in production and staging (K-58: revocation takes effect on the next request)",
            );
            // K-58 audit: a Turnstile / hCaptcha token solved on another
            // site must not pass; the provider's `hostname` is checked
            // against this list.
            p.require(
                !matches!(
                    self.protect.captcha.provider,
                    crate::ports::CaptchaProvider::Turnstile | crate::ports::CaptchaProvider::HCaptcha
                ) || !self.protect.captcha.hostnames.is_empty(),
                "protect.captcha.hostnames",
                "required in production and staging with turnstile / hcaptcha (PRT-05: tokens solved on other sites)",
            );
        }
        // K-66: a lone admin is already covered by the single-admin
        // exception, so production has no reason to switch it off. Staging
        // exception (K-111): a single tester may run admin flows alone.
        p.require(
            !production || self.admin.four_eyes != Some(false),
            "admin.four_eyes",
            "must not be false in production (K-66 four-eyes approval)",
        );
        self.validate_notify_environment(p);
        p.require(
            self.crypto.signing_keys.retired_retention >= self.session.access_token_ttl,
            "crypto.signing_keys.retired_retention",
            "must be at least session.access_token_ttl (CRY-10)",
        );
        p.require(
            self.admin.step_up_max_age <= self.session.step_up_max_age,
            "admin.step_up_max_age",
            "must not be longer than session.step_up_max_age",
        );
    }

    /// Environment-dependent `[notify]` rules (NTF-03, NTF-04). The
    /// authn-notify builders enforce the same rules again at startup; here
    /// they also reach `check-config` and every other `AppConfig` consumer.
    fn validate_notify_environment(&self, p: &mut ConfigProblems) {
        let environment = self.server.environment;
        let development = matches!(environment, Environment::Development | Environment::Test);
        p.require(
            development || self.notify.email.transport != notify::EmailTransportKind::Log,
            "notify.email.transport",
            "the log transport is for development and test only",
        );
        p.require(
            development || self.notify.sms.provider != notify::SmsProviderKind::Log,
            "notify.sms.provider",
            "the log provider is for development and test only",
        );
        p.require(
            environment != Environment::Production
                || self.notify.email.transport != notify::EmailTransportKind::Disabled,
            "notify.email.transport",
            "\"disabled\" is not allowed in production (verification and reset mails would be lost)",
        );
        p.require(
            development
                || self
                    .notify
                    .email
                    .smtp
                    .as_ref()
                    .is_none_or(|smtp| smtp.extra_ca_file.is_none()),
            "notify.email.smtp.extra_ca_file",
            "is for development and test only (e.g. the docker-compose Mailpit certificate)",
        );
    }

    fn reject_public_keys(&self, p: &mut ConfigProblems) {
        use crate::secret::ExposeSecret;
        let is_public = |secret: &crate::secret::SecretString| {
            let value = secret.expose_secret().trim();
            KNOWN_PUBLIC_KEYS
                .iter()
                .any(|known| crate::secret::constant_time_eq(known.as_bytes(), value.as_bytes()))
        };
        for (i, pepper) in self.crypto.peppers.iter().enumerate() {
            p.require(
                !is_public(&pepper.key),
                &format!("crypto.peppers[{i}].key"),
                "is a published example/test key",
            );
        }
        for (i, kek) in self.crypto.keks.iter().enumerate() {
            p.require(
                !is_public(&kek.key),
                &format!("crypto.keks[{i}].key"),
                "is a published example/test key",
            );
        }
        p.require(
            !is_public(&self.crypto.hmac_root_key),
            "crypto.hmac_root_key",
            "is a published example/test key",
        );
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use figment::providers::Serialized;

    use super::*;

    const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KEY_B: &str = "HxwdHhscGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=";

    fn minimal_toml() -> String {
        format!(
            r#"
            [server]
            environment = "development"
            public_base_url = "http://localhost:8080"

            [database]
            url = "postgres://authn:secret-db-password@localhost/authn"

            [notify.email]
            transport = "log"

            [crypto]
            current_pepper_version = 1
            current_kek_id = "k1"
            hmac_root_key = "{KEY_A}"
            [[crypto.peppers]]
            version = 1
            key = "{KEY_B}"
            [[crypto.keks]]
            id = "k1"
            key = "{KEY_A}"
            "#
        )
    }

    fn load(toml: &str) -> Result<AppConfig, ConfigError> {
        AppConfig::from_figment(&Figment::new().merge(Toml::string(toml)))
    }

    #[test]
    fn arc_07_minimal_config_gets_spec_defaults() {
        let cfg = load(&minimal_toml()).unwrap();
        // A sample of spec defaults from every section.
        assert_eq!(cfg.crypto.argon2.memory_kib, 19_456);
        assert_eq!(cfg.crypto.argon2.iterations, 2);
        assert_eq!(cfg.crypto.argon2.parallelism, 1);
        assert_eq!(cfg.crypto.jwt_leeway, Duration::from_secs(30));
        assert_eq!(cfg.password.min_length, 12);
        assert_eq!(cfg.password.max_length, 128);
        assert_eq!(cfg.password.min_strength_score, 3);
        assert_eq!(cfg.password.reset.token_ttl, Duration::from_secs(30 * 60));
        assert!(cfg.password.breach_check.fail_open);
        assert_eq!(
            cfg.account.verification.link_ttl,
            Duration::from_secs(24 * 3600)
        );
        assert_eq!(
            cfg.account.verification.code_ttl,
            Duration::from_secs(15 * 60)
        );
        assert_eq!(cfg.account.verification.code_max_attempts, 5);
        assert_eq!(
            cfg.account.verification.resend_cooldown,
            Duration::from_secs(60)
        );
        assert_eq!(
            cfg.account.unverified_purge_after,
            Duration::from_secs(7 * 86_400)
        );
        assert_eq!(
            cfg.account.deletion_grace_period,
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(cfg.session.web.idle_timeout, Duration::from_secs(2 * 3600));
        assert_eq!(
            cfg.session.web.absolute_timeout,
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(
            cfg.session.remember_me.idle_timeout,
            Duration::from_secs(14 * 86_400)
        );
        assert_eq!(
            cfg.session.refresh_token.absolute_timeout,
            Duration::from_secs(90 * 86_400)
        );
        assert_eq!(cfg.session.access_token_ttl, Duration::from_secs(600));
        assert_eq!(cfg.session.refresh_reuse_grace, Duration::ZERO);
        assert_eq!(cfg.session.mfa_challenge_ttl, Duration::from_secs(300));
        assert_eq!(cfg.session.step_up_max_age, Duration::from_secs(600));
        assert_eq!(cfg.session.max_concurrent_sessions, None);
        assert_eq!(cfg.session.magic_link_ttl, Duration::from_secs(900));
        assert_eq!(cfg.mfa.totp.digits, 6);
        assert_eq!(cfg.mfa.totp.period, Duration::from_secs(30));
        assert_eq!(cfg.mfa.totp.skew_steps, 1);
        assert_eq!(cfg.mfa.recovery_codes.count, 10);
        assert_eq!(cfg.mfa.trusted_device.ttl, Duration::from_secs(30 * 86_400));
        assert_eq!(cfg.webauthn.ceremony_ttl, Duration::from_secs(300));
        assert_eq!(cfg.oidc_client.state_ttl, Duration::from_secs(600));
        assert!(!cfg.oidc_client.auto_link_verified_email);
        assert_eq!(cfg.org.invitation_ttl, Duration::from_secs(7 * 86_400));
        assert_eq!(
            cfg.org.api_keys.max_lifetime,
            Duration::from_secs(365 * 86_400)
        );
        assert_eq!(cfg.server.limits.body_limit_bytes, 64 * 1024);
        assert_eq!(cfg.protect.rate_limit.login_per_ip.limit, 100);
        assert_eq!(
            cfg.protect.security_headers.hsts_max_age,
            Duration::from_secs(63_072_000)
        );
        assert_eq!(
            cfg.audit.user_visible_window,
            Duration::from_secs(90 * 86_400)
        );
        assert_eq!(
            cfg.admin.impersonation_default_ttl,
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            cfg.admin.impersonation_max_ttl,
            Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn arc_07_missing_secrets_fail_fast() {
        let toml = "[server]\npublic_base_url = \"http://localhost\"\n[database]\nurl = \"postgres://x\"\n";
        let err = load(toml).unwrap_err();
        assert!(err.to_string().contains("crypto"), "{err}");
    }

    #[test]
    fn arc_07_unknown_keys_are_rejected() {
        let toml = format!("{}\n[session]\nacess_token_ttl = \"5m\"\n", minimal_toml());
        let err = load(&toml).unwrap_err();
        assert!(err.to_string().contains("acess_token_ttl"), "{err}");
    }

    #[test]
    fn arc_07_invalid_values_are_all_reported_without_secrets() {
        let toml = minimal_toml().replace(
            "environment = \"development\"",
            "environment = \"production\"",
        ) + "\n[password]\nmin_length = 4\n[session]\nrefresh_reuse_grace = \"1m\"\n";
        let err = load(&toml).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("password.min_length"), "{text}");
        assert!(text.contains("session.refresh_reuse_grace"), "{text}");
        assert!(text.contains("server.public_base_url"), "{text}");
        assert!(!text.contains("secret-db-password"), "{text}");
        assert!(!text.contains(KEY_A) && !text.contains(KEY_B), "{text}");
        let ConfigError::Invalid(problems) = err else {
            panic!("expected Invalid")
        };
        assert!(problems.len() >= 3);
    }

    #[test]
    fn arc_07_type_errors_do_not_echo_values() {
        let toml = minimal_toml().replace(
            "current_pepper_version = 1",
            "current_pepper_version = \"super-secret-value\"",
        );
        let text = load(&toml).unwrap_err().to_string();
        assert!(text.contains("current_pepper_version"), "{text}");
        assert!(!text.contains("super-secret-value"), "{text}");
    }

    #[test]
    fn arc_07_environment_overrides_file() {
        let figment = Figment::new()
            .merge(Toml::string(&minimal_toml()))
            .merge(Serialized::default("session.access_token_ttl", "5m"));
        let cfg = AppConfig::from_figment(&figment).unwrap();
        assert_eq!(cfg.session.access_token_ttl, Duration::from_secs(300));
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment's own error type
    fn arc_07_env_provider_uses_prefix_and_double_underscore() {
        // Exercise the real Env provider through figment's jail (no global
        // environment mutation leaks out of the closure).
        figment::Jail::expect_with(|jail| {
            jail.create_file("authn.toml", &minimal_toml())?;
            jail.set_env("AUTHN__SESSION__ACCESS_TOKEN_TTL", "7m");
            jail.set_env("AUTHN__PASSWORD__MIN_LENGTH", "15");
            let cfg = AppConfig::load(Some(Path::new("authn.toml")))
                .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.session.access_token_ttl, Duration::from_secs(420));
            assert_eq!(cfg.password.min_length, 15);
            Ok(())
        });
    }

    #[test]
    fn arc_07_missing_config_file_is_an_error() {
        let err = AppConfig::load(Some(Path::new("/nonexistent/authn.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::Load(_)));
    }

    #[test]
    fn cry_02_published_keys_are_refused_in_production() {
        let toml =
            minimal_toml().replace("environment = \"development\"", "environment = \"staging\"");
        let text = load(&toml).unwrap_err().to_string();
        assert!(
            text.contains("crypto.keks[0].key: is a published"),
            "{text}"
        );
        assert!(
            text.contains("crypto.hmac_root_key: is a published"),
            "{text}"
        );
    }

    fn problems(toml: &str) -> Vec<String> {
        match load(toml) {
            Ok(_) => Vec::new(),
            Err(ConfigError::Invalid(problems)) => problems,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    fn with_environment(environment: &str, extra: &str) -> String {
        minimal_toml().replace(
            "environment = \"development\"",
            &format!("environment = \"{environment}\""),
        ) + extra
    }

    const DEV_ONLY_NOTIFY: &str = "
        [notify.email.smtp]
        host = \"localhost\"
        port = 1025
        extra_ca_file = \"config/dev-certs/mailpit.pem\"
        [notify.sms]
        provider = \"log\"
        ";

    #[test]
    fn ntf_03_development_only_notify_settings_are_refused_outside_development() {
        for environment in ["staging", "production"] {
            let found = problems(&with_environment(environment, DEV_ONLY_NOTIFY));
            for expected in [
                "notify.email.transport: the log transport",
                "notify.sms.provider: the log provider",
                "notify.email.smtp.extra_ca_file: is for development",
            ] {
                assert!(
                    found.iter().any(|p| p.starts_with(expected)),
                    "{environment}: {expected} missing in {found:?}"
                );
            }
        }
        // Development and test accept all of them (docker-compose Mailpit).
        for environment in ["development", "test"] {
            let found = problems(&with_environment(environment, DEV_ONLY_NOTIFY));
            assert!(
                !found.iter().any(|p| p.starts_with("notify.")),
                "{environment}: {found:?}"
            );
        }
    }

    #[test]
    fn adm_06_k66_four_eyes_cannot_be_switched_off_in_production() {
        let off =
            |environment: &str| with_environment(environment, "\n[admin]\nfour_eyes = false\n");
        let production = problems(&off("production"));
        assert!(
            production.iter().any(|p| p.starts_with("admin.four_eyes")),
            "{production:?}"
        );
        for environment in ["staging", "development", "test"] {
            let found = problems(&off(environment));
            assert!(
                !found.iter().any(|p| p.starts_with("admin.four_eyes")),
                "{environment}: {found:?}"
            );
        }
        let on = with_environment("production", "\n[admin]\nfour_eyes = true\n");
        assert!(
            !problems(&on)
                .iter()
                .any(|p| p.starts_with("admin.four_eyes"))
        );
    }

    #[test]
    fn prt_05_k58_captcha_hostnames_are_required_in_production() {
        let captcha = "\n[protect.captcha]\nprovider = \"turnstile\"\nsite_key = \"site\"\nsecret_key = \"secret\"\n";
        let key = "protect.captcha.hostnames";
        let production = problems(&with_environment("production", captcha));
        assert!(
            production.iter().any(|p| p.starts_with(key)),
            "{production:?}"
        );
        let development = problems(&with_environment("development", captcha));
        assert!(
            !development.iter().any(|p| p.starts_with(key)),
            "{development:?}"
        );
        let listed = format!("{captcha}hostnames = [\"auth.example.com\"]\n");
        let fixed = problems(&with_environment("production", &listed));
        assert!(!fixed.iter().any(|p| p.starts_with(key)), "{fixed:?}");
    }

    /// K-57 F1 (PRT-06): a catch-all `trusted_proxies` entry trusts every
    /// TCP peer and every forwarding hop, so the client IP becomes the
    /// left-most `X-Forwarded-For` value — chosen by the client. Per-IP
    /// rate limits, lock-out keys, risk signals, audit IPs and every
    /// organization IP allow-list (ORG-07) would trust a spoofed address.
    /// Refused in every environment.
    #[test]
    fn prt_06_k57_catch_all_trusted_proxies_are_refused() {
        for environment in ["production", "staging", "development", "test"] {
            for net in ["0.0.0.0/0", "::/0"] {
                let toml = with_environment(environment, "").replace(
                    "public_base_url = \"http://localhost:8080\"",
                    &format!(
                        "public_base_url = \"http://localhost:8080\"\ntrusted_proxies = [\"10.0.0.0/8\", \"{net}\"]"
                    ),
                );
                let found = problems(&toml);
                assert!(
                    found
                        .iter()
                        .any(|p| p.starts_with("server.trusted_proxies[1]")),
                    "{environment} {net}: {found:?}"
                );
            }
        }
        let fine = with_environment("development", "").replace(
            "public_base_url = \"http://localhost:8080\"",
            "public_base_url = \"http://localhost:8080\"\ntrusted_proxies = [\"10.0.0.0/8\", \"fd00::/8\"]",
        );
        assert!(
            !problems(&fine)
                .iter()
                .any(|p| p.starts_with("server.trusted_proxies")),
            "{:?}",
            problems(&fine)
        );
    }

    /// K-57 F1 re-audit (PRT-06): the catch-all check alone is bypassed by
    /// splitting the address space (`0.0.0.0/1` + `128.0.0.0/1`, `::/1` +
    /// `8000::/1`) or by any other near-catch-all covering large parts of
    /// the public internet. Real proxy ranges (private networks, published
    /// load-balancer / CDN ranges) are never shorter than an IPv4 `/8` or a
    /// global IPv6 `/16`; the private IPv6 ranges (`fc00::/7`,
    /// `fe80::/10`) stay allowed.
    #[test]
    fn prt_06_k57_near_catch_all_trusted_proxies_are_refused() {
        let with = |nets: &str| {
            with_environment("production", "").replace(
                "public_base_url = \"http://localhost:8080\"",
                &format!("public_base_url = \"http://localhost:8080\"\ntrusted_proxies = [{nets}]"),
            )
        };
        for nets in [
            "\"0.0.0.0/1\", \"128.0.0.0/1\"",
            "\"::/1\", \"8000::/1\"",
            "\"0.0.0.0/4\"",
            "\"64.0.0.0/7\"",
            "\"2000::/3\"",
            "\"2001::/15\"",
        ] {
            let found = problems(&with(nets));
            assert!(
                found
                    .iter()
                    .any(|p| p.starts_with("server.trusted_proxies[0]")),
                "{nets}: {found:?}"
            );
        }
        for nets in [
            "\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\", \"100.64.0.0/10\"",
            "\"fc00::/7\", \"fe80::/10\", \"fd00::/8\"",
            // Published CDN ranges (Cloudflare).
            "\"104.16.0.0/13\", \"2a06:98c0::/29\", \"2400:cb00::/32\"",
            "\"127.0.0.1/32\", \"::1/128\"",
        ] {
            let found = problems(&with(nets));
            assert!(
                !found
                    .iter()
                    .any(|p| p.starts_with("server.trusted_proxies")),
                "{nets}: {found:?}"
            );
        }
    }

    #[test]
    fn ses_08_k58_session_check_cannot_be_switched_off_in_production_or_staging() {
        let off = |environment: &str| {
            with_environment(
                environment,
                "\n[session]\naccess_token_session_check = false\n",
            )
        };
        let key = "session.access_token_session_check";
        for environment in ["production", "staging"] {
            let found = problems(&off(environment));
            assert!(
                found.iter().any(|p| p.starts_with(key)),
                "{environment}: {found:?}"
            );
        }
        for environment in ["development", "test"] {
            let found = problems(&off(environment));
            assert!(
                !found.iter().any(|p| p.starts_with(key)),
                "{environment}: {found:?}"
            );
        }
        let default = with_environment("production", "");
        assert!(!problems(&default).iter().any(|p| p.starts_with(key)));
    }

    #[test]
    fn ntf_03_disabled_email_transport_is_refused_in_production_only() {
        let disabled = |environment: &str| {
            with_environment(environment, "").replace(
                "[notify.email]\n            transport = \"log\"",
                "[notify.email]\n            transport = \"disabled\"",
            )
        };
        assert!(disabled("staging").contains("transport = \"disabled\""));
        let production = problems(&disabled("production"));
        assert!(
            production
                .iter()
                .any(|p| p.starts_with("notify.email.transport: \"disabled\"")),
            "{production:?}"
        );
        for environment in ["staging", "development", "test"] {
            let found = problems(&disabled(environment));
            assert!(
                !found.iter().any(|p| p.starts_with("notify.")),
                "{environment}: {found:?}"
            );
        }
    }

    /// ARC-07 / K-111: staging runs the production security rules. Before
    /// the fix staging only refused the published example keys, so a
    /// staging deployment (often reachable from the internet, often with a
    /// copy of real data) could run over http, with SSRF protection off,
    /// per-instance rate limits, no per-request session check and CAPTCHA
    /// tokens accepted from any site. The two documented exceptions stay
    /// allowed: four-eyes approval may be switched off and e-mail may be
    /// `disabled` (a staging copy must be able to never mail real users).
    #[test]
    fn arc_07_k111_staging_enforces_the_production_security_rules() {
        let weak = "
            [webauthn]
            allowed_origins = [\"http://localhost:8080\"]
            [protect.outbound]
            allow_private_networks = true
            [protect.rate_limit]
            backend = \"memory\"
            [session]
            access_token_session_check = false
            [protect.captcha]
            provider = \"turnstile\"
            site_key = \"site\"
            secret_key = \"secret\"
            ";
        let expected = [
            "server.public_base_url: must use https",
            "webauthn.allowed_origins: web origins must use https",
            "protect.outbound.allow_private_networks: must be false",
            "protect.rate_limit.backend: the in-memory backend",
            "session.access_token_session_check: must stay true",
            "protect.captcha.hostnames: required",
        ];
        for environment in ["production", "staging"] {
            let found = problems(&with_environment(environment, weak));
            for rule in expected {
                assert!(
                    found.iter().any(|p| p.starts_with(rule)),
                    "{environment}: {rule} missing in {found:?}"
                );
            }
        }
        // Development and test keep the relaxed rules.
        for environment in ["development", "test"] {
            let found = problems(&with_environment(environment, weak));
            for rule in expected {
                assert!(
                    !found.iter().any(|p| p.starts_with(rule)),
                    "{environment}: {rule} in {found:?}"
                );
            }
        }
        // The documented staging exceptions.
        let exceptions = with_environment("staging", "\n[admin]\nfour_eyes = false\n").replace(
            "[notify.email]\n            transport = \"log\"",
            "[notify.email]\n            transport = \"disabled\"",
        );
        let found = problems(&exceptions);
        assert!(
            !found
                .iter()
                .any(|p| p.starts_with("admin.four_eyes") || p.starts_with("notify.")),
            "{found:?}"
        );
    }

    #[test]
    fn cry_02_secrets_are_redacted_in_debug() {
        let cfg = load(&minimal_toml()).unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("secret-db-password"));
        assert!(!debug.contains(KEY_A));
        assert!(!debug.contains(KEY_B));
    }
}
