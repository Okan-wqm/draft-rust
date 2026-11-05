//! `config/example.toml` (OPS-08) must always be a valid configuration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use std::path::PathBuf;

use authn_core::config::{AppConfig, ConfigError, Environment};
use figment::Figment;
use figment::providers::{Format, Serialized, Toml};

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/example.toml")
}

#[test]
fn ops_08_example_config_is_valid() {
    let figment = Figment::new().merge(Toml::file_exact(example_path()));
    let config = AppConfig::from_figment(&figment).unwrap();
    assert_eq!(config.server.environment, Environment::Development);
    assert_eq!(config.crypto.peppers.len(), 1);
}

#[test]
fn ops_08_example_keys_are_refused_in_production() {
    let figment = Figment::new()
        .merge(Toml::file_exact(example_path()))
        .merge(Serialized::default("server.environment", "production"))
        .merge(Serialized::default(
            "server.public_base_url",
            "https://auth.example.com",
        ))
        .merge(Serialized::default(
            "webauthn.allowed_origins",
            ["https://auth.example.com"],
        ))
        .merge(Serialized::default(
            "protect.rate_limit.backend",
            "postgres",
        ));
    let err = AppConfig::from_figment(&figment).unwrap_err();
    let ConfigError::Invalid(problems) = err else {
        panic!("expected validation error")
    };
    assert!(
        problems.iter().any(|p| p.starts_with("crypto.keks[0].key")),
        "{problems:?}"
    );
}

/// K-74: the documented (commented) approval request caps of `[admin]` are
/// real keys with valid defaults: uncommented, the example still loads.
#[test]
fn adm_06_k74_example_approval_caps_are_valid_keys() {
    let text = std::fs::read_to_string(example_path()).unwrap();
    let keys: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("# four_eyes_max_"))
        .collect();
    assert_eq!(keys.len(), 2, "{keys:?}");
    let admin = format!(
        "[admin]\n{}\n",
        keys.iter()
            .map(|rest| format!("four_eyes_max_{rest}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let figment = Figment::new()
        .merge(Toml::file_exact(example_path()))
        .merge(Toml::string(&admin));
    let config = AppConfig::from_figment(&figment).unwrap();
    assert_eq!(config.admin.four_eyes_max_pending_requests, 3);
    assert_eq!(config.admin.four_eyes_max_requests_per_hour, 10);
}
