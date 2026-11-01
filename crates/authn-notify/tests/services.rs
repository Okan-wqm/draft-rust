#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ARC-07 / NTF-03 / NTF-04: everything wired from the configuration,
//! fail-fast on settings that are not allowed in the environment.

use std::sync::Arc;

use authn_core::config::Environment;
use authn_core::config::notify::{EmailTransportKind, SmsProviderKind};
use authn_core::domain::{EmailAddress, PhoneNumber};
use authn_core::ports::{Clock, EmailMessage, HttpClient, RateLimiter, SmsMessage};
use authn_core::secret::SensitiveString;
use authn_crypto::envelope::EnvelopeCipher;
use authn_notify::{LogEmailTransport, LogSmsSender, NotifyServices};
use authn_testkit::TestPorts;
use authn_testkit::config::test_config;

fn build(
    config: &authn_core::config::AppConfig,
) -> Result<NotifyServices, authn_notify::NotifyError> {
    let ports = TestPorts::new();
    let pool = sqlx::PgPool::connect_lazy("postgres://unused@localhost/unused").unwrap();
    NotifyServices::from_config(
        config,
        pool,
        EnvelopeCipher::from_config(&config.crypto).unwrap(),
        ports.clock.clone() as Arc<dyn Clock>,
        ports.rate_limiter.clone() as Arc<dyn RateLimiter>,
        ports.http.clone() as Arc<dyn HttpClient>,
    )
}

#[tokio::test]
async fn ntf_03_services_are_built_from_the_test_configuration() {
    let services = build(&test_config()).unwrap();
    assert!(
        !services.sms.is_configured(),
        "provider none: SMS unavailable (ARC-11)"
    );
    assert!(services.renderer.overridden().is_empty());
    let _port = services.notifier_port();
    let debug = format!("{services:?}");
    assert!(debug.contains("NotifyServices"));
}

#[tokio::test]
async fn ntf_03_development_only_settings_fail_fast_outside_development() {
    let mut config = test_config();
    config.server.environment = Environment::Staging;
    // Log e-mail transport (test default) is refused in staging.
    let err = build(&config).unwrap_err();
    assert!(err.to_string().contains("notify.email.transport"), "{err}");

    let mut config = test_config();
    config.notify.email.transport = EmailTransportKind::Disabled;
    config.notify.sms.provider = SmsProviderKind::Log;
    config.server.environment = Environment::Production;
    let err = build(&config).unwrap_err();
    assert!(err.to_string().contains("disabled"), "{err}");
}

#[tokio::test]
async fn ntf_02_broken_override_directory_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("en/email")).unwrap();
    std::fs::write(dir.path().join("en/email/login_code.txt"), "{% if %}").unwrap();
    let mut config = test_config();
    config.notify.template_dir = Some(dir.path().to_path_buf());
    let err = build(&config).unwrap_err();
    assert!(err.to_string().contains("en/email/login_code.txt"), "{err}");
    // A missing directory is an error too (no silent fallback).
    config.notify.template_dir = Some(dir.path().join("missing"));
    assert!(build(&config).is_err());
}

#[tokio::test]
async fn ntf_03_log_transports_accept_messages_in_development() {
    use authn_core::ports::{EmailTransport, SmsSender};
    let email = LogEmailTransport::new(Environment::Development).unwrap();
    email
        .send(&EmailMessage {
            to: EmailAddress::parse("dev@example.com").unwrap(),
            to_name: None,
            subject: "Your sign-in code".to_owned(),
            text_body: "Code: 123456".to_owned(),
            html_body: None,
            outbox_id: None,
        })
        .await
        .unwrap();
    let sms = LogSmsSender::new(Environment::Test).unwrap();
    assert!(sms.is_configured());
    sms.send(&SmsMessage {
        to: PhoneNumber::parse("+905551112233").unwrap(),
        body: SensitiveString::new("123456 is your code"),
    })
    .await
    .unwrap();
    assert!(LogEmailTransport::new(Environment::Production).is_err());
    assert!(LogSmsSender::new(Environment::Staging).is_err());
}

/// `config/example.toml` stays valid with every `[notify]` key enabled.
#[test]
fn ntf_03_example_config_documents_every_notify_key() {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/example.toml");
    let example = std::fs::read_to_string(&path).unwrap();
    let start = example.find("[notify]").unwrap();
    let end = example.find("[admin]").unwrap();
    let section = example.get(start..end).unwrap();
    for key in [
        "app_name",
        "template_dir",
        "max_attempts",
        "recipient_limit",
        "hello_name",
        "extra_ca_file",
        "http_auth_header",
        "http_auth_scheme",
        "http_body_template",
        "http_message_id_pointer",
    ] {
        assert!(
            section.contains(&format!("# {key} = ")),
            "{key} undocumented"
        );
    }
    let enabled: String = section
        .lines()
        .map(|line| match line.strip_prefix("# ") {
            Some(rest) if rest.split(' ').nth(1) == Some("=") => rest,
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let full = format!(
        "{}{enabled}{}",
        example.get(..start).unwrap(),
        example.get(end..).unwrap()
    );
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("example.toml");
    std::fs::write(&file, full).unwrap();
    let config = authn_core::config::AppConfig::load(Some(&file)).unwrap();
    assert_eq!(config.notify.max_attempts, 10);
    assert_eq!(config.notify.sms.http_auth_scheme, "Bearer");
}
