//! E-mail transports (NTF-03): the [`EmailTransport`] port implementations.
//!
//! | Transport | Use | Allowed environments |
//! |-----------|-----|----------------------|
//! | [`SmtpEmailTransport`] | real delivery, STARTTLS or implicit TLS **only** | all |
//! | [`LogEmailTransport`] | development: logs metadata and a body with links/codes redacted | development, test |
//! | [`MemoryEmailTransport`] | tests: records messages, can inject failures | any (built directly) |
//! | [`DisabledEmailTransport`] | drops messages | everything except production |
//!
//! Transports report temporary failures as `service_unavailable` (the
//! outbox retries) and permanent rejections as `delivery_rejected`
//! (dead-lettered).

mod log;
mod memory;
mod smtp;

use std::sync::Arc;

use authn_core::config::Environment;
use authn_core::config::notify::{EmailTransportKind, NotifyConfig};
use authn_core::ports::EmailTransport;

pub use self::log::LogEmailTransport;
pub(crate) use self::memory::lock as memory_lock;
pub use self::memory::{DisabledEmailTransport, InjectedFailure, MemoryEmailTransport};
pub use self::smtp::SmtpEmailTransport;
use crate::error::NotifyError;

/// Whether development-only conveniences are allowed.
pub(crate) const fn is_development(environment: Environment) -> bool {
    matches!(environment, Environment::Development | Environment::Test)
}

/// Builds the configured transport, refusing development-only transports
/// outside development/test (fail-fast at startup).
pub fn email_transport_from_config(
    config: &NotifyConfig,
    environment: Environment,
) -> Result<Arc<dyn EmailTransport>, NotifyError> {
    match config.email.transport {
        EmailTransportKind::Smtp => Ok(Arc::new(SmtpEmailTransport::from_config(
            &config.email,
            environment,
        )?)),
        EmailTransportKind::Log => Ok(Arc::new(LogEmailTransport::new(environment)?)),
        EmailTransportKind::Disabled => {
            if environment == Environment::Production {
                return Err(NotifyError::config(
                    "notify.email.transport = \"disabled\" is not allowed in production",
                ));
            }
            Ok(Arc::new(DisabledEmailTransport))
        }
    }
}

/// Replaces link-token fragments and runs of six or more digits (codes)
/// with `[REDACTED]`, for development logs.
pub(crate) fn redact_secrets(text: &str) -> String {
    const TOKEN_MARKER: &str = "token=";
    let mut out = String::with_capacity(text.len());
    let mut digits = String::new();
    let mut chars = text.chars().peekable();
    let flush = |digits: &mut String, out: &mut String| {
        if digits.len() >= 6 {
            out.push_str(authn_core::secret::REDACTED);
        } else {
            out.push_str(digits);
        }
        digits.clear();
    };
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        flush(&mut digits, &mut out);
        out.push(c);
        if out.ends_with(TOKEN_MARKER) {
            let mut skipped = false;
            while chars
                .peek()
                .is_some_and(|n| n.is_ascii_alphanumeric() || *n == '-' || *n == '_')
            {
                chars.next();
                skipped = true;
            }
            if skipped {
                out.push_str(authn_core::secret::REDACTED);
            }
        }
    }
    flush(&mut digits, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntf_03_development_logs_redact_links_and_codes() {
        let text = "Code: 123456\nhttps://a.example/reset#token=AbC-_123xyz\nyear 2026";
        assert_eq!(
            redact_secrets(text),
            "Code: [REDACTED]\nhttps://a.example/reset#token=[REDACTED]\nyear 2026"
        );
        assert_eq!(redact_secrets("12345"), "12345");
        assert_eq!(redact_secrets("x9876543210"), "x[REDACTED]");
    }

    #[test]
    fn ntf_03_development_transports_are_refused_in_production() {
        let mut config = NotifyConfig::default();
        config.email.transport = EmailTransportKind::Log;
        for env in [Environment::Production, Environment::Staging] {
            assert!(email_transport_from_config(&config, env).is_err());
        }
        assert!(email_transport_from_config(&config, Environment::Development).is_ok());
        config.email.transport = EmailTransportKind::Disabled;
        assert!(email_transport_from_config(&config, Environment::Production).is_err());
        assert!(email_transport_from_config(&config, Environment::Test).is_ok());
        config.email.transport = EmailTransportKind::Smtp;
        assert!(
            email_transport_from_config(&config, Environment::Test).is_err(),
            "smtp without [notify.email.smtp]"
        );
    }
}
