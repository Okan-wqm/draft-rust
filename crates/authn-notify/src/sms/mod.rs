//! SMS senders (NTF-04): the [`SmsSender`] port implementations.
//!
//! | Sender | Use | `is_configured` | Allowed environments |
//! |--------|-----|-----------------|----------------------|
//! | `HttpSmsSender` (feature `sms`) | generic HTTP provider through the `HttpClient` port | `true` | all |
//! | [`LogSmsSender`] | development: logs masked number, code redacted | `true` | development, test |
//! | [`MemorySmsSender`] | tests: records messages, can inject failures | `true` | any (built directly) |
//! | [`DisabledSmsSender`] | `provider = "none"` (default): SMS unavailable | `false` | all |
//!
//! Destinations are `PhoneNumber` values, i.e. strict E.164 by
//! construction. SMS pumping protection (country allow-list, per-number /
//! per-IP limits, global budget) is enforced by `authn-mfa` before a send.

#[cfg(feature = "sms")]
mod http;
mod log;
mod memory;

use std::sync::Arc;

use authn_core::config::Environment;
use authn_core::config::notify::{NotifyConfig, SmsProviderKind};
use authn_core::ports::{HttpClient, SmsSender};

#[cfg(feature = "sms")]
pub use self::http::HttpSmsSender;
pub use self::log::LogSmsSender;
pub use self::memory::{DisabledSmsSender, MemorySmsSender};
use crate::error::NotifyError;

/// Longest SMS body accepted by the senders (10 concatenated segments).
pub const MAX_SMS_BODY_CHARS: usize = 1600;

/// Builds the configured sender (fail-fast at startup). `http` must be the
/// SSRF-protected client of `authn-protect`; the provider URL is an
/// operator-configured (`Trusted`) destination.
pub fn sms_sender_from_config(
    config: &NotifyConfig,
    environment: Environment,
    http: Arc<dyn HttpClient>,
) -> Result<Arc<dyn SmsSender>, NotifyError> {
    match config.sms.provider {
        SmsProviderKind::None => {
            let _ = http;
            Ok(Arc::new(DisabledSmsSender))
        }
        SmsProviderKind::Log => {
            let _ = http;
            Ok(Arc::new(LogSmsSender::new(environment)?))
        }
        #[cfg(feature = "sms")]
        SmsProviderKind::Http => Ok(Arc::new(HttpSmsSender::from_config(&config.sms, http)?)),
        #[cfg(not(feature = "sms"))]
        SmsProviderKind::Http => {
            let _ = http;
            Err(NotifyError::config(
                "notify.sms.provider = \"http\" requires the `sms` cargo feature",
            ))
        }
    }
}

/// Whether an SMS body is acceptable: 1–1600 characters, no control
/// characters other than `\n`.
pub(crate) fn is_valid_body(body: &str) -> bool {
    let length = body.chars().count();
    (1..=MAX_SMS_BODY_CHARS).contains(&length) && body.chars().all(|c| c == '\n' || !c.is_control())
}

#[cfg(test)]
mod tests {
    use authn_testkit::fakes::FakeHttpClient;

    use super::*;

    #[test]
    fn ntf_04_sms_sender_selection_follows_configuration() {
        let http: Arc<dyn HttpClient> = Arc::new(FakeHttpClient::default());
        let mut config = NotifyConfig::default();
        let sender =
            sms_sender_from_config(&config, Environment::Production, http.clone()).unwrap();
        assert!(
            !sender.is_configured(),
            "provider none behaves as disabled (ARC-11)"
        );
        config.sms.provider = SmsProviderKind::Log;
        assert!(sms_sender_from_config(&config, Environment::Production, http.clone()).is_err());
        assert!(sms_sender_from_config(&config, Environment::Staging, http.clone()).is_err());
        assert!(
            sms_sender_from_config(&config, Environment::Development, http)
                .unwrap()
                .is_configured()
        );
    }

    #[test]
    fn ntf_04_sms_bodies_are_bounded_and_control_free() {
        assert!(is_valid_body(
            "123456 is your code.\n\n@auth.example #123456"
        ));
        assert!(!is_valid_body(""));
        assert!(!is_valid_body("a\rb"));
        assert!(!is_valid_body(&"x".repeat(MAX_SMS_BODY_CHARS + 1)));
    }
}
