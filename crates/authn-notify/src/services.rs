//! Everything of this crate built from the configuration (for
//! `authn-server`'s `AppState` and background workers).

use std::fmt;
use std::sync::Arc;

use authn_core::config::AppConfig;
use authn_core::ports::{Clock, EmailTransport, HttpClient, Notifier, RateLimiter, SmsSender};
use authn_crypto::envelope::EnvelopeCipher;
use sqlx::PgPool;

use crate::deliver::NotificationDeliverer;
use crate::email::email_transport_from_config;
use crate::error::NotifyError;
use crate::outbox::OutboxNotifier;
use crate::sms::sms_sender_from_config;
use crate::templates::TemplateRenderer;

/// The notification services of the process.
#[derive(Clone)]
pub struct NotifyServices {
    /// The `Notifier` port implementation (outbox producer).
    pub notifier: Arc<OutboxNotifier>,
    /// Delivers `notification.*` outbox rows (register with the outbox
    /// worker through a bridge handler).
    pub deliverer: Arc<NotificationDeliverer>,
    /// Templates (validated).
    pub renderer: Arc<TemplateRenderer>,
    /// The configured e-mail transport.
    pub email: Arc<dyn EmailTransport>,
    /// The configured SMS sender (also usable synchronously by authn-mfa).
    pub sms: Arc<dyn SmsSender>,
}

impl fmt::Debug for NotifyServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotifyServices")
            .field("notifier", &self.notifier)
            .field("renderer", &self.renderer)
            .field("sms_configured", &self.sms.is_configured())
            .finish_non_exhaustive()
    }
}

impl NotifyServices {
    /// Builds and validates everything (templates, transports, senders);
    /// fails fast on any problem (ARC-07).
    ///
    /// * `cipher` — the process `EnvelopeCipher` (`CryptoServices::envelopes`).
    /// * `rate_limiter` — the configured `RateLimiter` (per-recipient limit).
    /// * `http` — the SSRF-protected `HttpClient` of authn-protect (SMS).
    pub fn from_config(
        config: &AppConfig,
        pool: PgPool,
        cipher: EnvelopeCipher,
        clock: Arc<dyn Clock>,
        rate_limiter: Arc<dyn RateLimiter>,
        http: Arc<dyn HttpClient>,
    ) -> Result<Self, NotifyError> {
        let environment = config.server.environment;
        let renderer = Arc::new(TemplateRenderer::from_config(config)?);
        let email = email_transport_from_config(&config.notify, environment)?;
        let sms = sms_sender_from_config(&config.notify, environment, http)?;
        let notifier = Arc::new(OutboxNotifier::from_config(
            &config.notify,
            pool,
            cipher.clone(),
            clock.clone(),
            rate_limiter,
        ));
        let deliverer = Arc::new(NotificationDeliverer::new(
            cipher,
            renderer.clone(),
            email.clone(),
            sms.clone(),
            clock,
        ));
        Ok(Self {
            notifier,
            deliverer,
            renderer,
            email,
            sms,
        })
    }

    /// The notifier as the port trait object.
    #[must_use]
    pub fn notifier_port(&self) -> Arc<dyn Notifier> {
        self.notifier.clone()
    }
}
