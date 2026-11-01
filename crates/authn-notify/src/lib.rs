//! # authn-notify
//!
//! Transactional messaging of `rust-authentication`: the [`Notifier`] port
//! backed by the transactional outbox, TR/EN templates (HTML + text,
//! minijinja with auto-escaping), e-mail transports (SMTP with mandatory
//! TLS, log, memory) and SMS senders (generic HTTP provider, log, memory).
//!
//! Owned requirements: NTF-01 … NTF-04.
//!
//! | Module | Requirement | What |
//! |--------|-------------|------|
//! | [`outbox`] | NTF-01, NTF-03 | [`OutboxNotifier`]: `notify*` enqueue `notification.email` / `notification.sms` outbox rows; secrets and personal data sealed (CRY-08, AAD = outbox row) |
//! | [`deliver`] | NTF-03, NTF-04 | [`NotificationDeliverer`]: topic-agnostic delivery of one outbox row (unseal, render, send) with retry/permanent classification |
//! | [`templates`] | NTF-01, NTF-02 | [`TemplateRenderer`]: built-in TR/EN templates for every notification kind, override directory, startup validation |
//! | [`links`] | NTF-02, PWD-08 | [`LinkBuilder`]: links only from `server.public_base_url` + configured paths, token in the URL fragment |
//! | [`sanitize`] | NTF-02 | Neutralisation of user-provided text and header values |
//! | [`email`] | NTF-03 | [`SmtpEmailTransport`] (STARTTLS / implicit TLS only), [`LogEmailTransport`], [`MemoryEmailTransport`], [`DisabledEmailTransport`] |
//! | [`sms`] | NTF-04 | `HttpSmsSender` (feature `sms`), [`LogSmsSender`], [`MemorySmsSender`], [`DisabledSmsSender`] |
//! | [`services`] | ARC-07 | [`NotifyServices::from_config`]: everything wired from `[notify]`, fail-fast |
//!
//! This crate exposes no HTTP endpoint (NTF-* define none): producers use
//! the `Notifier` port, the server registers the deliverer with the outbox
//! worker of `authn-audit` (see `README.md`).
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::notify`; startup problems are
//!   [`NotifyError`].
//!
//! [`Notifier`]: authn_core::ports::Notifier

#![forbid(unsafe_code)]

pub mod deliver;
pub mod email;
pub mod error;
mod format;
pub mod links;
pub mod outbox;
pub mod sanitize;
pub mod services;
pub mod sms;
pub mod templates;

pub use deliver::{DeliveryFailure, DeliveryRequest, NotificationDeliverer};
pub use email::{
    DisabledEmailTransport, LogEmailTransport, MemoryEmailTransport, SmtpEmailTransport,
    email_transport_from_config,
};
pub use error::{NotifyError, RenderError};
pub use links::{LinkBuilder, LinkTarget};
pub use outbox::{
    EMAIL_TOPIC, NOTIFICATION_TOPIC_PREFIX, OutboxNotifier, SMS_TOPIC, sealed_payload_context,
};
pub use services::NotifyServices;
#[cfg(feature = "sms")]
pub use sms::HttpSmsSender;
pub use sms::{DisabledSmsSender, LogSmsSender, MemorySmsSender, sms_sender_from_config};
pub use templates::{RenderedEmail, TemplateRenderer};
