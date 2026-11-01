//! SMTP via `lettre` with **mandatory** TLS (NTF-03).
//!
//! * `tls = "starttls"` → `Tls::Required`: the session is aborted when the
//!   server does not offer STARTTLS or the upgrade fails — there is no
//!   opportunistic or plain-text fallback, so credentials and message
//!   contents never cross the network in clear text.
//! * `tls = "tls"` → `Tls::Wrapper` (implicit TLS, port 465).
//! * Certificates are verified against the host name with the platform
//!   verifier (rustls, `ring` provider). `extra_ca_file` adds one trusted
//!   root for development (e.g. the self-signed Mailpit certificate) and is
//!   refused outside development/test.
//! * `EHLO` sends `hello_name` (default: the sender's domain), never the
//!   machine host name (which would leak into `Received:` headers).
//! * `Message-ID` is `<outbox-id@sender-domain>`: stable across retries, so
//!   receivers can de-duplicate at-least-once deliveries.
//! * `Auto-Submitted: auto-generated` (RFC 3834) suppresses auto-replies.
//! * Subject and display names are re-sanitized here (no CR/LF reaches a
//!   header even if a caller bypasses the renderer); lettre RFC 2047-encodes
//!   non-ASCII text.
//! * Errors never carry the server's response text (it may echo the
//!   recipient address): only the SMTP code is logged.
//! * lettre's connection pool spawns Tokio tasks when it is created and
//!   dropped: [`SmtpEmailTransport::from_config`] must run inside a Tokio
//!   runtime (it returns an error otherwise instead of panicking), and a
//!   transport dropped after the runtime is gone is cleaned up on a
//!   temporary runtime.

use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use authn_core::config::Environment;
use authn_core::config::notify::{EmailConfig, SmtpTls};
use authn_core::domain::EmailAddress;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{EmailMessage, EmailTransport};
use authn_core::secret::ExposeSecret;
use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor};

use super::is_development;
use crate::error::NotifyError;
use crate::sanitize::{self, MAX_NAME_CHARS, MAX_SUBJECT_CHARS};

/// PEM header of a certificate.
const CERTIFICATE_MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";

/// Largest accepted `extra_ca_file`.
const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;

/// SMTP reply codes that are permanent for the *session* but caused by
/// configuration (authentication), not by the message: retried so that an
/// operator can fix the credentials without losing messages.
const AUTH_FAILURE_CODES: [&str; 4] = ["530", "534", "535", "538"];

/// SMTP transport with mandatory TLS.
pub struct SmtpEmailTransport {
    /// Always `Some` until dropped (see the `Drop` impl).
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Mailbox,
    message_id_domain: String,
}

impl fmt::Debug for SmtpEmailTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpEmailTransport")
            .field("message_id_domain", &self.message_id_domain)
            .finish_non_exhaustive()
    }
}

fn read_ca_file(path: &std::path::Path) -> Result<Vec<u8>, NotifyError> {
    let io_err = |source| NotifyError::Io {
        path: path.to_path_buf(),
        source,
    };
    let metadata = std::fs::metadata(path).map_err(io_err)?;
    if !metadata.is_file() || metadata.len() > MAX_CA_FILE_BYTES {
        return Err(NotifyError::config(
            "notify.email.smtp.extra_ca_file must be a PEM file of at most 1 MiB",
        ));
    }
    std::fs::read(path).map_err(io_err)
}

impl SmtpEmailTransport {
    /// Builds the transport from `[notify.email]` (requires
    /// `[notify.email.smtp]`). Connections are opened lazily.
    pub fn from_config(email: &EmailConfig, environment: Environment) -> Result<Self, NotifyError> {
        let smtp = email.smtp.as_ref().ok_or_else(|| {
            NotifyError::config("notify.email.smtp is required for transport smtp")
        })?;
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(NotifyError::config(
                "the SMTP transport must be created inside a Tokio runtime",
            ));
        }
        authn_core::tls::install_crypto_provider();
        // Normalised first (NFKC, IDNA/punycode domain), so headers, EHLO
        // and Message-ID stay ASCII.
        let sender = EmailAddress::parse(&email.from_address)
            .map_err(|_| NotifyError::config("notify.email.from_address is not a valid address"))?;
        let from_address = Address::from_str(sender.as_str())
            .map_err(|_| NotifyError::config("notify.email.from_address is not a valid address"))?;
        let from_name = sanitize::header_value(&email.from_name, MAX_NAME_CHARS);
        let message_id_domain = sender.domain().to_owned();
        let from = Mailbox::new(
            Some(from_name).filter(|name| !name.is_empty()),
            from_address,
        );

        let mut tls = TlsParameters::builder(smtp.host.clone());
        if let Some(path) = &smtp.extra_ca_file {
            if !is_development(environment) {
                return Err(NotifyError::config(
                    "notify.email.smtp.extra_ca_file is only allowed in development and test",
                ));
            }
            let pem = read_ca_file(path)?;
            // lettre accepts a PEM file without any certificate (and then
            // trusts nothing extra): refuse it so a wrong path is noticed.
            if !pem
                .windows(CERTIFICATE_MARKER.len())
                .any(|window| window == CERTIFICATE_MARKER)
            {
                return Err(NotifyError::config(
                    "notify.email.smtp.extra_ca_file contains no PEM certificate",
                ));
            }
            let certificate = Certificate::from_pem(&pem).map_err(|_| {
                NotifyError::config("notify.email.smtp.extra_ca_file is not a PEM certificate")
            })?;
            tls = tls.add_root_certificate(certificate);
        }
        let tls = tls
            .build_rustls()
            .map_err(|_| NotifyError::config("SMTP TLS parameters could not be built"))?;
        let mode = match smtp.tls {
            SmtpTls::Starttls => Tls::Required(tls),
            SmtpTls::Tls => Tls::Wrapper(tls),
        };
        let hello = smtp
            .hello_name
            .clone()
            .unwrap_or_else(|| message_id_domain.clone());
        let mut builder =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp.host.clone())
                .port(smtp.port)
                .tls(mode)
                .timeout(Some(smtp.timeout))
                .hello_name(ClientId::Domain(hello));
        if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
            builder = builder.credentials(Credentials::new(
                username.clone(),
                password.expose_secret().to_owned(),
            ));
        }
        Ok(Self {
            transport: Some(builder.build()),
            from,
            message_id_domain,
        })
    }

    /// Builds the MIME message (exposed for tests and previews).
    pub fn build_message(&self, message: &EmailMessage) -> Result<Message, AuthError> {
        let to = Address::from_str(message.to.as_str()).map_err(|_| {
            AuthError::new(codes::notify::DELIVERY_REJECTED)
                .with_context("recipient address not accepted by the MIME builder")
        })?;
        let to_name = message
            .to_name
            .as_deref()
            .map(|name| sanitize::header_value(name, MAX_NAME_CHARS))
            .filter(|name| !name.is_empty());
        let subject = sanitize::header_value(&message.subject, MAX_SUBJECT_CHARS);
        let id = message.outbox_id.map_or_else(
            || uuid::Uuid::now_v7().hyphenated().to_string(),
            |id| id.to_string(),
        );
        let builder = Message::builder()
            .from(self.from.clone())
            .to(Mailbox::new(to_name, to))
            .subject(subject)
            .message_id(Some(format!("<{id}@{}>", self.message_id_domain)))
            .raw_header(HeaderValue::new(
                HeaderName::new_from_ascii_str("Auto-Submitted"),
                "auto-generated".to_owned(),
            ))
            .raw_header(HeaderValue::new(
                HeaderName::new_from_ascii_str("X-Auto-Response-Suppress"),
                "All".to_owned(),
            ));
        let built = match &message.html_body {
            Some(html) => builder.multipart(MultiPart::alternative_plain_html(
                message.text_body.clone(),
                html.clone(),
            )),
            None => builder.singlepart(SinglePart::plain(message.text_body.clone())),
        };
        built.map_err(|_| {
            AuthError::new(codes::notify::DELIVERY_REJECTED)
                .with_context("message could not be built")
        })
    }
}

impl Drop for SmtpEmailTransport {
    fn drop(&mut self) {
        let Some(transport) = self.transport.take() else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            drop(transport);
            return;
        }
        // lettre's pool spawns a shutdown task on drop; without a runtime
        // that would panic. Drop it on a short-lived runtime instead (or, if
        // even that is impossible, leak it: this only happens at exit).
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => {
                let _guard = runtime.enter();
                drop(transport);
            }
            Err(_) => {
                let _ = Box::leak(Box::new(transport));
            }
        }
    }
}

/// Maps a lettre error without its (possibly personal) response text.
fn classify(err: &lettre::transport::smtp::Error) -> AuthError {
    let code = err.status().map(|c| c.to_string());
    if err.is_permanent()
        && !code
            .as_deref()
            .is_some_and(|c| AUTH_FAILURE_CODES.contains(&c))
    {
        tracing::warn!(
            smtp_code = code.as_deref().unwrap_or(""),
            "SMTP server rejected the message"
        );
        return AuthError::new(codes::notify::DELIVERY_REJECTED)
            .with_context("SMTP permanent rejection");
    }
    let context = if err.is_tls() {
        "SMTP TLS failure (no plain-text fallback)"
    } else if err.is_timeout() {
        "SMTP timeout"
    } else if err.is_transient() {
        "SMTP transient failure"
    } else if err.is_permanent() {
        "SMTP authentication failure"
    } else {
        "SMTP connection or protocol failure"
    };
    tracing::warn!(
        smtp_code = code.as_deref().unwrap_or(""),
        reason = context,
        "SMTP delivery failed"
    );
    AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_context(context)
}

#[async_trait]
impl EmailTransport for SmtpEmailTransport {
    async fn send(&self, message: &EmailMessage) -> Result<(), AuthError> {
        let email = self.build_message(message)?;
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| AuthError::internal("SMTP transport already dropped"))?;
        transport
            .send(email)
            .await
            .map(|_| ())
            .map_err(|err| classify(&err))
    }
}
