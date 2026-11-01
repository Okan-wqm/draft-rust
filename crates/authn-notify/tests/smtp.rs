#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! NTF-03: SMTP transport against a local TLS-capable SMTP server.
//!
//! The server below is a minimal, blocking SMTP implementation on a
//! `std::thread` with rustls (test CA in `tests/fixtures`). It records every
//! command together with whether it arrived over TLS, so the tests can prove
//! that nothing — credentials, envelope, message — is ever sent in clear
//! text.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use authn_core::config::Environment;
use authn_core::config::notify::{EmailConfig, EmailTransportKind, SmtpConfig, SmtpTls};
use authn_core::domain::EmailAddress;
use authn_core::error::codes;
use authn_core::id::OutboxMessageId;
use authn_core::ports::{EmailMessage, EmailTransport};
use authn_core::secret::SecretString;
use authn_notify::SmtpEmailTransport;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const CERT: &[u8] = include_bytes!("fixtures/localhost.pem");
const KEY: &[u8] = include_bytes!("fixtures/localhost.key");

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[derive(Clone, Copy)]
struct ServerOptions {
    offer_starttls: bool,
    implicit_tls: bool,
    rcpt_reply: &'static str,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            offer_starttls: true,
            implicit_tls: false,
            rcpt_reply: "250 2.1.5 OK",
        }
    }
}

#[derive(Default)]
struct Captured {
    /// (over TLS?, command line)
    commands: Vec<(bool, String)>,
    /// DATA payloads (always received over TLS in a passing test).
    messages: Vec<(bool, String)>,
}

impl Captured {
    fn commands_starting_with(&self, prefix: &str) -> Vec<(bool, String)> {
        self.commands
            .iter()
            .filter(|(_, c)| c.to_ascii_uppercase().starts_with(prefix))
            .cloned()
            .collect()
    }
}

enum Outcome {
    StartTls,
    Done,
}

fn read_line<S: Read>(stream: &mut S) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    line.truncate(line.len() - 2);
                    return Some(String::from_utf8_lossy(&line).into_owned());
                }
            }
        }
    }
}

fn reply<S: Write>(stream: &mut S, text: &str) {
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.flush();
}

fn session<S: Read + Write>(
    stream: &mut S,
    tls: bool,
    greet: bool,
    options: ServerOptions,
    captured: &Mutex<Captured>,
) -> Outcome {
    if greet {
        reply(stream, "220 localhost ESMTP authn-notify test server\r\n");
    }
    while let Some(line) = read_line(stream) {
        captured.lock().unwrap().commands.push((tls, line.clone()));
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            let mut response = String::from("250-localhost\r\n");
            if !tls && options.offer_starttls {
                response.push_str("250-STARTTLS\r\n");
            }
            if tls {
                response.push_str("250-AUTH PLAIN\r\n");
            }
            response.push_str("250 8BITMIME\r\n");
            reply(stream, &response);
        } else if upper.starts_with("STARTTLS") {
            if !tls && options.offer_starttls {
                reply(stream, "220 2.0.0 Ready to start TLS\r\n");
                return Outcome::StartTls;
            }
            reply(stream, "502 5.5.1 not supported\r\n");
        } else if upper.starts_with("AUTH PLAIN") {
            if upper.trim() == "AUTH PLAIN" {
                reply(stream, "334 \r\n");
                let credentials = read_line(stream).unwrap_or_default();
                captured.lock().unwrap().commands.push((tls, credentials));
            }
            reply(stream, "235 2.7.0 Authentication successful\r\n");
        } else if upper.starts_with("MAIL FROM") {
            reply(stream, "250 2.1.0 OK\r\n");
        } else if upper.starts_with("RCPT TO") {
            reply(stream, &format!("{}\r\n", options.rcpt_reply));
        } else if upper.starts_with("DATA") {
            reply(stream, "354 End data with <CR><LF>.<CR><LF>\r\n");
            let mut data = String::new();
            while let Some(data_line) = read_line(stream) {
                if data_line == "." {
                    break;
                }
                data.push_str(&data_line);
                data.push('\n');
            }
            captured.lock().unwrap().messages.push((tls, data));
            reply(stream, "250 2.0.0 queued\r\n");
        } else if upper.starts_with("QUIT") {
            reply(stream, "221 2.0.0 bye\r\n");
            return Outcome::Done;
        } else if upper.starts_with("RSET") || upper.starts_with("NOOP") {
            reply(stream, "250 2.0.0 OK\r\n");
        } else {
            reply(stream, "500 5.5.2 unrecognized\r\n");
        }
    }
    Outcome::Done
}

fn tls_config() -> Arc<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(CERT)
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    Arc::new(config)
}

fn handle(mut tcp: TcpStream, options: ServerOptions, captured: &Mutex<Captured>) {
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let config = tls_config();
    if options.implicit_tls {
        let connection = rustls::ServerConnection::new(config).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        session(&mut stream, true, true, options, captured);
        return;
    }
    if let Outcome::StartTls = session(&mut tcp, false, true, options, captured) {
        let connection = rustls::ServerConnection::new(config).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        session(&mut stream, true, false, options, captured);
    }
}

fn start_server(options: ServerOptions) -> (u16, Arc<Mutex<Captured>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(Captured::default()));
    let shared = captured.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let shared = shared.clone();
            thread::spawn(move || handle(stream, options, &shared));
        }
    });
    (port, captured)
}

fn email_config(port: u16, tls: SmtpTls, extra_ca: bool) -> EmailConfig {
    EmailConfig {
        transport: EmailTransportKind::Smtp,
        from_address: "no-reply@test.example".to_owned(),
        from_name: "Authn Test".to_owned(),
        smtp: Some(SmtpConfig {
            host: "localhost".to_owned(),
            port,
            tls,
            username: Some("mailer".to_owned()),
            password: Some(SecretString::from("smtp-secret-password".to_owned())),
            timeout: Duration::from_secs(5),
            extra_ca_file: extra_ca.then(|| fixture("test-ca.pem")),
            hello_name: None,
        }),
    }
}

fn message(outbox_id: OutboxMessageId) -> EmailMessage {
    EmailMessage {
        to: EmailAddress::parse("ada@example.com").unwrap(),
        to_name: Some("Ada Lovelace".to_owned()),
        subject: "Reset your password".to_owned(),
        text_body: "Code: 123456\nhttps://auth.test.example/reset-password#token=abc".to_owned(),
        html_body: Some("<p>Code: <b>123456</b></p>".to_owned()),
        outbox_id: Some(outbox_id),
    }
}

#[tokio::test]
async fn ntf_03_smtp_delivers_over_starttls_and_authenticates_only_after_tls() {
    let (port, captured) = start_server(ServerOptions::default());
    let transport = SmtpEmailTransport::from_config(
        &email_config(port, SmtpTls::Starttls, true),
        Environment::Test,
    )
    .unwrap();
    let id = OutboxMessageId::generate();
    transport.send(&message(id)).await.unwrap();

    let captured = captured.lock().unwrap();
    // The only commands in clear text are EHLO and STARTTLS.
    for (tls, command) in &captured.commands {
        if !tls {
            let upper = command.to_ascii_uppercase();
            assert!(
                upper.starts_with("EHLO") || upper.starts_with("STARTTLS"),
                "clear-text command: {command}"
            );
        }
    }
    let auth = captured.commands_starting_with("AUTH");
    assert_eq!(auth.len(), 1);
    assert!(
        auth.iter().all(|(tls, _)| *tls),
        "credentials only over TLS"
    );
    assert!(
        captured
            .commands_starting_with("MAIL FROM")
            .iter()
            .all(|(tls, _)| *tls)
    );
    // EHLO announces the sender domain, never the machine host name.
    for (_, ehlo) in captured.commands_starting_with("EHLO") {
        assert_eq!(ehlo, "EHLO test.example");
    }

    assert_eq!(captured.messages.len(), 1);
    let (over_tls, data) = &captured.messages[0];
    assert!(over_tls);
    assert!(
        data.contains(&format!("Message-ID: <{id}@test.example>")),
        "{data}"
    );
    assert!(data.contains("Subject: Reset your password"));
    assert!(data.contains("Auto-Submitted: auto-generated"));
    assert!(
        data.contains("To: \"Ada Lovelace\" <ada@example.com>"),
        "{data}"
    );
    assert!(
        data.contains("From: \"Authn Test\" <no-reply@test.example>"),
        "{data}"
    );
    assert!(data.contains("multipart/alternative"));
    assert!(data.contains("text/plain") && data.contains("text/html"));
}

#[tokio::test]
async fn ntf_03_smtp_never_falls_back_to_plain_text() {
    let (port, captured) = start_server(ServerOptions {
        offer_starttls: false,
        ..ServerOptions::default()
    });
    let transport = SmtpEmailTransport::from_config(
        &email_config(port, SmtpTls::Starttls, true),
        Environment::Test,
    )
    .unwrap();
    let err = transport
        .send(&message(OutboxMessageId::generate()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE, "retryable");
    let captured = captured.lock().unwrap();
    assert!(captured.commands_starting_with("AUTH").is_empty());
    assert!(captured.commands_starting_with("MAIL").is_empty());
    assert!(captured.messages.is_empty());
}

#[tokio::test]
async fn ntf_03_smtp_rejects_untrusted_server_certificates() {
    let (port, captured) = start_server(ServerOptions::default());
    // No extra CA: the test certificate is not trusted.
    let transport = SmtpEmailTransport::from_config(
        &email_config(port, SmtpTls::Starttls, false),
        Environment::Test,
    )
    .unwrap();
    let err = transport
        .send(&message(OutboxMessageId::generate()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
    let captured = captured.lock().unwrap();
    assert!(
        captured.commands.iter().all(|(tls, _)| !tls),
        "handshake failed"
    );
    assert!(captured.commands_starting_with("AUTH").is_empty());
    assert!(captured.messages.is_empty());
}

#[tokio::test]
async fn ntf_03_smtp_supports_implicit_tls() {
    let (port, captured) = start_server(ServerOptions {
        implicit_tls: true,
        ..ServerOptions::default()
    });
    let transport =
        SmtpEmailTransport::from_config(&email_config(port, SmtpTls::Tls, true), Environment::Test)
            .unwrap();
    transport
        .send(&message(OutboxMessageId::generate()))
        .await
        .unwrap();
    let captured = captured.lock().unwrap();
    assert!(captured.commands.iter().all(|(tls, _)| *tls));
    assert_eq!(captured.messages.len(), 1);
}

#[tokio::test]
async fn ntf_03_smtp_permanent_rejection_is_not_retried() {
    let (port, _captured) = start_server(ServerOptions {
        rcpt_reply: "550 5.1.1 <ada@example.com>: Recipient address rejected",
        ..ServerOptions::default()
    });
    let transport = SmtpEmailTransport::from_config(
        &email_config(port, SmtpTls::Starttls, true),
        Environment::Test,
    )
    .unwrap();
    let err = transport
        .send(&message(OutboxMessageId::generate()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::notify::DELIVERY_REJECTED);
    // The server's response (which echoes the address) is not kept.
    let debug = format!("{err:?}");
    assert!(!debug.contains("ada@example.com"), "{debug}");
}

#[tokio::test]
async fn ntf_03_smtp_transient_rejection_is_retried() {
    let (port, _captured) = start_server(ServerOptions {
        rcpt_reply: "451 4.3.0 Mailbox temporarily unavailable",
        ..ServerOptions::default()
    });
    let transport = SmtpEmailTransport::from_config(
        &email_config(port, SmtpTls::Starttls, true),
        Environment::Test,
    )
    .unwrap();
    let err = transport
        .send(&message(OutboxMessageId::generate()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn ntf_03_extra_ca_certificate_is_development_only() {
    for environment in [Environment::Production, Environment::Staging] {
        let err = SmtpEmailTransport::from_config(
            &email_config(25, SmtpTls::Starttls, true),
            environment,
        )
        .unwrap_err();
        assert!(err.to_string().contains("extra_ca_file"), "{err}");
    }
    // Without the extra CA, production is fine (platform trust store).
    SmtpEmailTransport::from_config(
        &email_config(25, SmtpTls::Starttls, false),
        Environment::Production,
    )
    .unwrap();
    // A file that is not a certificate is refused at startup.
    let mut config = email_config(25, SmtpTls::Starttls, true);
    config.smtp.as_mut().unwrap().extra_ca_file = Some(fixture("README.md"));
    assert!(SmtpEmailTransport::from_config(&config, Environment::Development).is_err());
}

#[tokio::test]
async fn ntf_03_headers_cannot_be_injected_through_subject_or_name() {
    let transport = SmtpEmailTransport::from_config(
        &email_config(25, SmtpTls::Starttls, false),
        Environment::Test,
    )
    .unwrap();
    let mut msg = message(OutboxMessageId::generate());
    msg.subject = "Hello\r\nBcc: victim@example.com\r\n\r\nInjected body".to_owned();
    msg.to_name = Some("Ada\r\nCc: other@example.com".to_owned());
    let formatted = String::from_utf8(transport.build_message(&msg).unwrap().formatted()).unwrap();
    let headers = formatted.split("\r\n\r\n").next().unwrap();
    for line in headers.split("\r\n") {
        assert!(!line.starts_with("Bcc:"), "{line}");
        assert!(!line.starts_with("Cc:"), "{line}");
    }
    assert!(
        headers.contains("Subject: Hello Bcc: victim@example.com Injected body"),
        "{headers}"
    );
    // Without an outbox id a random Message-ID on the sender domain is used
    // (never the machine host name).
    msg.outbox_id = None;
    let formatted = String::from_utf8(transport.build_message(&msg).unwrap().formatted()).unwrap();
    let message_id = formatted
        .split("\r\n")
        .find(|l| l.starts_with("Message-ID:"))
        .unwrap();
    assert!(message_id.ends_with("@test.example>"), "{message_id}");
}

#[test]
fn ntf_03_smtp_transport_needs_a_runtime_but_never_panics() {
    // Outside a runtime: a clean error, not a panic in lettre's pool.
    let err = SmtpEmailTransport::from_config(
        &email_config(25, SmtpTls::Starttls, false),
        Environment::Test,
    )
    .unwrap_err();
    assert!(err.to_string().contains("Tokio runtime"), "{err}");
    // Built inside a runtime, dropped after it is gone: no panic.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let transport = runtime
        .block_on(async {
            SmtpEmailTransport::from_config(
                &email_config(25, SmtpTls::Starttls, false),
                Environment::Test,
            )
        })
        .unwrap();
    drop(runtime);
    drop(transport);
}
