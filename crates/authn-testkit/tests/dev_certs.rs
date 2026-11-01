//! The fixed docker-compose Mailpit development certificate
//! (`config/dev-certs`, NTF-03, OPS-08) is usable by the SMTP transport's
//! verifier for `localhost` only, matches its key, and is wired into
//! `docker-compose.yml` and `config/example.toml`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn dev_cert() -> CertificateDer<'static> {
    CertificateDer::from_pem_file(repo_file("config/dev-certs/mailpit.pem")).unwrap()
}

/// Verification happens at fixed instants, never the wall clock (TST-08).
fn at(unix_seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(unix_seconds))
}
/// 2027-01-01T00:00:00Z.
const Y2027: u64 = 1_798_761_600;
/// 2045-01-01T00:00:00Z.
const Y2045: u64 = 2_366_841_600;

/// The same verifier lettre builds for `extra_ca_file`: webpki with the dev
/// certificate as the only trust anchor (ring provider).
fn verifier() -> Arc<WebPkiServerVerifier> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(dev_cert()).unwrap();
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap()
}

fn verify(name: &str, now: UnixTime) -> Result<(), rustls::Error> {
    verifier()
        .verify_server_cert(
            &dev_cert(),
            &[],
            &ServerName::try_from(name.to_owned()).unwrap(),
            &[],
            now,
        )
        .map(|_| ())
}

#[test]
fn ntf_03_mailpit_dev_certificate_verifies_for_localhost_only() {
    for name in ["localhost", "127.0.0.1", "::1"] {
        verify(name, at(Y2027)).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    // Still valid for many years, so nobody is tempted to disable checks.
    verify("localhost", at(Y2045)).unwrap();
    // Never valid for a real host name: trusting it cannot vouch for a
    // production SMTP relay.
    for name in ["smtp.example.com", "mail.localhost.example", "10.0.0.1"] {
        assert!(verify(name, at(Y2027)).is_err(), "{name} must not verify");
    }
}

#[test]
fn ntf_03_mailpit_dev_key_matches_the_certificate() {
    let key = PrivateKeyDer::from_pem_file(repo_file("config/dev-certs/mailpit.key")).unwrap();
    let signer = rustls::crypto::ring::sign::any_ecdsa_type(&key).unwrap();
    CertifiedKey::new(vec![dev_cert()], signer)
        .keys_match()
        .unwrap();
}

#[test]
fn ops_08_dev_certificate_is_wired_into_compose_and_the_example_config() {
    let compose = std::fs::read_to_string(repo_file("docker-compose.yml")).unwrap();
    for needle in [
        "MP_SMTP_TLS_CERT: /certs/mailpit.pem",
        "MP_SMTP_TLS_KEY: /certs/mailpit.key",
        "MP_SMTP_REQUIRE_STARTTLS: \"true\"",
        "./config/dev-certs:/certs:ro",
    ] {
        assert!(
            compose.contains(needle),
            "docker-compose.yml lacks {needle}"
        );
    }
    assert!(
        !compose.contains("sans:localhost"),
        "random per-start certificates cannot be trusted"
    );
    let example = std::fs::read_to_string(repo_file("config/example.toml")).unwrap();
    // Documented as a commented line (authn-notify requires optional
    // `[notify]` keys in that form); developers uncomment it locally.
    assert!(example.contains("# extra_ca_file = \"config/dev-certs/mailpit.pem\""));
    assert!(example.contains("environment = \"development\""));
}
