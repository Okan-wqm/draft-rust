//! Process-wide TLS crypto provider.
//!
//! The workspace uses rustls with the `ring` provider only (no aws-lc /
//! OpenSSL). `reqwest` is built with `rustls-no-provider` and **panics** when
//! a client is built before a provider is installed, so every constructor
//! that builds a `reqwest::Client` (and `main`) calls
//! [`install_crypto_provider`] first. The call is idempotent and cheap.

use std::sync::Once;

/// Installs `rustls::crypto::ring` as the process default provider (once).
pub fn install_crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // An `Err` means another provider was installed first; that is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_provider_is_installed_idempotently() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
