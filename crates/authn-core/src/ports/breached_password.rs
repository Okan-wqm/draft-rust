//! Breached-password lookup (PWD-03). Owner of this file: authn-password.
//!
//! The HIBP implementation sends only the first 5 hex characters of the
//! SHA-1 hash (k-anonymity) with `Add-Padding: true`; optionally an offline
//! list is consulted. When the service is unreachable the result is
//! [`BreachStatus::Unknown`] and the configured fail mode applies.

use async_trait::async_trait;

use crate::error::AuthError;
use crate::secret::SecretString;

/// Checks whether a password appears in known breaches.
#[async_trait]
pub trait BreachedPasswordChecker: Send + Sync {
    /// Looks the (NFKC-normalized) password up.
    async fn check(&self, password: &SecretString) -> Result<BreachStatus, AuthError>;
}

/// Result of a breach lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachStatus {
    /// Found in breach corpora.
    Breached {
        /// Number of occurrences reported.
        occurrences: u64,
    },
    /// Not found.
    NotFound,
    /// The lookup could not be performed.
    Unknown,
}
