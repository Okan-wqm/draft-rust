//! Errors of the cryptographic layer.
//!
//! Messages are static and never contain key material, plaintext, tokens or
//! hashes. They are meant for logs; clients only ever see the generic code
//! produced by the `AuthError` conversion.

use authn_core::error::{AuthError, codes};

/// A cryptographic operation failed.
///
/// Variants are deliberately coarse: distinguishing *why* a ciphertext or a
/// signature is invalid would hand an attacker an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The operating-system CSPRNG failed.
    #[error("random number generator failure")]
    Rng,
    /// Key material is missing, has the wrong length or is not valid base64.
    #[error("invalid key material")]
    InvalidKey,
    /// The referenced key id is not configured (or no longer configured).
    #[error("unknown key id")]
    UnknownKey,
    /// Input (envelope, token, hash string…) does not have the expected
    /// format.
    #[error("malformed input")]
    Malformed,
    /// Authenticated decryption failed: wrong key, wrong AAD or tampering.
    #[error("authentication failed")]
    Unauthentic,
    /// Algorithm, version or parameter is not supported / outside the
    /// accepted bounds.
    #[error("unsupported algorithm, version or parameters")]
    Unsupported,
    /// Input exceeds a hard size limit.
    #[error("input too large")]
    TooLarge,
    /// The blocking worker pool for heavy hashing is unavailable (runtime
    /// shutting down).
    #[error("hashing worker unavailable")]
    WorkerUnavailable,
    /// An invariant of a third-party primitive was violated (should not
    /// happen; logged as an internal error).
    #[error("internal cryptographic error: {0}")]
    Internal(&'static str),
}

impl From<CryptoError> for AuthError {
    fn from(err: CryptoError) -> Self {
        let code = match err {
            CryptoError::WorkerUnavailable => codes::common::SERVICE_UNAVAILABLE,
            _ => codes::common::INTERNAL_ERROR,
        };
        AuthError::new(code).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_13_errors_map_to_generic_codes() {
        assert_eq!(
            AuthError::from(CryptoError::Unauthentic).code(),
            codes::common::INTERNAL_ERROR
        );
        assert_eq!(
            AuthError::from(CryptoError::WorkerUnavailable).code(),
            codes::common::SERVICE_UNAVAILABLE
        );
    }
}
