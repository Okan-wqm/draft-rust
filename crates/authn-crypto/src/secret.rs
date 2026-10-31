//! Secret containers (CRY-13).
//!
//! * [`SecretKey`] — fixed-size key material (32 bytes for every symmetric
//!   key of the system), zeroized on drop, redacted `Debug`, no `Display`,
//!   constant-time `==`.
//! * [`SecretBytes`] — variable-length secret bytes with the same guarantees.
//!
//! `authn_core::secret::{SecretString, SensitiveString}` remain the types for
//! secrets that cross module boundaries as text (passwords, tokens, codes).

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, ct, random};

/// Placeholder printed instead of secret values.
pub use authn_core::secret::REDACTED;

/// Fixed-size secret key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize>([u8; N]);

impl<const N: usize> SecretKey<N> {
    /// Wraps existing key bytes (the caller's copy should be zeroized).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Copies key bytes from a slice of exactly `N` bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; N] = bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(array))
    }

    /// Fresh random key material from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = random::secret_bytes::<N>()?;
        Ok(Self(*bytes))
    }

    /// The key bytes. Call sites should be easy to audit.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> PartialEq for SecretKey<N> {
    fn eq(&self, other: &Self) -> bool {
        ct::eq_array(&self.0, &other.0)
    }
}

impl<const N: usize> Eq for SecretKey<N> {}

impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<{N}>({REDACTED})")
    }
}

/// Variable-length secret bytes.
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes. Call sites should be easy to audit.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes (not secret).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Zeroizing<Vec<u8>>> for SecretBytes {
    fn from(value: Zeroizing<Vec<u8>>) -> Self {
        Self(value)
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        ct::constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({REDACTED})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_13_secret_key_debug_is_redacted() {
        let key = SecretKey::<32>::from_bytes([0xAB; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains(REDACTED));
        assert!(!debug.contains("171"), "{debug}");
        assert!(!debug.to_lowercase().contains("ab"), "{debug}");
        let bytes = SecretBytes::new(vec![0xAB; 8]);
        assert_eq!(format!("{bytes:?}"), format!("SecretBytes({REDACTED})"));
    }

    #[test]
    fn cry_12_secret_key_equality() {
        let a = SecretKey::<32>::generate().unwrap();
        let b = SecretKey::<32>::generate().unwrap();
        assert_eq!(a, a.clone());
        assert_ne!(a, b);
        assert!(SecretKey::<32>::from_slice(&[0; 31]).is_err());
        assert_eq!(
            SecretBytes::new(vec![1, 2]),
            SecretBytes::from(Zeroizing::new(vec![1, 2]))
        );
    }
}
