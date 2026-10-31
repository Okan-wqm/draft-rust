//! Secret-handling helpers (CRY-12, CRY-13).
//!
//! * [`SecretString`] (re-exported from `secrecy`) is the type for secrets
//!   that are only ever *read* (configuration keys, passwords in requests).
//! * [`SensitiveString`] is for short-lived secrets that must travel through a
//!   serialization boundary on purpose — e.g. a magic-link URL or an OTP code
//!   inside a [`crate::ports::Notification`] that is sealed into the outbox.
//!   Its `Debug`/`Display` are redacted and its buffer is zeroized on drop.
//! * [`constant_time_eq`] compares secrets without early exit.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use secrecy::{ExposeSecret, SecretBox, SecretString};

/// Placeholder printed instead of secret values.
pub const REDACTED: &str = "[REDACTED]";

/// A string that is secret but must be serialized deliberately (for example
/// into an encrypted outbox payload).
///
/// * `Debug` and `Display` print `[REDACTED]`.
/// * `==` is constant-time in the content.
/// * The heap buffer is zeroized when the value is dropped.
/// * `Serialize` writes the clear text: only serialize it into storage that is
///   sealed with envelope encryption (`authn-crypto`), never into logs, audit
///   events or HTTP responses unless that is the explicit purpose.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveString(String);

/// Equality is constant-time in the content (CRY-12); only the length can
/// influence timing.
impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for SensitiveString {}

impl SensitiveString {
    /// Wraps a secret value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the clear text. Call sites should be easy to audit.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes of the secret (does not reveal content).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for SensitiveString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

impl From<String> for SensitiveString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Constant-time equality for secret byte strings (CRY-12).
///
/// Returns `false` immediately when the lengths differ: the length of a token
/// or hash is not secret in this system (all are fixed length).
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_13_sensitive_string_is_redacted_in_debug_and_display() {
        let s = SensitiveString::new("123456");
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{s}"), REDACTED);
        assert_eq!(s.expose(), "123456");
    }

    #[test]
    fn cry_13_sensitive_string_serializes_clear_text_on_purpose() {
        let s = SensitiveString::new("abc");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"abc\"");
        let back: SensitiveString = serde_json::from_str("\"abc\"").unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn cry_12_sensitive_string_equality() {
        assert_eq!(SensitiveString::new("abc"), SensitiveString::new("abc"));
        assert_ne!(SensitiveString::new("abc"), SensitiveString::new("abd"));
        assert_ne!(SensitiveString::new("abc"), SensitiveString::new("ab"));
    }

    #[test]
    fn cry_12_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
