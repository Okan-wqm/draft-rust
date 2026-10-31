//! Shared configuration building blocks (owner: authn-core).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::secret::{ExposeSecret, SecretString};

text_enum! {
    /// Deployment environment. Defaults to `production`, the strictest mode:
    /// forgetting to set it can only make validation stricter.
    #[derive(Default)]
    pub enum Environment {
        /// Production: all safety checks enforced.
        #[default]
        Production => "production",
        /// Staging: production rules, separate data.
        Staging => "staging",
        /// Local development (log e-mail transport, http localhost allowed).
        Development => "development",
        /// Automated tests.
        Test => "test",
    }
}

text_enum! {
    /// When a CAPTCHA is demanded (PRT-05, ACC-13).
    #[derive(Default)]
    pub enum CaptchaPolicy {
        /// Always required.
        Always => "always",
        /// Required when risk / failure counters say so.
        #[default]
        RiskBased => "risk_based",
        /// Never required.
        Never => "never",
    }
}

/// A versioned secret key (peppers, KEKs). The key is base64 (standard or
/// URL-safe, padding optional) and must decode to at least 32 bytes.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedKey {
    /// Key version (≥ 1), stored next to everything protected by the key.
    pub version: u32,
    /// Base64 key material.
    pub key: SecretString,
}

impl fmt::Debug for VersionedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionedKey")
            .field("version", &self.version)
            .field("key", &crate::secret::REDACTED)
            .finish()
    }
}

/// Decodes base64 key material (standard or URL-safe alphabet, with or
/// without padding) into a zeroizing buffer.
#[must_use]
pub fn decode_key_material(secret: &SecretString) -> Option<Zeroizing<Vec<u8>>> {
    let text = secret.expose_secret().trim();
    [&STANDARD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(text).ok())
        .or_else(|| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(text)
                .ok()
        })
        .map(Zeroizing::new)
}

/// Duration helpers for readable defaults.
#[must_use]
pub const fn secs(n: u64) -> std::time::Duration {
    std::time::Duration::from_secs(n)
}

/// `n` minutes.
#[must_use]
pub const fn mins(n: u64) -> std::time::Duration {
    std::time::Duration::from_secs(n * 60)
}

/// `n` hours.
#[must_use]
pub const fn hours(n: u64) -> std::time::Duration {
    std::time::Duration::from_secs(n * 3600)
}

/// `n` days.
#[must_use]
pub const fn days(n: u64) -> std::time::Duration {
    std::time::Duration::from_secs(n * 86_400)
}

/// Minimum key length in bytes for every symmetric secret.
pub const MIN_KEY_BYTES: usize = 32;

/// Collects configuration problems. Messages name the key and the rule,
/// never the value.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigProblems(Vec<String>);

impl ConfigProblems {
    /// Records `message` for `key` unless `ok`.
    pub fn require(&mut self, ok: bool, key: &str, message: &str) {
        if !ok {
            self.0.push(format!("{key}: {message}"));
        }
    }

    /// Records a problem unconditionally.
    pub fn push(&mut self, key: &str, message: &str) {
        self.0.push(format!("{key}: {message}"));
    }

    /// Checks that a secret decodes to at least [`MIN_KEY_BYTES`].
    pub fn require_key(&mut self, secret: &SecretString, key: &str) {
        let ok = decode_key_material(secret).is_some_and(|k| k.len() >= MIN_KEY_BYTES);
        self.require(ok, key, "must be base64 of at least 32 random bytes");
    }

    /// Checks `low <= value <= high` for durations.
    pub fn require_range(
        &mut self,
        value: std::time::Duration,
        low: std::time::Duration,
        high: std::time::Duration,
        key: &str,
    ) {
        if value < low || value > high {
            self.0.push(format!(
                "{key}: must be between {} and {}",
                super::duration::format(low),
                super::duration::format(high)
            ));
        }
    }

    /// Whether no problem was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The recorded problems.
    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.0
    }

    /// `Ok(())` or [`ConfigError::Invalid`].
    pub fn into_result(self) -> Result<(), ConfigError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(self.0))
        }
    }
}

/// Configuration loading / validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// Sources could not be read or deserialized.
    #[error("failed to load configuration: {0}")]
    Load(String),
    /// Values violate the rules.
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

impl ConfigError {
    /// Converts a figment error without echoing offending values (which
    /// could be secrets put under the wrong key).
    #[must_use]
    pub fn from_figment(err: &figment::Error) -> Self {
        use figment::error::Kind;
        let mut messages = Vec::new();
        for e in err.clone() {
            let path = if e.path.is_empty() {
                "<root>".to_owned()
            } else {
                e.path.join(".")
            };
            let what = match &e.kind {
                Kind::Message(m) => m.clone(),
                Kind::InvalidType(_, expected) | Kind::InvalidValue(_, expected) => {
                    format!("invalid value (expected {expected})")
                }
                Kind::InvalidLength(_, expected) => format!("invalid length (expected {expected})"),
                Kind::UnknownVariant(_, expected) => {
                    format!("unknown variant (expected one of {})", expected.join(", "))
                }
                Kind::UnknownField(field, _) => format!("unknown field `{field}`"),
                Kind::MissingField(field) => format!("missing field `{field}`"),
                Kind::DuplicateField(field) => format!("duplicate field `{field}`"),
                Kind::ISizeOutOfRange(_) | Kind::USizeOutOfRange(_) => {
                    "number out of range".to_owned()
                }
                Kind::Unsupported(_) | Kind::UnsupportedKey(_, _) => "unsupported value".to_owned(),
            };
            let source = e
                .metadata
                .as_ref()
                .map(|m| format!(" (from {})", m.name))
                .unwrap_or_default();
            messages.push(format!("{path}: {what}{source}"));
        }
        Self::Load(messages.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_08_key_material_decoding_accepts_common_base64_forms() {
        let raw = [7_u8; 32];
        for encoded in [
            STANDARD.encode(raw),
            URL_SAFE.encode(raw),
            URL_SAFE_NO_PAD.encode(raw),
        ] {
            let secret = SecretString::from(encoded);
            assert_eq!(decode_key_material(&secret).unwrap().as_slice(), &raw);
        }
        assert!(decode_key_material(&SecretString::from("not base64!".to_owned())).is_none());
    }

    #[test]
    fn arc_07_short_keys_are_rejected() {
        let mut p = ConfigProblems::default();
        p.require_key(&SecretString::from(STANDARD.encode([1_u8; 16])), "k");
        assert_eq!(p.problems().len(), 1);
        let mut p = ConfigProblems::default();
        p.require_key(&SecretString::from(STANDARD.encode([1_u8; 32])), "k");
        assert!(p.is_empty());
    }

    #[test]
    fn environment_defaults_to_production() {
        assert_eq!(Environment::default(), Environment::Production);
    }
}
