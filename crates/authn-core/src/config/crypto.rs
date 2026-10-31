//! `[crypto]` — key material and cryptographic parameters (owner:
//! authn-crypto). CRY-01, CRY-02, CRY-08, CRY-09, CRY-10, CRY-11, ARC-12.

use std::collections::HashSet;
use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, VersionedKey, days, hours, mins, secs};
use crate::secret::SecretString;

/// Argon2id parameters (CRY-01). Defaults: OWASP m=19456 KiB, t=2, p=1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Argon2Config {
    /// Memory cost in KiB. Default 19456.
    pub memory_kib: u32,
    /// Iterations. Default 2.
    pub iterations: u32,
    /// Lanes. Default 1.
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// A key-encryption key (CRY-08).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KekConfig {
    /// Identifier embedded in every envelope (`key_id`).
    pub id: String,
    /// Base64 of exactly 32 random bytes.
    pub key: SecretString,
}

impl std::fmt::Debug for KekConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KekConfig")
            .field("id", &self.id)
            .field("key", &crate::secret::REDACTED)
            .finish()
    }
}

/// JWT signing-key lifecycle (CRY-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SigningKeyConfig {
    /// `Cache-Control: max-age` of the JWKS (SES-09). Default `1h`.
    #[serde(with = "super::duration")]
    pub jwks_cache_ttl: Duration,
    /// How long a new key is published as `pending` before activation; must
    /// be ≥ `jwks_cache_ttl`. Default `2h`.
    #[serde(with = "super::duration")]
    pub pending_period: Duration,
    /// Automatic rotation interval. Default `30d`.
    #[serde(with = "super::duration")]
    pub rotation_interval: Duration,
    /// How long a retired key stays in the JWKS; must be ≥ the longest token
    /// lifetime. Default `1d`.
    #[serde(with = "super::duration")]
    pub retired_retention: Duration,
}

impl Default for SigningKeyConfig {
    fn default() -> Self {
        Self {
            jwks_cache_ttl: hours(1),
            pending_period: hours(2),
            rotation_interval: days(30),
            retired_retention: days(1),
        }
    }
}

/// `[crypto]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    /// Argon2id parameters.
    #[serde(default)]
    pub argon2: Argon2Config,
    /// **Required.** Pepper keys (CRY-02), several versions may be active.
    pub peppers: Vec<VersionedKey>,
    /// **Required.** Version used for new hashes.
    pub current_pepper_version: u32,
    /// **Required.** Key-encryption keys (CRY-08).
    pub keks: Vec<KekConfig>,
    /// **Required.** KEK id used for new envelopes.
    pub current_kek_id: String,
    /// **Required.** Root key for HKDF purpose sub-keys (CRY-11): OTP
    /// hashes, CSRF tokens, trusted-device tokens, PoW challenges…
    pub hmac_root_key: SecretString,
    /// JWT clock-skew tolerance (CRY-09). Default `30s`.
    #[serde(default = "default_leeway", with = "super::duration")]
    pub jwt_leeway: Duration,
    /// Signing-key lifecycle.
    #[serde(default)]
    pub signing_keys: SigningKeyConfig,
    /// Concurrent Argon2 computations (ARC-12 semaphore). Default 4.
    #[serde(default = "default_hash_concurrency")]
    pub max_concurrent_hashes: u32,
}

const fn default_leeway() -> Duration {
    secs(30)
}

const fn default_hash_concurrency() -> u32 {
    4
}

impl CryptoConfig {
    /// Validates the section. Messages never include key material.
    pub fn validate(&self, p: &mut ConfigProblems) {
        let a = &self.argon2;
        p.require(
            (7_168..=4_194_304).contains(&a.memory_kib),
            "crypto.argon2.memory_kib",
            "must be between 7168 and 4194304 (OWASP minimum 7 MiB)",
        );
        p.require(
            (1..=16).contains(&a.iterations),
            "crypto.argon2.iterations",
            "must be between 1 and 16",
        );
        p.require(
            (1..=16).contains(&a.parallelism),
            "crypto.argon2.parallelism",
            "must be between 1 and 16",
        );

        p.require(
            !self.peppers.is_empty(),
            "crypto.peppers",
            "at least one pepper is required (CRY-02)",
        );
        let mut versions = HashSet::new();
        for (i, pepper) in self.peppers.iter().enumerate() {
            let key = format!("crypto.peppers[{i}]");
            p.require(pepper.version >= 1, &key, "version must be >= 1");
            p.require(versions.insert(pepper.version), &key, "duplicate version");
            p.require_key(&pepper.key, &format!("{key}.key"));
        }
        p.require(
            versions.contains(&self.current_pepper_version),
            "crypto.current_pepper_version",
            "must reference a configured pepper",
        );

        p.require(
            !self.keks.is_empty(),
            "crypto.keks",
            "at least one KEK is required (CRY-08)",
        );
        let mut ids = HashSet::new();
        for (i, kek) in self.keks.iter().enumerate() {
            let key = format!("crypto.keks[{i}]");
            p.require(
                !kek.id.is_empty()
                    && kek.id.len() <= 32
                    && kek
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                &key,
                "id must be 1-32 characters of [A-Za-z0-9_-]",
            );
            p.require(ids.insert(kek.id.as_str()), &key, "duplicate id");
            let exact = super::common::decode_key_material(&kek.key).is_some_and(|k| k.len() == 32);
            p.require(
                exact,
                &format!("{key}.key"),
                "must be base64 of exactly 32 random bytes",
            );
        }
        p.require(
            ids.contains(self.current_kek_id.as_str()),
            "crypto.current_kek_id",
            "must reference a configured KEK",
        );
        p.require_key(&self.hmac_root_key, "crypto.hmac_root_key");
        p.require_range(
            self.jwt_leeway,
            Duration::ZERO,
            mins(5),
            "crypto.jwt_leeway",
        );
        p.require(
            (1..=256).contains(&self.max_concurrent_hashes),
            "crypto.max_concurrent_hashes",
            "must be between 1 and 256",
        );
        let s = &self.signing_keys;
        p.require(
            s.pending_period >= s.jwks_cache_ttl,
            "crypto.signing_keys.pending_period",
            "must be at least jwks_cache_ttl (CRY-10)",
        );
        p.require_range(
            s.jwks_cache_ttl,
            mins(1),
            days(1),
            "crypto.signing_keys.jwks_cache_ttl",
        );
        p.require_range(
            s.rotation_interval,
            days(1),
            days(365),
            "crypto.signing_keys.rotation_interval",
        );
        // Bounded so the JWKS stays small and a typo cannot keep a key
        // published (or unusable) for years.
        p.require_range(
            s.pending_period,
            mins(1),
            days(30),
            "crypto.signing_keys.pending_period",
        );
        p.require_range(
            s.retired_retention,
            mins(1),
            days(90),
            "crypto.signing_keys.retired_retention",
        );
        p.require(
            s.pending_period < s.rotation_interval,
            "crypto.signing_keys.pending_period",
            "must be shorter than rotation_interval (CRY-10)",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> CryptoConfig {
        let key = |s: &str| SecretString::from(s.to_owned());
        CryptoConfig {
            argon2: Argon2Config::default(),
            peppers: vec![VersionedKey {
                version: 1,
                key: key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
            }],
            current_pepper_version: 1,
            keks: vec![KekConfig {
                id: "k1".to_owned(),
                key: key("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="),
            }],
            current_kek_id: "k1".to_owned(),
            hmac_root_key: key("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
            jwt_leeway: default_leeway(),
            signing_keys: SigningKeyConfig::default(),
            max_concurrent_hashes: default_hash_concurrency(),
        }
    }

    fn problems(config: &CryptoConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    #[test]
    fn cry_01_defaults_are_valid() {
        assert!(problems(&valid()).is_empty(), "{:?}", problems(&valid()));
        assert_eq!(Argon2Config::default().memory_kib, 19_456);
        assert_eq!(valid().jwt_leeway, secs(30));
    }

    #[test]
    fn cry_10_signing_key_periods_are_bounded() {
        let mut c = valid();
        c.signing_keys.pending_period = days(31);
        assert!(
            problems(&c)
                .iter()
                .any(|p| p.starts_with("crypto.signing_keys.pending_period"))
        );
        let mut c = valid();
        c.signing_keys.retired_retention = days(91);
        assert!(
            problems(&c)
                .iter()
                .any(|p| p.starts_with("crypto.signing_keys.retired_retention"))
        );
        let mut c = valid();
        c.signing_keys.jwks_cache_ttl = hours(3);
        assert!(
            problems(&c)
                .iter()
                .any(|p| p.starts_with("crypto.signing_keys.pending_period"))
        );
        let mut c = valid();
        c.signing_keys.rotation_interval = days(1);
        c.signing_keys.pending_period = days(2);
        assert!(
            problems(&c)
                .iter()
                .any(|p| p.contains("shorter than rotation_interval"))
        );
    }

    #[test]
    fn cry_08_kek_rules_never_echo_key_material() {
        let mut c = valid();
        c.keks[0].key = SecretString::from("c2hvcnQ=".to_owned());
        c.keks.push(c.keks[0].clone());
        c.current_kek_id = "missing".to_owned();
        let found = problems(&c);
        assert!(found.iter().any(|p| p.contains("exactly 32")));
        assert!(found.iter().any(|p| p.contains("duplicate id")));
        assert!(found.iter().any(|p| p.starts_with("crypto.current_kek_id")));
        assert!(found.iter().all(|p| !p.contains("c2hvcnQ")));
    }
}
