//! Argon2id with PHC strings (CRY-01).
//!
//! Only one PHC shape is produced and accepted:
//!
//! ```text
//! $argon2id$v=19$m=<KiB>,t=<iterations>,p=<lanes>$<salt>$<hash>
//! ```
//!
//! with PHC "B64" (standard alphabet, no padding, canonical) salt and hash.
//! The parser is hand-written and strict on purpose: no `keyid`/`data`
//! parameters, no other variants or versions, no leading zeros, bounded
//! parameters (a planted `m=4194304,t=4294967295` hash cannot turn a login
//! into a denial of service), bounded total length. It is fuzzed
//! (`fuzz/fuzz_targets/password_hash_parse.rs`).

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use zeroize::Zeroizing;

use crate::{CryptoError, ct};

/// Output length of hashes produced by this crate.
pub const OUTPUT_LEN: usize = 32;
/// Salt length of hashes produced by this crate.
pub const SALT_LEN: usize = 16;

/// Bounds accepted when *verifying* a stored hash (mirrors the
/// `crypto.argon2` validation ranges).
pub const MIN_MEMORY_KIB: u32 = 7_168;
/// Upper memory bound (4 GiB).
pub const MAX_MEMORY_KIB: u32 = 4_194_304;
/// Upper iteration bound.
pub const MAX_ITERATIONS: u32 = 16;
/// Upper lane bound.
pub const MAX_PARALLELISM: u32 = 16;

const MIN_SALT: usize = 8;
const MAX_SALT: usize = 48;
const MIN_OUTPUT: usize = 16;
const MAX_OUTPUT: usize = 64;
const MAX_PHC_LEN: usize = 256;
const PREFIX: &str = "$argon2id$v=19$";

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Settings {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Iterations.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl Argon2Settings {
    /// OWASP defaults (CRY-01): m=19456, t=2, p=1.
    pub const DEFAULT: Self = Self {
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    };

    /// Validates the bounds.
    pub fn validate(self) -> Result<Self, CryptoError> {
        let ok = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (1..=MAX_ITERATIONS).contains(&self.iterations)
            && (1..=MAX_PARALLELISM).contains(&self.parallelism)
            // Argon2 needs at least 8 blocks per lane.
            && self.memory_kib >= 8 * self.parallelism;
        if ok {
            Ok(self)
        } else {
            Err(CryptoError::Unsupported)
        }
    }

    fn params(self, output_len: usize) -> Result<Params, CryptoError> {
        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(output_len),
        )
        .map_err(|_| CryptoError::Unsupported)
    }
}

impl Default for Argon2Settings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl From<authn_core::config::crypto::Argon2Config> for Argon2Settings {
    fn from(c: authn_core::config::crypto::Argon2Config) -> Self {
        Self {
            memory_kib: c.memory_kib,
            iterations: c.iterations,
            parallelism: c.parallelism,
        }
    }
}

/// A parsed `$argon2id$` PHC string.
#[derive(Clone, PartialEq, Eq)]
pub struct Argon2Phc {
    settings: Argon2Settings,
    salt: Vec<u8>,
    output: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Argon2Phc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Argon2Phc")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Argon2Phc {
    /// Strictly parses a PHC string.
    pub fn parse(phc: &str) -> Result<Self, CryptoError> {
        if phc.len() > MAX_PHC_LEN {
            return Err(CryptoError::TooLarge);
        }
        let rest = phc.strip_prefix(PREFIX).ok_or(CryptoError::Unsupported)?;
        let mut fields = rest.split('$');
        let (Some(params), Some(salt), Some(output), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(CryptoError::Malformed);
        };

        let mut values = params.split(',');
        let (Some(m), Some(t), Some(p), None) =
            (values.next(), values.next(), values.next(), values.next())
        else {
            return Err(CryptoError::Malformed);
        };
        let settings = Argon2Settings {
            memory_kib: decimal(m.strip_prefix("m=").ok_or(CryptoError::Malformed)?)?,
            iterations: decimal(t.strip_prefix("t=").ok_or(CryptoError::Malformed)?)?,
            parallelism: decimal(p.strip_prefix("p=").ok_or(CryptoError::Malformed)?)?,
        }
        .validate()?;

        let salt = STANDARD_NO_PAD
            .decode(salt)
            .map_err(|_| CryptoError::Malformed)?;
        let output = Zeroizing::new(
            STANDARD_NO_PAD
                .decode(output)
                .map_err(|_| CryptoError::Malformed)?,
        );
        if !(MIN_SALT..=MAX_SALT).contains(&salt.len())
            || !(MIN_OUTPUT..=MAX_OUTPUT).contains(&output.len())
        {
            return Err(CryptoError::Malformed);
        }
        Ok(Self {
            settings,
            salt,
            output,
        })
    }

    /// The cost parameters of the stored hash.
    #[must_use]
    pub const fn settings(&self) -> Argon2Settings {
        self.settings
    }

    /// Whether this hash has exactly the shape new hashes get with
    /// `current` (parameters, salt and output length).
    #[must_use]
    pub fn is_current(&self, current: Argon2Settings) -> bool {
        self.settings == current && self.salt.len() == SALT_LEN && self.output.len() == OUTPUT_LEN
    }

    /// Recomputes Argon2id over `input` with the stored salt/parameters and
    /// compares the outputs in constant time.
    pub fn verify(&self, input: &[u8]) -> Result<bool, CryptoError> {
        let params = self.settings.params(self.output.len())?;
        let mut computed = Zeroizing::new(vec![0_u8; self.output.len()]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(input, &self.salt, &mut computed)
            .map_err(|_| CryptoError::Internal("argon2 verification failed"))?;
        Ok(ct::constant_time_eq(&computed, &self.output))
    }
}

/// Hashes `input` with a fresh random salt and returns the PHC string.
pub(crate) fn hash(settings: Argon2Settings, input: &[u8]) -> Result<String, CryptoError> {
    let salt = crate::random::bytes::<SALT_LEN>()?;
    hash_with_salt(settings, input, &salt)
}

/// Hashes `input` with the given salt (8..=48 bytes). Crate-private: a
/// caller-chosen salt is only legitimate for known-answer tests.
pub(crate) fn hash_with_salt(
    settings: Argon2Settings,
    input: &[u8],
    salt: &[u8],
) -> Result<String, CryptoError> {
    let settings = settings.validate()?;
    if !(MIN_SALT..=MAX_SALT).contains(&salt.len()) {
        return Err(CryptoError::Malformed);
    }
    let mut output = Zeroizing::new([0_u8; OUTPUT_LEN]);
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        settings.params(OUTPUT_LEN)?,
    )
    .hash_password_into(input, salt, output.as_mut_slice())
    .map_err(|_| CryptoError::Internal("argon2 hashing failed"))?;
    Ok(format!(
        "{PREFIX}m={},t={},p={}${}${}",
        settings.memory_kib,
        settings.iterations,
        settings.parallelism,
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(output.as_slice()),
    ))
}

/// Canonical unsigned decimal: 1–10 ASCII digits, no sign, no leading zero.
fn decimal(text: &str) -> Result<u32, CryptoError> {
    let canonical = !text.is_empty()
        && text.len() <= 10
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return Err(CryptoError::Malformed);
    }
    text.parse().map_err(|_| CryptoError::Malformed)
}

#[cfg(test)]
mod tests {
    use argon2::PasswordVerifier as _;

    use super::*;

    const CHEAP: Argon2Settings = Argon2Settings {
        memory_kib: 7_168,
        iterations: 1,
        parallelism: 1,
    };

    /// Reference implementation (`phc-winner-argon2` `src/test.c`) vector:
    /// Argon2id v1.3, t=2, m=2^16 KiB, p=1, "password" / "somesalt".
    #[test]
    fn cry_14_argon2id_reference_phc_vector() {
        let expected = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
        let settings = Argon2Settings {
            memory_kib: 65_536,
            iterations: 2,
            parallelism: 1,
        };
        assert_eq!(
            hash_with_salt(settings, b"password", b"somesalt").unwrap(),
            expected
        );
        let parsed = Argon2Phc::parse(expected).unwrap();
        assert!(parsed.verify(b"password").unwrap());
        assert!(!parsed.verify(b"Password").unwrap());
        assert!(!parsed.is_current(settings), "8-byte salt is not current");
    }

    /// RFC 9106 §5.3 Argon2id test vector (secret and associated data, via the
    /// underlying primitive).
    #[test]
    fn cry_14_argon2id_rfc9106_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .build()
            .unwrap();
        let ctx = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
            .unwrap();
        let mut out = [0_u8; 32];
        ctx.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
            .unwrap();
        assert_eq!(
            crate::encoding::hex(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn cry_01_produced_strings_interoperate_with_the_argon2_crate() {
        let phc = hash(CHEAP, b"input").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=7168,t=1,p=1$"));
        let parsed = Argon2Phc::parse(&phc).unwrap();
        assert!(parsed.is_current(CHEAP));
        assert!(parsed.verify(b"input").unwrap());
        let reference = argon2::password_hash::phc::PasswordHash::new(&phc).unwrap();
        assert!(
            Argon2::default()
                .verify_password(b"input", &reference)
                .is_ok()
        );
        // Fresh salt every time.
        assert_ne!(hash(CHEAP, b"input").unwrap(), phc);
    }

    #[test]
    fn cry_01_parser_is_strict() {
        let good = hash(CHEAP, b"x").unwrap();
        assert!(Argon2Phc::parse(&good).is_ok());
        let cases = [
            good.replace("argon2id", "argon2i"),
            good.replace("argon2id", "argon2d"),
            good.replace("v=19", "v=16"),
            good.replace("m=7168", "m=07168"),
            good.replace("m=7168", "m=+7168"),
            good.replace("m=7168", "m=1024"),
            good.replace("m=7168", "m=4194305"),
            good.replace("t=1", "t=17"),
            good.replace("t=1", "t=0"),
            good.replace("p=1", "p=17"),
            good.replace("m=7168,t=1,p=1", "t=1,m=7168,p=1"),
            good.replace("p=1", "p=1,keyid=AAAA"),
            format!("{good}$"),
            format!("{good}="),
            good.replacen('$', "", 1),
            good.replace("$v=19", ""),
            "$argon2id$v=19$m=7168,t=1,p=1$$".to_owned(),
            format!(
                "$argon2id$v=19$m=7168,t=1,p=1$c29tZXNhbHQ${}",
                "A".repeat(300)
            ),
            String::new(),
        ];
        for case in &cases {
            assert!(Argon2Phc::parse(case).is_err(), "{case}");
        }
    }

    #[test]
    fn cry_01_settings_bounds() {
        assert!(Argon2Settings::DEFAULT.validate().is_ok());
        assert!(
            Argon2Settings {
                memory_kib: 7_168,
                iterations: 1,
                parallelism: 16
            }
            .validate()
            .is_ok()
        );
        assert!(
            Argon2Settings {
                memory_kib: 7_167,
                ..Argon2Settings::DEFAULT
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            Argon2Settings::from(authn_core::config::crypto::Argon2Config::default()),
            Argon2Settings::DEFAULT
        );
    }

    #[test]
    fn cry_13_parsed_hash_debug_hides_output() {
        let parsed = Argon2Phc::parse(&hash(CHEAP, b"x").unwrap()).unwrap();
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("output"), "{debug}");
        assert!(!debug.contains("salt"), "{debug}");
    }
}
