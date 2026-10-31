//! Legacy password hashes (CRY-04).
//!
//! Supported imports and how they are verified:
//!
//! | `algorithm` column | Stored value | Verification input |
//! |--------------------|--------------|--------------------|
//! | `bcrypt` | `$2a$`/`$2b$`/`$2y$` modular crypt, cost 4..=[`MAX_BCRYPT_COST`] | raw password bytes |
//! | `pbkdf2_sha256` | `$pbkdf2-sha256$i=N[,l=L]$salt$hash` (PHC), `$pbkdf2-sha256$N$salt$hash` (passlib) or `pbkdf2_sha256$N$salt$hash` (Django) | raw password bytes |
//! | `argon2id_wrapped_md5` | Argon2id PHC of `HMAC(pepper, hex(md5(pw)))` | raw password bytes |
//! | `argon2id_wrapped_sha1` | Argon2id PHC of `HMAC(pepper, hex(sha1(pw)))` | raw password bytes |
//!
//! Legacy systems hashed the bytes they received, so legacy verification
//! uses the raw (not NFKC-normalized) password. After a successful legacy
//! verification the caller re-hashes the canonical password with plain
//! Argon2id ([`super::RehashReason::LegacyAlgorithm`]).
//!
//! Unsalted MD5/SHA-1 digests are never verified directly: the migration tool
//! (`migrate-legacy-hashes`, [`super::PasswordHasher::wrap_legacy_digest`])
//! wraps them in Argon2id so the database never holds a fast hash.
//!
//! All parsers bound their inputs (length, cost, iterations) so an imported
//! row cannot be used for a denial of service, and they are fuzzed.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use md5::Digest as _;
use zeroize::Zeroizing;

use crate::encoding::hex;
use crate::{CryptoError, ct};

/// Highest bcrypt cost accepted (2^15 rounds ≈ 2–3 s; anything above is
/// treated as a denial-of-service attempt).
pub const MAX_BCRYPT_COST: u32 = 15;
/// Lowest bcrypt cost accepted.
pub const MIN_BCRYPT_COST: u32 = 4;
/// Highest PBKDF2 iteration count accepted.
pub const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;

const MAX_LEGACY_LEN: usize = 512;

/// An unsalted digest scheme that is wrapped into Argon2id on import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyDigest {
    /// MD5 (32 hex characters).
    Md5,
    /// SHA-1 (40 hex characters).
    Sha1,
}

impl LegacyDigest {
    const fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
        }
    }

    /// Lowercase hex digest of `password` (the "legacy hash" of the password).
    #[must_use]
    pub fn digest_hex(self, password: &[u8]) -> Zeroizing<String> {
        let digest = match self {
            Self::Md5 => md5::Md5::digest(password).to_vec(),
            Self::Sha1 => sha1::Sha1::digest(password).to_vec(),
        };
        let digest = Zeroizing::new(digest);
        Zeroizing::new(hex(&digest))
    }

    /// Validates and lowercases an imported hex digest.
    pub fn normalize_hex(self, stored: &str) -> Result<Zeroizing<String>, CryptoError> {
        let trimmed = stored.trim();
        if trimmed.len() != self.hex_len() || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CryptoError::Malformed);
        }
        Ok(Zeroizing::new(trimmed.to_ascii_lowercase()))
    }
}

/// Verifies a bcrypt hash, refusing unknown variants and excessive costs.
pub fn verify_bcrypt(password: &[u8], stored: &str) -> Result<bool, CryptoError> {
    if stored.len() != 60 || !stored.is_ascii() {
        return Err(CryptoError::Malformed);
    }
    let variant = stored.get(..4).ok_or(CryptoError::Malformed)?;
    if !matches!(variant, "$2a$" | "$2b$" | "$2y$") {
        return Err(CryptoError::Unsupported);
    }
    let parts: bcrypt::HashParts = stored.parse().map_err(|_| CryptoError::Malformed)?;
    if !(MIN_BCRYPT_COST..=MAX_BCRYPT_COST).contains(&parts.get_cost()) {
        return Err(CryptoError::Unsupported);
    }
    // bcrypt's verify compares in constant time (subtle) and, like every
    // historic bcrypt, only considers the first 72 bytes of the password.
    bcrypt::verify(password, stored).map_err(|_| CryptoError::Malformed)
}

/// A parsed PBKDF2-HMAC-SHA256 hash.
#[derive(Clone, PartialEq, Eq)]
pub struct Pbkdf2Hash {
    iterations: u32,
    salt: Vec<u8>,
    hash: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Pbkdf2Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pbkdf2Hash")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

impl Pbkdf2Hash {
    /// Parses the PHC, passlib or Django representation.
    pub fn parse(stored: &str) -> Result<Self, CryptoError> {
        if stored.len() > MAX_LEGACY_LEN {
            return Err(CryptoError::TooLarge);
        }
        let parsed = if let Some(rest) = stored.strip_prefix("$pbkdf2-sha256$") {
            let (params, salt, hash) = three_fields(rest)?;
            if params.contains('=') {
                // PHC (RustCrypto `pbkdf2` crate): i=N[,l=L], B64 fields.
                let mut items = params.split(',');
                let iterations = decimal(
                    items
                        .next()
                        .and_then(|i| i.strip_prefix("i="))
                        .ok_or(CryptoError::Malformed)?,
                )?;
                let expected_len = match items.next() {
                    Some(l) => Some(decimal(
                        l.strip_prefix("l=").ok_or(CryptoError::Malformed)?,
                    )?),
                    None => None,
                };
                if items.next().is_some() {
                    return Err(CryptoError::Malformed);
                }
                let parsed = Self {
                    iterations,
                    salt: b64_no_pad(salt)?,
                    hash: Zeroizing::new(b64_no_pad(hash)?),
                };
                if let Some(len) = expected_len
                    && usize::try_from(len).ok() != Some(parsed.hash.len())
                {
                    return Err(CryptoError::Malformed);
                }
                parsed
            } else {
                // passlib: rounds, "adapted base64" ('.' instead of '+').
                Self {
                    iterations: decimal(params)?,
                    salt: ab64(salt)?,
                    hash: Zeroizing::new(ab64(hash)?),
                }
            }
        } else if let Some(rest) = stored.strip_prefix("pbkdf2_sha256$") {
            // Django: the salt is used as its UTF-8 text, hash is base64.
            let (iterations, salt, hash) = three_fields(rest)?;
            if !salt.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(CryptoError::Malformed);
            }
            Self {
                iterations: decimal(iterations)?,
                salt: salt.as_bytes().to_vec(),
                hash: Zeroizing::new(STANDARD.decode(hash).map_err(|_| CryptoError::Malformed)?),
            }
        } else {
            return Err(CryptoError::Unsupported);
        };
        parsed.validate()
    }

    fn validate(self) -> Result<Self, CryptoError> {
        if !(1..=MAX_PBKDF2_ITERATIONS).contains(&self.iterations) {
            return Err(CryptoError::Unsupported);
        }
        if !(1..=256).contains(&self.salt.len()) || !(16..=64).contains(&self.hash.len()) {
            return Err(CryptoError::Malformed);
        }
        Ok(self)
    }

    /// Iteration count.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Recomputes PBKDF2-HMAC-SHA256 and compares in constant time.
    #[must_use]
    pub fn verify(&self, password: &[u8]) -> bool {
        let mut computed = Zeroizing::new(vec![0_u8; self.hash.len()]);
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &self.salt, self.iterations, &mut computed);
        ct::constant_time_eq(&computed, &self.hash)
    }
}

fn three_fields(rest: &str) -> Result<(&str, &str, &str), CryptoError> {
    let mut fields = rest.split('$');
    match (fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some(a), Some(b), Some(c), None) if !a.is_empty() && !b.is_empty() && !c.is_empty() => {
            Ok((a, b, c))
        }
        _ => Err(CryptoError::Malformed),
    }
}

fn b64_no_pad(text: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD_NO_PAD
        .decode(text)
        .map_err(|_| CryptoError::Malformed)
}

fn ab64(text: &str) -> Result<Vec<u8>, CryptoError> {
    if text.contains('+') {
        return Err(CryptoError::Malformed);
    }
    b64_no_pad(&text.replace('.', "+"))
}

fn decimal(text: &str) -> Result<u32, CryptoError> {
    if text.is_empty()
        || text.len() > 9
        || !text.bytes().all(|b| b.is_ascii_digit())
        || text.starts_with('0')
    {
        return Err(CryptoError::Malformed);
    }
    text.parse().map_err(|_| CryptoError::Malformed)
}

#[cfg(test)]
#[allow(clippy::string_slice)] // ASCII fixtures
mod tests {
    use super::*;

    #[test]
    fn cry_04_bcrypt_known_hash() {
        // Generated with OpenBSD bcrypt semantics: "hunter2", cost 4.
        let stored = bcrypt::hash_with_salt(b"hunter2", 4, [7; 16])
            .unwrap()
            .format_for_version(bcrypt::Version::TwoB);
        assert!(verify_bcrypt(b"hunter2", &stored).unwrap());
        assert!(!verify_bcrypt(b"hunter3", &stored).unwrap());
        // Classic published vector (cost 5, "U*U").
        let published = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        assert!(verify_bcrypt(b"U*U", published).unwrap());
    }

    #[test]
    fn cry_04_bcrypt_rejects_variants_and_dos_costs() {
        let stored = bcrypt::hash_with_salt(b"pw", 4, [7; 16])
            .unwrap()
            .format_for_version(bcrypt::Version::TwoB);
        assert_eq!(
            verify_bcrypt(b"pw", &stored.replacen("$2b$", "$2x$", 1)).unwrap_err(),
            CryptoError::Unsupported
        );
        assert_eq!(
            verify_bcrypt(b"pw", &stored.replacen("$04$", "$31$", 1)).unwrap_err(),
            CryptoError::Unsupported
        );
        assert!(verify_bcrypt(b"pw", &stored[..59]).is_err());
        assert!(verify_bcrypt(b"pw", &format!("{}é", &stored[..58])).is_err());
    }

    #[test]
    fn cry_04_pbkdf2_formats() {
        // RFC 7914 §11 PBKDF2-HMAC-SHA256 vector: P="passwd", S="salt", c=1, dkLen=64.
        let expected = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
        let raw = data_encoding::HEXLOWER.decode(expected.as_bytes()).unwrap();
        let phc = format!(
            "$pbkdf2-sha256$i=1,l=64${}${}",
            STANDARD_NO_PAD.encode(b"salt"),
            STANDARD_NO_PAD.encode(&raw)
        );
        let parsed = Pbkdf2Hash::parse(&phc).unwrap();
        assert_eq!(parsed.iterations(), 1);
        assert!(parsed.verify(b"passwd"));
        assert!(!parsed.verify(b"passwe"));

        // Django format.
        let mut dk = [0_u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"secret", b"NaClSalt", 1000, &mut dk);
        let django = format!("pbkdf2_sha256$1000$NaClSalt${}", STANDARD.encode(dk));
        assert!(Pbkdf2Hash::parse(&django).unwrap().verify(b"secret"));

        // passlib format (adapted base64).
        let passlib = format!(
            "$pbkdf2-sha256$1000${}${}",
            STANDARD_NO_PAD.encode(b"NaClSalt").replace('+', "."),
            STANDARD_NO_PAD.encode(dk).replace('+', ".")
        );
        assert!(Pbkdf2Hash::parse(&passlib).unwrap().verify(b"secret"));
    }

    #[test]
    fn cry_04_pbkdf2_parser_is_bounded_and_strict() {
        let dk = STANDARD.encode([1_u8; 32]);
        for bad in [
            format!("pbkdf2_sha256$0$salt${dk}"),
            format!("pbkdf2_sha256$5000001$salt${dk}"),
            format!("pbkdf2_sha256$01000$salt${dk}"),
            format!("pbkdf2_sha256$1000$$${dk}"),
            format!("pbkdf2_sha256$1000$salt${dk}$"),
            format!("pbkdf2_sha256$1000$sa lt${dk}"),
            "pbkdf2_sha256$1000$salt$AAAA".to_owned(),
            "$pbkdf2-sha256$i=1,l=31$c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "$pbkdf2-sha256$i=1,x=1$c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "$pbkdf2-sha512$i=1$c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "x".repeat(600),
            String::new(),
        ] {
            assert!(Pbkdf2Hash::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cry_04_legacy_digests() {
        assert_eq!(
            &*LegacyDigest::Md5.digest_hex(b"password"),
            "5f4dcc3b5aa765d61d8327deb882cf99"
        );
        assert_eq!(
            &*LegacyDigest::Sha1.digest_hex(b"password"),
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        );
        assert_eq!(
            &*LegacyDigest::Md5
                .normalize_hex(" 5F4DCC3B5AA765D61D8327DEB882CF99 ")
                .unwrap(),
            "5f4dcc3b5aa765d61d8327deb882cf99"
        );
        assert!(LegacyDigest::Md5.normalize_hex("5f4dcc").is_err());
        assert!(LegacyDigest::Sha1.normalize_hex(&"g".repeat(40)).is_err());
    }
}
