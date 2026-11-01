//! Recovery codes (MFA-04): generation, parsing and keyed storage hashes.
//!
//! * Alphabet: Crockford base32 (`0-9`, `A-Z` without `I`, `L`, `O`, `U`) —
//!   32 symbols, so every character carries exactly 5 bits and a 10-character
//!   code carries **50 bits** (MFA-04 minimum).
//! * Shown grouped as `XXXXX-XXXXX`. Input is forgiving: case-insensitive,
//!   hyphens and spaces ignored, and the confusable letters `O` → `0`,
//!   `I` / `L` → `1` are mapped (they never appear in generated codes).
//! * Storage: `HMAC-SHA256(K_recovery, len‖user_id‖len‖code)` with the
//!   [`KeyPurpose::RecoveryCode`] HKDF sub-key. Binding the user id makes a
//!   hash useless for any other account; the key makes a database leak alone
//!   insufficient to brute-force the 2^50 space offline.
//! * Single use is enforced by the database (`UPDATE … WHERE used_at IS NULL
//!   RETURNING`), see `crate::store::recovery`.

use std::fmt;

use authn_core::id::UserId;
use authn_crypto::CryptoError;
use authn_crypto::kdf::{HmacKey, KeyPurpose, KeyRing};
use authn_crypto::random;
use zeroize::Zeroizing;

/// The 32-symbol output alphabet (Crockford base32).
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters of a code (without the separator).
pub const CODE_CHARS: usize = 10;

/// Entropy of one code in bits (`CODE_CHARS × log2(32)`).
pub const CODE_BITS: u32 = 50;

/// Longest input accepted by [`RecoveryCode::parse`] (bytes).
const MAX_INPUT_BYTES: usize = 32;

/// A recovery code in canonical form (10 alphabet characters, no
/// separator). Zeroized on drop, redacted in `Debug`, no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    /// A fresh uniformly random code from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        random::string_from_alphabet(ALPHABET, CODE_CHARS).map(Self)
    }

    /// Parses user input; `None` for anything that is not a well-formed
    /// code. Never allocates proportionally to hostile input.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        if input.len() > MAX_INPUT_BYTES {
            return None;
        }
        let mut out = Zeroizing::new(String::with_capacity(CODE_CHARS));
        for c in input.chars() {
            let mapped = match c.to_ascii_uppercase() {
                '-' | ' ' => continue,
                'O' => b'0',
                'I' | 'L' => b'1',
                other => match u8::try_from(other) {
                    Ok(byte) if ALPHABET.contains(&byte) => byte,
                    _ => return None,
                },
            };
            if out.len() == CODE_CHARS {
                return None;
            }
            out.push(char::from(mapped));
        }
        (out.len() == CODE_CHARS).then_some(Self(out))
    }

    /// The display form `XXXXX-XXXXX` (only for showing the codes once).
    #[must_use]
    pub fn display(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(CODE_CHARS + 1));
        for (i, c) in self.0.chars().enumerate() {
            if i == CODE_CHARS / 2 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// The canonical form (10 characters, no separator).
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryCode({})", authn_core::secret::REDACTED)
    }
}

/// Generates `count` distinct codes.
pub fn generate_batch(count: usize) -> Result<Vec<RecoveryCode>, CryptoError> {
    let mut codes: Vec<RecoveryCode> = Vec::with_capacity(count);
    // A collision has probability ~count²/2^51; the loop is bounded anyway.
    let mut budget = count.saturating_mul(4).max(8);
    while codes.len() < count {
        if budget == 0 {
            return Err(CryptoError::Internal("recovery code generation"));
        }
        budget -= 1;
        let code = RecoveryCode::generate()?;
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    Ok(codes)
}

/// Keyed storage hashes of recovery codes.
#[derive(Clone)]
pub struct RecoveryCodeHasher {
    key: HmacKey,
}

impl RecoveryCodeHasher {
    /// A hasher with the [`KeyPurpose::RecoveryCode`] sub-key.
    pub fn new(ring: &KeyRing) -> Result<Self, CryptoError> {
        Ok(Self {
            key: ring.key(KeyPurpose::RecoveryCode)?.clone(),
        })
    }

    /// The 32-byte storage hash of `code` for `user`.
    #[must_use]
    pub fn hash(&self, user: UserId, code: &RecoveryCode) -> [u8; 32] {
        self.key.sign_fields(&[
            user.as_uuid().as_bytes().as_slice(),
            code.canonical().as_bytes(),
        ])
    }
}

impl fmt::Debug for RecoveryCodeHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCodeHasher").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn mfa_04_alphabet_has_32_unambiguous_symbols_and_50_bits() {
        let set: HashSet<u8> = ALPHABET.iter().copied().collect();
        assert_eq!(set.len(), 32);
        for ambiguous in *b"ILOU" {
            assert!(!set.contains(&ambiguous));
        }
        assert!(
            ALPHABET
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        );
        // 32^10 = 2^50.
        let chars = u32::try_from(CODE_CHARS).unwrap();
        assert_eq!(
            u64::try_from(ALPHABET.len()).unwrap().pow(chars),
            1_u64 << CODE_BITS
        );
        const { assert!(CODE_BITS >= 50) };
    }

    #[test]
    fn mfa_04_generated_codes_are_well_formed_and_distinct() {
        let codes = generate_batch(10).unwrap();
        assert_eq!(codes.len(), 10);
        let unique: HashSet<String> = codes.iter().map(|c| c.canonical().to_owned()).collect();
        assert_eq!(unique.len(), 10);
        for code in &codes {
            let shown = code.display();
            assert_eq!(shown.len(), 11);
            assert_eq!(shown.as_bytes()[5], b'-');
            assert!(code.canonical().bytes().all(|b| ALPHABET.contains(&b)));
            assert_eq!(RecoveryCode::parse(&shown).as_ref(), Some(code));
        }
    }

    #[test]
    fn mfa_04_parsing_is_forgiving_but_strict_about_content() {
        let code = RecoveryCode::parse("ab0cd-1ef2g").unwrap();
        assert_eq!(code.canonical(), "AB0CD1EF2G");
        // Confusables map to their digit.
        assert_eq!(
            RecoveryCode::parse("abocd-ief2g").unwrap().canonical(),
            "AB0CD1EF2G"
        );
        assert_eq!(
            RecoveryCode::parse(" AB0CD 1EF2G ").unwrap().canonical(),
            "AB0CD1EF2G"
        );
        assert_eq!(
            RecoveryCode::parse("ab0cdlef2g").unwrap().canonical(),
            "AB0CD1EF2G"
        );
        for bad in [
            "",
            "AB0CD-1EF2",
            "AB0CD-1EF2GH",
            "AB0CD-1EF2U",
            "AB0CD_1EF2G",
            "AB0CD-1EF2Ğ",
            "ＡB0CD-1EF2G",
            "AB0CD-1EF2G\0",
            &"A".repeat(33),
        ] {
            assert!(RecoveryCode::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn mfa_04_hash_is_keyed_and_bound_to_the_user() {
        let ring = KeyRing::derive(&[7; 32]).unwrap();
        let hasher = RecoveryCodeHasher::new(&ring).unwrap();
        let code = RecoveryCode::parse("AB0CD-1EF2G").unwrap();
        let alice = UserId::generate();
        let bob = UserId::generate();
        assert_eq!(hasher.hash(alice, &code), hasher.hash(alice, &code));
        assert_ne!(hasher.hash(alice, &code), hasher.hash(bob, &code));
        let other = RecoveryCodeHasher::new(&KeyRing::derive(&[8; 32]).unwrap()).unwrap();
        assert_ne!(hasher.hash(alice, &code), other.hash(alice, &code));
        assert_ne!(
            hasher.hash(alice, &code),
            authn_crypto::sha256(b"AB0CD1EF2G")
        );
    }

    #[test]
    fn cry_13_recovery_codes_are_redacted() {
        let code = RecoveryCode::parse("AB0CD-1EF2G").unwrap();
        assert!(!format!("{code:?}").contains("AB0CD"));
    }
}
