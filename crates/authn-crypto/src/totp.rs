//! TOTP core (RFC 6238 over RFC 4226 HOTP), used by `authn-mfa` (MFA-01,
//! MFA-02).
//!
//! * Defaults (MFA-01): HMAC-SHA1, 6 digits, 30 s period, ±1 step window;
//!   all configurable within safe bounds.
//! * [`Totp::verify`] checks **every** step of the window with constant-time
//!   comparisons (no early exit) and returns the matched time step, so the
//!   caller can persist it and reject that step and every earlier one
//!   afterwards (replay protection, MFA-02). Steps `<= last_used_step` are
//!   never accepted.
//! * Secrets are 160 bits from the OS CSPRNG, zeroized on drop, redacted in
//!   `Debug`, base32 for provisioning.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use hmac::Mac as _;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::encoding::percent_encode;
use crate::secret::SecretBytes;
use crate::{CryptoError, ct, random};

/// Default secret size in bytes (160 bits, RFC 4226 §4 recommendation).
pub const SECRET_BYTES: usize = 20;
const MIN_SECRET_BYTES: usize = 16;
const MAX_SECRET_BYTES: usize = 64;

/// HMAC hash function of the OTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (interoperable default of every authenticator app).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl TotpAlgorithm {
    /// Name used in `otpauth://` URIs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// TOTP parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TotpParams {
    /// HMAC hash function.
    pub algorithm: TotpAlgorithm,
    /// Code length, 6..=8.
    pub digits: u32,
    /// Time step in seconds, 15..=300.
    pub period: u32,
    /// Accepted steps before and after the current one, 0..=5.
    pub skew: u32,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            skew: 1,
        }
    }
}

impl TotpParams {
    /// Validates the bounds.
    pub fn validate(self) -> Result<Self, CryptoError> {
        let ok =
            (6..=8).contains(&self.digits) && (15..=300).contains(&self.period) && self.skew <= 5;
        if ok {
            Ok(self)
        } else {
            Err(CryptoError::Unsupported)
        }
    }
}

/// A shared TOTP secret.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(SecretBytes);

impl TotpSecret {
    /// A new 160-bit secret.
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = random::secret_bytes::<SECRET_BYTES>()?;
        Ok(Self(SecretBytes::new(bytes.to_vec())))
    }

    /// Wraps stored secret bytes (16..=64 bytes), e.g. after opening the
    /// envelope stored in `mfa_factors`.
    pub fn from_bytes(bytes: SecretBytes) -> Result<Self, CryptoError> {
        if (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(CryptoError::InvalidKey)
        }
    }

    /// Parses a base32 secret (case-insensitive, spaces and `=` padding
    /// ignored).
    pub fn from_base32(text: &str) -> Result<Self, CryptoError> {
        if text.len() > 256 {
            return Err(CryptoError::TooLarge);
        }
        let mut cleaned = Zeroizing::new(String::with_capacity(text.len()));
        for c in text.trim_end_matches('=').chars() {
            match c {
                ' ' => {}
                'a'..='z' => cleaned.push(c.to_ascii_uppercase()),
                'A'..='Z' | '2'..='7' => cleaned.push(c),
                _ => return Err(CryptoError::Malformed),
            }
        }
        let decoded = BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| CryptoError::Malformed)?;
        Self::from_bytes(SecretBytes::new(decoded))
    }

    /// Base32 (RFC 4648, no padding) for provisioning.
    #[must_use]
    pub fn to_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE32_NOPAD.encode(self.0.expose()))
    }

    /// The raw secret (to seal it with envelope encryption).
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TotpSecret({})", crate::secret::REDACTED)
    }
}

/// HOTP value (RFC 4226 §5.3) for `counter`, before zero-padding.
pub fn hotp(
    secret: &[u8],
    counter: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<u32, CryptoError> {
    let message = counter.to_be_bytes();
    let digest: Zeroizing<Vec<u8>> = Zeroizing::new(match algorithm {
        TotpAlgorithm::Sha1 => mac::<sha1::Sha1>(secret, &message)?,
        TotpAlgorithm::Sha256 => mac::<sha2::Sha256>(secret, &message)?,
        TotpAlgorithm::Sha512 => mac::<sha2::Sha512>(secret, &message)?,
    });
    let offset = usize::from(
        digest
            .last()
            .copied()
            .ok_or(CryptoError::Internal("empty mac"))?
            & 0x0f,
    );
    let window: [u8; 4] = digest
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(CryptoError::Internal("short mac"))?;
    let binary = u32::from_be_bytes(window) & 0x7fff_ffff;
    let modulus = 10_u32.checked_pow(digits).ok_or(CryptoError::Unsupported)?;
    Ok(binary % modulus)
}

fn mac<D>(key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError>
where
    D: hmac::EagerHash,
    hmac::Hmac<D>: hmac::KeyInit + hmac::Mac,
{
    let mut mac = <hmac::Hmac<D> as hmac::KeyInit>::new_from_slice(key)
        .map_err(|_| CryptoError::Internal("hmac key length"))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// A TOTP generator / verifier with fixed parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Totp {
    params: TotpParams,
}

impl Totp {
    /// Validates the parameters.
    pub fn new(params: TotpParams) -> Result<Self, CryptoError> {
        Ok(Self {
            params: params.validate()?,
        })
    }

    /// The parameters.
    #[must_use]
    pub const fn params(&self) -> TotpParams {
        self.params
    }

    /// Time step containing `at` (`None` before the Unix epoch).
    #[must_use]
    pub fn time_step(&self, at: OffsetDateTime) -> Option<u64> {
        u64::try_from(at.unix_timestamp())
            .ok()
            .map(|secs| secs / u64::from(self.params.period))
    }

    /// The code for time step `step`.
    pub fn code_for_step(
        &self,
        secret: &TotpSecret,
        step: u64,
    ) -> Result<Zeroizing<String>, CryptoError> {
        let value = hotp(
            secret.expose(),
            step,
            self.params.digits,
            self.params.algorithm,
        )?;
        let width = usize::try_from(self.params.digits).map_err(|_| CryptoError::Unsupported)?;
        Ok(Zeroizing::new(format!("{value:0width$}")))
    }

    /// The code valid at `at`.
    pub fn generate(
        &self,
        secret: &TotpSecret,
        at: OffsetDateTime,
    ) -> Result<Zeroizing<String>, CryptoError> {
        let step = self.time_step(at).ok_or(CryptoError::Unsupported)?;
        self.code_for_step(secret, step)
    }

    /// Verifies `code` at `at`. Returns the matched time step, or `None` if
    /// the code is malformed, wrong, outside the window, or for a step
    /// `<= last_used_step` (replay).
    pub fn verify(
        &self,
        secret: &TotpSecret,
        code: &str,
        at: OffsetDateTime,
        last_used_step: Option<u64>,
    ) -> Result<Option<u64>, CryptoError> {
        let digits = usize::try_from(self.params.digits).map_err(|_| CryptoError::Unsupported)?;
        if code.len() != digits || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(None);
        }
        let Some(current) = self.time_step(at) else {
            return Ok(None);
        };
        let skew = u64::from(self.params.skew);
        let mut matched = None;
        for step in current.saturating_sub(skew)..=current.saturating_add(skew) {
            let expected = self.code_for_step(secret, step)?;
            let equal = ct::constant_time_eq(expected.as_bytes(), code.as_bytes());
            let fresh = last_used_step.is_none_or(|last| step > last);
            if equal && fresh && matched.is_none() {
                matched = Some(step);
            }
        }
        Ok(matched)
    }

    /// `otpauth://totp/…` provisioning URI (Key URI Format) for QR codes.
    /// Contains the secret: treat as secret.
    pub fn provisioning_uri(
        &self,
        secret: &TotpSecret,
        issuer: &str,
        account: &str,
    ) -> Result<Zeroizing<String>, CryptoError> {
        let valid = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        if !valid(issuer) || !valid(account) || issuer.contains(':') {
            return Err(CryptoError::Malformed);
        }
        let issuer = percent_encode(issuer);
        Ok(Zeroizing::new(format!(
            "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
            account = percent_encode(account),
            secret = secret.to_base32().as_str(),
            algorithm = self.params.algorithm.as_str(),
            digits = self.params.digits,
            period = self.params.period,
        )))
    }
}

#[cfg(test)]
#[allow(clippy::string_slice)] // ASCII fixtures
mod tests {
    use time::macros::datetime;

    use super::*;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    fn secret(ascii: &[u8]) -> TotpSecret {
        TotpSecret::from_bytes(SecretBytes::new(ascii.to_vec())).unwrap()
    }

    /// RFC 4226 Appendix D.
    #[test]
    fn cry_14_hotp_rfc4226_vectors() {
        let expected = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (counter, value) in expected.iter().enumerate() {
            assert_eq!(
                hotp(
                    b"12345678901234567890",
                    counter as u64,
                    6,
                    TotpAlgorithm::Sha1
                )
                .unwrap(),
                *value
            );
        }
    }

    /// RFC 6238 Appendix B (8 digits, 30 s, SHA1/SHA256/SHA512).
    #[test]
    fn cry_14_totp_rfc6238_vectors() {
        let sha1 = secret(b"12345678901234567890");
        let sha256 = secret(b"12345678901234567890123456789012");
        let sha512 = secret(b"1234567890123456789012345678901234567890123456789012345678901234");
        let table: [(i64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (time, c1, c256, c512) in table {
            for (algorithm, key, expected) in [
                (TotpAlgorithm::Sha1, &sha1, c1),
                (TotpAlgorithm::Sha256, &sha256, c256),
                (TotpAlgorithm::Sha512, &sha512, c512),
            ] {
                let totp = Totp::new(TotpParams {
                    algorithm,
                    digits: 8,
                    period: 30,
                    skew: 0,
                })
                .unwrap();
                assert_eq!(
                    &*totp.generate(key, at(time)).unwrap(),
                    expected,
                    "{algorithm:?} @ {time}"
                );
                let step = totp.verify(key, expected, at(time), None).unwrap();
                assert_eq!(step, totp.time_step(at(time)));
            }
        }
    }

    #[test]
    fn mfa_01_window_and_replay_protection() {
        let totp = Totp::new(TotpParams::default()).unwrap();
        let key = TotpSecret::generate().unwrap();
        assert_eq!(key.expose().len(), SECRET_BYTES);
        let now = datetime!(2026-03-01 12:00:10 UTC);
        let step = totp.time_step(now).unwrap();
        let previous = totp.code_for_step(&key, step - 1).unwrap();
        let current = totp.code_for_step(&key, step).unwrap();
        let next = totp.code_for_step(&key, step + 1).unwrap();
        let too_old = totp.code_for_step(&key, step - 2).unwrap();

        assert_eq!(totp.verify(&key, &current, now, None).unwrap(), Some(step));
        assert_eq!(
            totp.verify(&key, &previous, now, None).unwrap(),
            Some(step - 1)
        );
        assert_eq!(totp.verify(&key, &next, now, None).unwrap(), Some(step + 1));
        if *too_old != *previous && *too_old != *current && *too_old != *next {
            assert_eq!(totp.verify(&key, &too_old, now, None).unwrap(), None);
        }
        // MFA-02: the same step (and older ones) cannot be replayed.
        assert_eq!(totp.verify(&key, &current, now, Some(step)).unwrap(), None);
        if *previous != *next {
            assert_eq!(
                totp.verify(&key, &previous, now, Some(step - 1)).unwrap(),
                None
            );
        }
        assert_eq!(
            totp.verify(&key, &next, now, Some(step)).unwrap(),
            Some(step + 1)
        );
        // Malformed input.
        for bad in ["", "12345", "1234567", "12345a", "١٢٣٤٥٦"] {
            assert_eq!(totp.verify(&key, bad, now, None).unwrap(), None);
        }
        // Before the epoch nothing verifies.
        assert_eq!(totp.time_step(at(-1)), None);
        assert_eq!(totp.verify(&key, &current, at(-1), None).unwrap(), None);
    }

    #[test]
    fn mfa_01_parameters_are_bounded() {
        let base = TotpParams::default();
        for bad in [
            TotpParams { digits: 5, ..base },
            TotpParams { digits: 9, ..base },
            TotpParams { period: 0, ..base },
            TotpParams {
                period: 301,
                ..base
            },
            TotpParams { skew: 6, ..base },
        ] {
            assert!(Totp::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mfa_01_base32_and_otpauth_uri() {
        let key = TotpSecret::from_base32("jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp====").unwrap();
        assert_eq!(
            key.expose(),
            b"Hello!\xde\xad\xbe\xefHello!\xde\xad\xbe\xef"
        );
        assert_eq!(&*key.to_base32(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        // 80-bit secrets are below the 128-bit minimum.
        assert!(
            TotpSecret::from_base32("JBSWY3DPEHPK3PXP").is_err(),
            "too short"
        );
        assert!(TotpSecret::from_base32("JBSWY3DP=EHPK3PXPJBSWY3DPEHPK3PXP").is_err());
        assert!(TotpSecret::from_base32("JBSWY3DPEHPK3PX!").is_err());
        assert!(TotpSecret::from_base32(&"A".repeat(300)).is_err());
        let round = TotpSecret::generate().unwrap();
        assert_eq!(TotpSecret::from_base32(&round.to_base32()).unwrap(), round);

        let totp = Totp::new(TotpParams::default()).unwrap();
        let uri = totp
            .provisioning_uri(&key, "Acme Inc", "alice@example.com")
            .unwrap();
        assert_eq!(
            &*uri,
            "otpauth://totp/Acme%20Inc:alice%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Acme%20Inc&algorithm=SHA1&digits=6&period=30"
        );
        assert!(totp.provisioning_uri(&key, "Ac:me", "a").is_err());
        assert!(totp.provisioning_uri(&key, "Acme", "").is_err());
        assert!(totp.provisioning_uri(&key, "Acme", "a\nb").is_err());
    }

    #[test]
    fn cry_13_totp_secret_is_redacted() {
        let key = TotpSecret::generate().unwrap();
        assert!(!format!("{key:?}").contains(&key.to_base32()[..8]));
    }
}
