//! E.164 phone number newtype (MFA-06 baseline).
//!
//! Only the syntactic E.164 form is checked here (`+` followed by 8–15
//! digits, first digit non-zero). Country allow-lists, SMS pumping
//! protection and number verification are owned by `authn-mfa`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Why a phone number was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("phone number must be in E.164 format")]
pub struct PhoneNumberError;

/// A phone number in E.164 format, e.g. `+905551112233`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PhoneNumber(String);

impl PhoneNumber {
    /// Parses strict E.164 (no spaces, dashes or parentheses).
    pub fn parse(input: &str) -> Result<Self, PhoneNumberError> {
        let digits = input.strip_prefix('+').ok_or(PhoneNumberError)?;
        let valid = (8..=15).contains(&digits.len())
            && digits.bytes().all(|b| b.is_ascii_digit())
            && !digits.starts_with('0');
        if valid {
            Ok(Self(input.to_owned()))
        } else {
            Err(PhoneNumberError)
        }
    }

    /// The E.164 string including the leading `+`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Masked form for logs and listings (`+90*******233`).
    #[must_use]
    pub fn masked(&self) -> String {
        let chars: Vec<char> = self.0.chars().collect();
        chars
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i < 3 || i + 3 >= chars.len() {
                    *c
                } else {
                    '*'
                }
            })
            .collect()
    }
}

impl fmt::Debug for PhoneNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhoneNumber({})", self.masked())
    }
}

impl Serialize for PhoneNumber {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PhoneNumber {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_06_e164_parsing() {
        assert!(PhoneNumber::parse("+905551112233").is_ok());
        assert!(PhoneNumber::parse("+14155552671").is_ok());
        for bad in [
            "905551112233",
            "+0555",
            "+90 555 111 22 33",
            "+",
            "+1234567",
            "+1234567890123456",
            "+90abc1112233",
        ] {
            assert!(PhoneNumber::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mfa_06_phone_is_masked_in_debug() {
        let p = PhoneNumber::parse("+905551112233").unwrap();
        assert_eq!(p.masked(), "+90*******233");
        assert_eq!(format!("{p:?}"), "PhoneNumber(+90*******233)");
    }
}
