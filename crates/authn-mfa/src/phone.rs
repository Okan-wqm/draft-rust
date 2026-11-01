//! Phone numbers for the SMS factor (MFA-06): strict E.164 parsing and the
//! country allow-list.
//!
//! E.164 country calling codes form a prefix code (ITU-T E.164 §6), so a
//! number belongs to an allowed country exactly when its digits start with
//! one of the configured codes (`mfa.sms.allowed_country_codes`, validated
//! as 1–3 digits without a leading zero). Nothing is "normalized" here on
//! purpose: spaces, dashes, parentheses, full-width or other Unicode digits
//! are rejected rather than guessed, so two spellings can never map to the
//! same number in one place and to different numbers in another.

use authn_core::domain::PhoneNumber;
use authn_core::error::{AuthError, codes};

/// Longest input accepted before parsing (`+` and 15 digits).
const MAX_PHONE_INPUT_BYTES: usize = 16;

/// Parses a strict E.164 number (`+` followed by 8–15 ASCII digits, the
/// first non-zero).
pub fn parse_phone(input: &str) -> Result<PhoneNumber, AuthError> {
    if input.len() > MAX_PHONE_INPUT_BYTES {
        return Err(AuthError::new(codes::mfa::MFA_INVALID_PHONE_NUMBER));
    }
    PhoneNumber::parse(input).map_err(|_| AuthError::new(codes::mfa::MFA_INVALID_PHONE_NUMBER))
}

/// Whether `phone` belongs to one of the allowed country calling codes
/// (codes without `+`, e.g. `"90"`). An empty list allows nothing.
#[must_use]
pub fn country_allowed(phone: &PhoneNumber, allowed_country_codes: &[String]) -> bool {
    let digits = phone.as_str().trim_start_matches('+');
    allowed_country_codes.iter().any(|code| {
        !code.is_empty()
            && code.bytes().all(|b| b.is_ascii_digit())
            && digits.starts_with(code.as_str())
    })
}

/// Parses `input` and checks the allow-list (MFA-06).
pub fn parse_allowed_phone(
    input: &str,
    allowed_country_codes: &[String],
) -> Result<PhoneNumber, AuthError> {
    let phone = parse_phone(input)?;
    if country_allowed(&phone, allowed_country_codes) {
        Ok(phone)
    } else {
        Err(AuthError::new(codes::mfa::MFA_PHONE_COUNTRY_NOT_ALLOWED))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn mfa_06_strict_e164_only() {
        assert_eq!(
            parse_phone("+905551112233").unwrap().as_str(),
            "+905551112233"
        );
        for bad in [
            "905551112233",
            "+90 555 111 22 33",
            "+90-555-111-2233",
            "(+90)5551112233",
            "+0905551112233",
            "+١٢٣٤٥٦٧٨٩٠",
            "＋905551112233",
            "+90555111223３",
            "+1234567",
            "+1234567890123456",
            "",
            "+",
            "+90555111223\n",
        ] {
            assert!(parse_phone(bad).is_err(), "{bad:?}");
            assert_eq!(
                parse_phone(bad).unwrap_err().code(),
                codes::mfa::MFA_INVALID_PHONE_NUMBER
            );
        }
    }

    #[test]
    fn mfa_06_country_allow_list() {
        let list = allowed(&["90", "1"]);
        assert!(parse_allowed_phone("+905551112233", &list).is_ok());
        assert!(parse_allowed_phone("+14155552671", &list).is_ok());
        let err = parse_allowed_phone("+447911123456", &list).unwrap_err();
        assert_eq!(err.code(), codes::mfa::MFA_PHONE_COUNTRY_NOT_ALLOWED);
        // Default (empty) list: SMS is not available anywhere.
        assert!(!country_allowed(
            &parse_phone("+905551112233").unwrap(),
            &[]
        ));
        // A number whose digits merely *contain* the code is not allowed.
        assert!(!country_allowed(
            &parse_phone("+449055511122").unwrap(),
            &allowed(&["90"])
        ));
        // Garbage entries never match everything.
        assert!(!country_allowed(
            &parse_phone("+905551112233").unwrap(),
            &allowed(&["", "+90"])
        ));
    }
}
