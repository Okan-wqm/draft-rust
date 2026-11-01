//! RFC 8176 authentication method references of second factors (SES-08,
//! SES-21).
//!
//! | Factor | `amr` |
//! |--------|-------|
//! | TOTP | `otp` |
//! | SMS OTP | `sms` |
//! | E-mail OTP | `email` (documented extension) |
//! | Recovery code | `kba` |
//! | WebAuthn (authn-webauthn) | `hwk` / `swk` (reported by that module) |
//!
//! [`combine`] adds `mfa` once two different factors were verified.

use authn_core::domain::{AuthMethodRef, FactorKind};

/// The method references of one verified factor of this crate.
#[must_use]
pub fn for_factor(kind: FactorKind) -> Vec<AuthMethodRef> {
    match kind {
        FactorKind::Totp => vec![AuthMethodRef::Otp],
        FactorKind::Sms => vec![AuthMethodRef::Sms],
        FactorKind::Email => vec![AuthMethodRef::Email],
        FactorKind::RecoveryCode => vec![AuthMethodRef::Kba],
        // Verified by authn-webauthn, which reports hwk/swk itself.
        FactorKind::Webauthn => vec![AuthMethodRef::Hwk],
    }
}

/// Merges the references of the primary authentication and of a verified
/// second factor (deduplicated, order kept) and appends `mfa` when the
/// second factor added a method that was not already there.
#[must_use]
pub fn combine(primary: &[AuthMethodRef], second: &[AuthMethodRef]) -> Vec<AuthMethodRef> {
    let mut out: Vec<AuthMethodRef> = Vec::with_capacity(primary.len() + second.len() + 1);
    for amr in primary {
        if !out.contains(amr) {
            out.push(*amr);
        }
    }
    let mut added = false;
    for amr in second {
        if !out.contains(amr) {
            out.push(*amr);
            added = true;
        }
    }
    if added && !primary.is_empty() && !out.contains(&AuthMethodRef::Mfa) {
        out.push(AuthMethodRef::Mfa);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ses_08_factor_amr_values() {
        assert_eq!(for_factor(FactorKind::Totp), vec![AuthMethodRef::Otp]);
        assert_eq!(for_factor(FactorKind::Sms), vec![AuthMethodRef::Sms]);
        assert_eq!(for_factor(FactorKind::Email), vec![AuthMethodRef::Email]);
        assert_eq!(
            for_factor(FactorKind::RecoveryCode),
            vec![AuthMethodRef::Kba]
        );
    }

    #[test]
    fn mfa_08_combine_adds_mfa_once() {
        let pwd = [AuthMethodRef::Pwd];
        assert_eq!(
            combine(&pwd, &for_factor(FactorKind::Totp)),
            vec![AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa]
        );
        let already = combine(
            &[AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa],
            &[AuthMethodRef::Otp],
        );
        assert_eq!(
            already,
            vec![AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa]
        );
        // Same method again is not a second factor.
        assert_eq!(
            combine(&[AuthMethodRef::Otp], &[AuthMethodRef::Otp]),
            vec![AuthMethodRef::Otp]
        );
        assert_eq!(
            combine(&[], &[AuthMethodRef::Otp]),
            vec![AuthMethodRef::Otp]
        );
    }
}
