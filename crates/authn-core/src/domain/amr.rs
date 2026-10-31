//! Authentication method references (RFC 8176) and related classifiers.

text_enum! {
    /// Authentication Method Reference values (RFC 8176) carried in sessions
    /// and the `amr` claim of access tokens (SES-08, SES-21).
    ///
    /// `email` and `fed` are not registered in RFC 8176; they are documented
    /// extensions of this system (e-mail OTP / magic link, federated login).
    pub enum AuthMethodRef {
        /// Password.
        Pwd => "pwd",
        /// One-time password (TOTP or OTP code).
        Otp => "otp",
        /// Proof of possession of a hardware-secured key (device-bound passkey,
        /// security key).
        Hwk => "hwk",
        /// Proof of possession of a software-secured key (synced passkey).
        Swk => "swk",
        /// Multiple factors were used.
        Mfa => "mfa",
        /// SMS confirmation code.
        Sms => "sms",
        /// User presence test (WebAuthn UP).
        User => "user",
        /// PIN or pattern (WebAuthn UV via PIN).
        Pin => "pin",
        /// Fingerprint biometric.
        Fpt => "fpt",
        /// Facial recognition biometric.
        Face => "face",
        /// Knowledge-based authentication (recovery code).
        Kba => "kba",
        /// Risk-based authentication.
        Rba => "rba",
        /// Multiple-channel authentication.
        Mca => "mca",
        /// E-mail delivered code or link (extension).
        Email => "email",
        /// Federated login at an external identity provider (extension).
        Fed => "fed",
    }
}

text_enum! {
    /// Which kind of client a session or challenge belongs to.
    pub enum ClientKind {
        /// Browser: opaque session cookie + CSRF protection (SES-03, SES-04).
        Web => "web",
        /// Native / mobile: JWT access token + rotating refresh token (SES-05).
        Native => "native",
    }
}

text_enum! {
    /// Second-factor kinds (MFA-*, PKY-*). Used by MFA policy evaluation,
    /// organization policies (allowed factors) and login challenges.
    pub enum FactorKind {
        /// RFC 6238 TOTP authenticator app.
        Totp => "totp",
        /// WebAuthn credential used as a second factor.
        Webauthn => "webauthn",
        /// Single-use recovery code.
        RecoveryCode => "recovery_code",
        /// E-mail OTP (backup factor).
        Email => "email",
        /// SMS OTP (weak factor).
        Sms => "sms",
    }
}

impl FactorKind {
    /// Phishing-resistant factors (MFA-08, ORG-07): only WebAuthn.
    #[must_use]
    pub const fn is_phishing_resistant(self) -> bool {
        matches!(self, Self::Webauthn)
    }

    /// Weak factors that organization policies may forbid (MFA-06).
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(self, Self::Sms)
    }
}

text_enum! {
    /// Primary login methods (ORG-07 "allowed login methods", SES-*).
    pub enum LoginMethod {
        /// E-mail + password.
        Password => "password",
        /// Passkey (discoverable WebAuthn credential).
        Passkey => "passkey",
        /// Magic link sent by e-mail (SES-18).
        MagicLink => "magic_link",
        /// Six-digit code sent by e-mail (SES-19).
        EmailCode => "email_code",
        /// Social / federated login (SOC-*).
        Social => "social",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ses_08_amr_values_follow_rfc_8176_spelling() {
        let all: Vec<&str> = AuthMethodRef::ALL.iter().map(|a| a.as_str()).collect();
        for v in ["pwd", "otp", "hwk", "swk", "mfa", "sms"] {
            assert!(all.contains(&v), "{v} missing");
        }
        for amr in AuthMethodRef::ALL {
            assert_eq!(
                serde_json::to_value(amr).unwrap(),
                serde_json::Value::String(amr.as_str().to_owned())
            );
        }
    }

    #[test]
    fn mfa_08_only_webauthn_is_phishing_resistant() {
        for f in FactorKind::ALL {
            assert_eq!(f.is_phishing_resistant(), *f == FactorKind::Webauthn);
        }
        assert!(FactorKind::Sms.is_weak());
    }

    #[test]
    fn text_enums_round_trip() {
        for m in LoginMethod::ALL {
            assert_eq!(m.to_string().parse::<LoginMethod>().unwrap(), *m);
        }
        for c in ClientKind::ALL {
            assert_eq!(c.as_str().parse::<ClientKind>().unwrap(), *c);
        }
    }
}
