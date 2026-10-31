//! Every crypto service built from `[crypto]` in one place (for
//! `authn-server`'s `AppState` and for CLI commands).

use std::time::Duration;

use authn_core::config::crypto::CryptoConfig;

use crate::CryptoError;
use crate::envelope::EnvelopeCipher;
use crate::jwt::JwtValidation;
use crate::kdf::KeyRing;
use crate::otp::OtpHasher;
use crate::password::PasswordHasher;

/// The crypto services of the process. Cheap to clone.
#[derive(Debug, Clone)]
pub struct CryptoServices {
    /// Password hashing (CRY-01 … CRY-05).
    pub passwords: PasswordHasher,
    /// Purpose sub-keys (CRY-11).
    pub keys: KeyRing,
    /// OTP storage hashes (CRY-07).
    pub otp: OtpHasher,
    /// Envelope encryption (CRY-08).
    pub envelopes: EnvelopeCipher,
    /// JWT clock-skew tolerance (CRY-09).
    pub jwt_leeway: Duration,
}

impl CryptoServices {
    /// Builds every service; fails fast on invalid key material (ARC-07).
    pub async fn from_config(config: &CryptoConfig) -> Result<Self, CryptoError> {
        let keys = KeyRing::from_config(config)?;
        Ok(Self {
            passwords: PasswordHasher::from_config(config).await?,
            otp: OtpHasher::new(&keys)?,
            keys,
            envelopes: EnvelopeCipher::from_config(config)?,
            jwt_leeway: config.jwt_leeway,
        })
    }

    /// Access-token validation with the configured leeway.
    #[must_use]
    pub fn access_token_validation(
        &self,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> JwtValidation {
        JwtValidation::access_token(issuer, audience).with_leeway(self.jwt_leeway)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeContext;

    #[tokio::test]
    async fn arc_07_services_from_test_config() {
        let config = authn_testkit::config::test_config();
        let services = CryptoServices::from_config(&config.crypto).await.unwrap();
        let ctx = EnvelopeContext::new("t", "c", "r").unwrap();
        let sealed = services.envelopes.seal(b"x", &ctx).await.unwrap();
        assert_eq!(
            services
                .envelopes
                .open(&sealed, &ctx)
                .await
                .unwrap()
                .expose(),
            b"x"
        );
        assert_eq!(
            services.access_token_validation("i", "a").leeway,
            config.crypto.jwt_leeway
        );
        let debug = format!("{services:?}");
        assert!(!debug.contains(authn_testkit::config::TEST_KEK_1));
        assert!(!debug.contains(authn_testkit::config::TEST_PEPPER_V1));
    }

    #[tokio::test]
    async fn arc_07_invalid_key_material_fails_fast() {
        let mut config = authn_testkit::config::test_config();
        config.crypto.hmac_root_key = secrecy::SecretString::from("c2hvcnQ=".to_owned());
        assert_eq!(
            CryptoServices::from_config(&config.crypto)
                .await
                .unwrap_err(),
            CryptoError::InvalidKey
        );
    }
}
