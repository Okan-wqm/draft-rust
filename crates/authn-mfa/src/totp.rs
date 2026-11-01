//! TOTP enrollment material (MFA-01): parameters from the configuration,
//! the `otpauth://` URI and its QR code as SVG.
//!
//! The RFC 6238 computation, the constant-time window scan and the replay
//! guard (`last_used_step`, MFA-02) live in `authn_crypto::totp`; this module
//! only prepares what the user's authenticator app needs.

use std::fmt;

use authn_core::config::mfa::TotpConfig;
use authn_core::error::AuthError;
use authn_crypto::totp::{Totp, TotpAlgorithm, TotpParams, TotpSecret};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use zeroize::Zeroizing;

/// Smallest rendered QR code (pixels per side).
const QR_MIN_PIXELS: u32 = 240;

/// The TOTP verifier for a stored factor (digits / period as stored at
/// enrollment, skew from the current configuration).
pub fn totp_for(digits: u32, period_secs: u32, skew: u32) -> Result<Totp, AuthError> {
    Totp::new(TotpParams {
        algorithm: TotpAlgorithm::Sha1,
        digits,
        period: period_secs,
        skew,
    })
    .map_err(|e| AuthError::internal("invalid TOTP parameters").with_source(e))
}

/// The TOTP verifier for new enrollments (`[mfa.totp]`).
pub fn totp_from_config(config: &TotpConfig) -> Result<Totp, AuthError> {
    let period = u32::try_from(config.period.as_secs())
        .map_err(|_| AuthError::internal("mfa.totp.period out of range"))?;
    totp_for(config.digits, period, config.skew_steps)
}

/// What the user's authenticator app needs. Every field contains the
/// shared secret: shown exactly once, never logged (redacted `Debug`).
pub struct TotpProvisioning {
    /// Base32 secret for manual entry.
    pub secret_base32: Zeroizing<String>,
    /// `otpauth://totp/...` Key URI.
    pub otpauth_uri: Zeroizing<String>,
    /// The URI as a QR code (SVG document).
    pub qr_svg: Zeroizing<String>,
}

impl fmt::Debug for TotpProvisioning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpProvisioning").finish_non_exhaustive()
    }
}

/// Builds the provisioning material for `secret`.
pub fn provisioning(
    totp: &Totp,
    secret: &TotpSecret,
    issuer: &str,
    account: &str,
) -> Result<TotpProvisioning, AuthError> {
    let otpauth_uri = totp
        .provisioning_uri(secret, issuer, account)
        .map_err(|e| AuthError::internal("otpauth URI").with_source(e))?;
    let qr_svg = qr_svg(&otpauth_uri)?;
    Ok(TotpProvisioning {
        secret_base32: secret.to_base32(),
        otpauth_uri,
        qr_svg,
    })
}

/// Renders `data` as a QR code SVG (error correction M).
pub fn qr_svg(data: &str) -> Result<Zeroizing<String>, AuthError> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .map_err(|e| AuthError::internal("QR encoding failed").with_source(e))?;
    Ok(Zeroizing::new(
        code.render::<svg::Color<'_>>()
            .min_dimensions(QR_MIN_PIXELS, QR_MIN_PIXELS)
            .quiet_zone(true)
            .build(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_01_provisioning_uri_and_qr_svg() {
        let config = TotpConfig::default();
        let totp = totp_from_config(&config).unwrap();
        let secret = TotpSecret::generate().unwrap();
        let p = provisioning(&totp, &secret, &config.issuer, "alice@example.com").unwrap();
        assert_eq!(p.secret_base32.len(), 32, "160-bit secret in base32");
        assert!(
            p.otpauth_uri
                .starts_with("otpauth://totp/rust-authentication:alice%40example.com?secret=")
        );
        assert!(p.otpauth_uri.contains("&digits=6&period=30"));
        assert!(p.otpauth_uri.contains("algorithm=SHA1"));
        assert!(p.qr_svg.starts_with("<?xml"));
        assert!(p.qr_svg.contains("<svg"));
        assert!(p.qr_svg.ends_with("</svg>"));
        assert!(!format!("{p:?}").contains(p.secret_base32.as_str()));
    }

    #[test]
    fn mfa_01_stored_parameters_are_validated() {
        assert!(totp_for(6, 30, 1).is_ok());
        assert!(totp_for(5, 30, 1).is_err());
        assert!(totp_for(6, 0, 1).is_err());
    }
}
