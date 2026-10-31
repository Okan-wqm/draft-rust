//! Owner: authn-crypto (CRY-06, CRY-07, MFA-01). TST-04: parsers of
//! user-supplied secrets: opaque tokens, OTP codes, TOTP codes and base32
//! secrets, webhook secrets, KEK ids.
#![no_main]

use std::sync::OnceLock;

use authn_crypto::envelope::KekId;
use authn_crypto::otp::OtpCode;
use authn_crypto::token::{OpaqueToken, TOKEN_LEN};
use authn_crypto::totp::{Totp, TotpParams, TotpSecret};
use authn_crypto::webhook::WebhookSecret;
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

fn totp() -> &'static (Totp, TotpSecret) {
    static TOTP: OnceLock<(Totp, TotpSecret)> = OnceLock::new();
    TOTP.get_or_init(|| {
        (
            Totp::new(TotpParams::default()).expect("params"),
            TotpSecret::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").expect("secret"),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(token) = OpaqueToken::parse(text) {
        assert_eq!(token.expose(), text);
        assert_eq!(text.len(), TOKEN_LEN);
        assert!(token.matches(&token.hash()));
    }
    if let Ok(code) = OtpCode::parse(text) {
        assert_eq!(code.expose().len(), 6);
        assert!(code.expose().bytes().all(|b| b.is_ascii_digit()));
    }
    if let Ok(secret) = TotpSecret::from_base32(text) {
        assert_eq!(TotpSecret::from_base32(&secret.to_base32()).expect("round trip"), secret);
    }
    let (totp, secret) = totp();
    let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time");
    if let Ok(Some(step)) = totp.verify(secret, text, at, None) {
        assert_eq!(&*totp.code_for_step(secret, step).expect("code"), text);
    }
    if let Ok(secret) = WebhookSecret::parse(text) {
        assert_eq!(WebhookSecret::parse(&secret.to_text()).expect("round trip"), secret);
    }
    if let Ok(id) = KekId::new(text) {
        assert_eq!(id.as_str(), text);
    }
});
