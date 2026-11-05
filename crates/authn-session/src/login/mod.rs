//! The login flows (SES-01, SES-02, SES-18 … SES-22, RSK-03, RSK-04,
//! MFA-09).
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`pipeline`] | SES-01, SES-21, SES-22, RSK-03, RSK-04, MFA-09 | the decision after the primary authentication (account → organization → MFA → risk → trusted device → session or challenge) |
//! | `password` | SES-01, PRT-02 … PRT-05, PWD-12 | `POST /v1/login/password` |
//! | `challenge` | SES-02, SES-22, MFA-01 … MFA-09 | completing a pending login: second factor, required actions |
//! | `passwordless` | SES-18, SES-19 | magic link and e-mail code |
//! | `passkey` | SES-20, SES-21 | username-less passkey login, conditional UI |
//! | `not_me` | RSK-04 | the "this wasn't me" link ([`authn_protect::NotMeTokenIssuer`]) |
//! | [`routes`] | — | HTTP endpoints, merged into [`crate::router`] |
//!
//! Every endpoint takes the login-CSRF proof for web clients
//! ([`crate::SessionService::verify_login_csrf_request`]) and answers with
//! [`crate::response::credentials_response`] or
//! [`crate::response::challenge_response`].

mod challenge;
mod not_me;
mod passkey;
mod password;
mod passwordless;
pub mod pipeline;
pub mod routes;

use authn_core::secret::SensitiveString;
use axum::http::HeaderMap;

pub use self::challenge::{
    ChallengeOutcome, ChallengeStep, FactorSubmission, PasskeyEnrollmentVerify, SendCodeChannel,
};
pub use self::not_me::{NOT_ME_TTL, NotMeRequest};
pub use self::passkey::{PasskeyLogin, PasskeyLoginOptions, PasskeyLoginStart};
pub use self::password::PasswordLogin;
pub use self::passwordless::{
    EmailCodeStart, EmailCodeVerify, MagicLinkRequest, MagicLinkStart, MagicLinkVerify,
};
pub use self::pipeline::{LoginSignals, PipelineOutcome};

use crate::cookies::{CookieValue, read_cookie};

/// Cookie binding a magic-link request to the browser that made it
/// (SES-18): `HttpOnly; Secure; SameSite=Lax` — the link is opened by a
/// top-level navigation from the mail client.
pub const MAGIC_LINK_BINDING_COOKIE: &str = "__Host-authn_magic";

/// The trusted-device token of the request (MFA-09): the
/// `__Host-authn_trusted_device` cookie (web) or the `x-trusted-device`
/// header (native). Ambiguous (repeated) values are ignored.
#[must_use]
pub fn trusted_device_token(headers: &HeaderMap) -> Option<SensitiveString> {
    if let CookieValue::One(value) = read_cookie(headers, authn_mfa::TRUSTED_DEVICE_COOKIE) {
        return Some(SensitiveString::new(value));
    }
    let mut values = headers.get_all(authn_mfa::TRUSTED_DEVICE_HEADER).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first
        .to_str()
        .ok()
        .filter(|v| !v.is_empty() && v.len() <= 1024)
        .map(|v| SensitiveString::new(v.to_owned()))
}

/// A single cookie value or `None` (absent or ambiguous).
pub(crate) fn single_cookie(headers: &HeaderMap, name: &str) -> Option<SensitiveString> {
    match read_cookie(headers, name) {
        CookieValue::One(value) => Some(SensitiveString::new(value)),
        _ => None,
    }
}
