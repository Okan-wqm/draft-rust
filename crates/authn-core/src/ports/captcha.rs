//! Bot protection (ACC-13, PRT-05). Owner of this file: authn-protect.
//!
//! Implementations: Cloudflare Turnstile, hCaptcha (server-side HTTP
//! verification) and a self-hosted proof-of-work (HMAC-signed, single-use,
//! difficulty adjustable). *When* a CAPTCHA is required is policy
//! (always / risk based / never) decided by authn-protect configuration.

use std::net::IpAddr;

use async_trait::async_trait;
use serde::Serialize;
use time::OffsetDateTime;

use crate::error::AuthError;

/// Verifies CAPTCHA responses.
#[async_trait]
pub trait CaptchaVerifier: Send + Sync {
    /// Which provider backs this verifier.
    fn provider(&self) -> CaptchaProvider;

    /// What the client must solve (widget site key or a PoW challenge).
    async fn issue_challenge(&self, ctx: &CaptchaContext) -> Result<CaptchaChallenge, AuthError>;

    /// Verifies a client response. Single use: a response can pass once.
    async fn verify(
        &self,
        response: &str,
        ctx: &CaptchaContext,
    ) -> Result<CaptchaVerdict, AuthError>;
}

text_enum! {
    /// CAPTCHA provider.
    pub enum CaptchaProvider {
        /// No CAPTCHA configured.
        Disabled => "disabled",
        /// Cloudflare Turnstile.
        Turnstile => "turnstile",
        /// hCaptcha.
        HCaptcha => "hcaptcha",
        /// Self-hosted proof of work.
        ProofOfWork => "proof_of_work",
    }
}

/// Context of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaContext {
    /// Protected action (`register`, `login`…), bound into PoW challenges.
    pub action: &'static str,
    /// Client IP (sent to providers that accept `remoteip`).
    pub ip: IpAddr,
}

/// What the client has to solve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaptchaChallenge {
    /// No CAPTCHA required / configured.
    None,
    /// Render a third-party widget.
    Widget {
        /// Provider.
        provider: CaptchaProvider,
        /// Public site key.
        site_key: String,
    },
    /// Solve a proof-of-work puzzle.
    ProofOfWork {
        /// Signed challenge string.
        challenge: String,
        /// Required leading zero bits.
        difficulty: u8,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
}

/// Result of a verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaVerdict {
    /// Valid response.
    Passed,
    /// Invalid, expired or replayed response.
    Failed,
    /// Provider unreachable; callers apply the configured fail mode.
    Unavailable,
}
