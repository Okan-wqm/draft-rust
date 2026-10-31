use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{
    CaptchaChallenge, CaptchaContext, CaptchaProvider, CaptchaVerdict, CaptchaVerifier,
};

use super::lock;

/// CAPTCHA fake: the response `"pass"` passes, anything else fails; the
/// verdict can be forced (e.g. `Unavailable`).
#[derive(Debug, Default)]
pub struct FakeCaptcha {
    forced: Mutex<Option<CaptchaVerdict>>,
    verified: Mutex<Vec<String>>,
}

impl FakeCaptcha {
    /// Forces every verification to return `verdict` (`None` restores the
    /// default behaviour).
    pub fn force(&self, verdict: Option<CaptchaVerdict>) {
        *lock(&self.forced) = verdict;
    }

    /// Responses verified so far.
    #[must_use]
    pub fn verified(&self) -> Vec<String> {
        lock(&self.verified).clone()
    }
}

#[async_trait]
impl CaptchaVerifier for FakeCaptcha {
    fn provider(&self) -> CaptchaProvider {
        CaptchaProvider::Turnstile
    }

    async fn issue_challenge(&self, _ctx: &CaptchaContext) -> Result<CaptchaChallenge, AuthError> {
        Ok(CaptchaChallenge::Widget {
            provider: CaptchaProvider::Turnstile,
            site_key: "test-site-key".to_owned(),
        })
    }

    async fn verify(
        &self,
        response: &str,
        _ctx: &CaptchaContext,
    ) -> Result<CaptchaVerdict, AuthError> {
        lock(&self.verified).push(response.to_owned());
        if let Some(verdict) = *lock(&self.forced) {
            return Ok(verdict);
        }
        Ok(if response == "pass" {
            CaptchaVerdict::Passed
        } else {
            CaptchaVerdict::Failed
        })
    }
}
