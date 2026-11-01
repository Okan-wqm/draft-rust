//! Cloudflare Turnstile and hCaptcha server-side verification (PRT-05).
//!
//! Both providers expose a `siteverify` endpoint taking the secret, the
//! client token and (optionally) the client IP as a form post, and answer
//! `{"success": bool, "error-codes": [...], ...}`. Tokens are single use on
//! the provider side (`timeout-or-duplicate`). The call goes through the
//! [`HttpClient`] port as a *trusted* (operator-configured) target, so
//! timeouts and size limits apply.

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{
    CaptchaChallenge, CaptchaContext, CaptchaProvider, CaptchaVerdict, CaptchaVerifier, HttpClient,
    OutboundRequest, OutboundTarget,
};
use authn_core::secret::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

/// Cloudflare Turnstile verification endpoint.
pub const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
/// hCaptcha verification endpoint.
pub const HCAPTCHA_VERIFY_URL: &str = "https://api.hcaptcha.com/siteverify";

/// Longest client token forwarded to a provider (Turnstile tokens are at
/// most 2048 characters); longer input fails without an outbound call.
const MAX_TOKEN_BYTES: usize = 4096;

/// Verifier for Turnstile / hCaptcha.
pub struct SiteVerifyCaptcha {
    provider: CaptchaProvider,
    site_key: String,
    secret: SecretString,
    verify_url: Url,
    http: Arc<dyn HttpClient>,
}

impl std::fmt::Debug for SiteVerifyCaptcha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteVerifyCaptcha")
            .field("provider", &self.provider)
            .field("site_key", &self.site_key)
            .field("secret", &authn_core::secret::REDACTED)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct SiteVerifyResponse {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
    /// Turnstile only: the widget's `data-action`.
    #[serde(default)]
    action: Option<String>,
}

impl SiteVerifyCaptcha {
    /// A verifier for `provider` (`Turnstile` or `HCaptcha`).
    /// `verify_url` overrides the provider endpoint (tests only).
    pub fn new(
        provider: CaptchaProvider,
        site_key: String,
        secret: SecretString,
        verify_url: Option<&str>,
        http: Arc<dyn HttpClient>,
    ) -> Result<Self, AuthError> {
        let default_url = match provider {
            CaptchaProvider::Turnstile => TURNSTILE_VERIFY_URL,
            CaptchaProvider::HCaptcha => HCAPTCHA_VERIFY_URL,
            CaptchaProvider::Disabled | CaptchaProvider::ProofOfWork => {
                return Err(AuthError::internal(
                    "siteverify needs Turnstile or hCaptcha",
                ));
            }
        };
        let verify_url = Url::parse(verify_url.unwrap_or(default_url))
            .map_err(|_| AuthError::internal("invalid captcha verify URL"))?;
        Ok(Self {
            provider,
            site_key,
            secret,
            verify_url,
            http,
        })
    }

    fn form(&self, token: &str, ctx: &CaptchaContext) -> Vec<u8> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("secret", self.secret.expose_secret())
            .append_pair("response", token)
            .append_pair("remoteip", &ctx.ip.to_string());
        if self.provider == CaptchaProvider::HCaptcha {
            // hCaptcha checks that the token was issued for this site key.
            form.append_pair("sitekey", &self.site_key);
        }
        form.finish().into_bytes()
    }
}

/// Statuses that mean "the provider could not decide": server errors, rate
/// limiting / timeouts, and a 2xx whose body is not a verdict.
fn is_outage(status: http::StatusCode) -> bool {
    status.is_server_error()
        || status.is_success()
        || status == http::StatusCode::TOO_MANY_REQUESTS
        || status == http::StatusCode::REQUEST_TIMEOUT
}

fn plausible_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|b| b.is_ascii_graphic())
}

#[async_trait]
impl CaptchaVerifier for SiteVerifyCaptcha {
    fn provider(&self) -> CaptchaProvider {
        self.provider
    }

    async fn issue_challenge(&self, _ctx: &CaptchaContext) -> Result<CaptchaChallenge, AuthError> {
        Ok(CaptchaChallenge::Widget {
            provider: self.provider,
            site_key: self.site_key.clone(),
        })
    }

    async fn verify(
        &self,
        response: &str,
        ctx: &CaptchaContext,
    ) -> Result<CaptchaVerdict, AuthError> {
        if !plausible_token(response) {
            return Ok(CaptchaVerdict::Failed);
        }
        let mut request = OutboundRequest::post(
            self.verify_url.clone(),
            self.form(response, ctx),
            OutboundTarget::Trusted,
        );
        request.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        request.headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
        request.max_response_bytes = Some(16 * 1024);
        let response = match self.http.execute(request).await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(provider = %self.provider, error = %err, "captcha provider unreachable");
                return Ok(CaptchaVerdict::Unavailable);
            }
        };
        let status = response.status;
        let parsed = serde_json::from_slice::<SiteVerifyResponse>(&response.body).ok();
        // Only a real outage is `Unavailable` (which `fail_open` turns into a
        // pass). A provider that *answered* — a definitive `success: false`
        // on any status, or a client-error status — has rejected the token:
        // `Failed`, never `Unavailable`, or an attacker-chosen token that
        // makes the provider answer 4xx would bypass the CAPTCHA.
        let body = match parsed {
            Some(body) if !body.success || status.is_success() => body,
            _ if is_outage(status) => {
                tracing::warn!(provider = %self.provider, status = %status, "captcha provider error");
                return Ok(CaptchaVerdict::Unavailable);
            }
            _ => {
                tracing::debug!(provider = %self.provider, status = %status, "captcha provider rejected the request");
                return Ok(CaptchaVerdict::Failed);
            }
        };
        if !body.success {
            // Provider error codes are stable identifiers, safe to log.
            tracing::debug!(provider = %self.provider, codes = ?body.error_codes, "captcha rejected");
            if body
                .error_codes
                .iter()
                .any(|c| c == "invalid-input-secret" || c == "missing-input-secret")
            {
                tracing::error!(provider = %self.provider, "captcha secret key rejected by provider");
                return Ok(CaptchaVerdict::Unavailable);
            }
            return Ok(CaptchaVerdict::Failed);
        }
        // A token solved for another action (e.g. a newsletter form) must not
        // unlock the login (Turnstile reports the widget action).
        if let Some(action) = body.action.as_deref()
            && !action.is_empty()
            && action != ctx.action
        {
            tracing::debug!(provider = %self.provider, "captcha token issued for another action");
            return Ok(CaptchaVerdict::Failed);
        }
        Ok(CaptchaVerdict::Passed)
    }
}

#[cfg(test)]
mod tests {
    use authn_testkit::fakes::FakeHttpClient;
    use http::{Method, StatusCode};

    use super::*;

    fn ctx() -> CaptchaContext {
        CaptchaContext {
            action: "login",
            ip: "198.51.100.5".parse().unwrap(),
        }
    }

    fn verifier(provider: CaptchaProvider, http: Arc<FakeHttpClient>) -> SiteVerifyCaptcha {
        SiteVerifyCaptcha::new(
            provider,
            "site-key".to_owned(),
            SecretString::from("top-secret".to_owned()),
            None,
            http,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn prt_05_turnstile_success_sends_secret_token_and_ip() {
        let http = Arc::new(FakeHttpClient::default());
        http.respond_json(
            Method::POST,
            TURNSTILE_VERIFY_URL,
            StatusCode::OK,
            &serde_json::json!({"success": true, "action": "login", "error-codes": []}),
        );
        let v = verifier(CaptchaProvider::Turnstile, http.clone());
        assert_eq!(
            v.verify("tok-123", &ctx()).await.unwrap(),
            CaptchaVerdict::Passed
        );
        let sent = http.requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].target, OutboundTarget::Trusted);
        let body = String::from_utf8(sent[0].body.clone().unwrap()).unwrap();
        assert!(body.contains("secret=top-secret"));
        assert!(body.contains("response=tok-123"));
        assert!(body.contains("remoteip=198.51.100.5"));
        assert!(!format!("{v:?}").contains("top-secret"));
        assert_eq!(
            v.issue_challenge(&ctx()).await.unwrap(),
            CaptchaChallenge::Widget {
                provider: CaptchaProvider::Turnstile,
                site_key: "site-key".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn prt_05_turnstile_rejects_replayed_or_foreign_action_tokens() {
        let http = Arc::new(FakeHttpClient::default());
        http.respond_json(
            Method::POST,
            TURNSTILE_VERIFY_URL,
            StatusCode::OK,
            &serde_json::json!({"success": false, "error-codes": ["timeout-or-duplicate"]}),
        );
        let v = verifier(CaptchaProvider::Turnstile, http.clone());
        assert_eq!(
            v.verify("tok", &ctx()).await.unwrap(),
            CaptchaVerdict::Failed
        );

        let http = Arc::new(FakeHttpClient::default());
        http.respond_json(
            Method::POST,
            TURNSTILE_VERIFY_URL,
            StatusCode::OK,
            &serde_json::json!({"success": true, "action": "newsletter"}),
        );
        let v = verifier(CaptchaProvider::Turnstile, http);
        assert_eq!(
            v.verify("tok", &ctx()).await.unwrap(),
            CaptchaVerdict::Failed
        );
    }

    #[tokio::test]
    async fn prt_05_hcaptcha_binds_site_key_and_maps_outages_to_unavailable() {
        let http = Arc::new(FakeHttpClient::default());
        http.respond_json(
            Method::POST,
            HCAPTCHA_VERIFY_URL,
            StatusCode::OK,
            &serde_json::json!({"success": true}),
        );
        let v = verifier(CaptchaProvider::HCaptcha, http.clone());
        assert_eq!(
            v.verify("P1_abc", &ctx()).await.unwrap(),
            CaptchaVerdict::Passed
        );
        let body = String::from_utf8(http.requests()[0].body.clone().unwrap()).unwrap();
        assert!(body.contains("sitekey=site-key"));

        // Provider down / 5xx / garbage / bad secret → Unavailable.
        let down = verifier(
            CaptchaProvider::HCaptcha,
            Arc::new(FakeHttpClient::default()),
        );
        assert_eq!(
            down.verify("x", &ctx()).await.unwrap(),
            CaptchaVerdict::Unavailable
        );
        for (status, body) in [
            (StatusCode::BAD_GATEWAY, "{}".to_owned()),
            (StatusCode::OK, "<html>".to_owned()),
            (
                StatusCode::OK,
                r#"{"success":false,"error-codes":["invalid-input-secret"]}"#.to_owned(),
            ),
        ] {
            let http = Arc::new(FakeHttpClient::default());
            http.respond(Method::POST, HCAPTCHA_VERIFY_URL, status, body);
            let v = verifier(CaptchaProvider::HCaptcha, http);
            assert_eq!(
                v.verify("x", &ctx()).await.unwrap(),
                CaptchaVerdict::Unavailable
            );
        }
    }

    /// Regression (security review): a definitive rejection delivered with
    /// a non-2xx status used to map to `Unavailable`, which `fail_open`
    /// turns into a pass — a CAPTCHA bypass with any token that makes the
    /// provider answer 4xx.
    #[tokio::test]
    async fn prt_05_provider_rejections_on_error_statuses_never_count_as_outage() {
        for (status, body) in [
            (
                StatusCode::BAD_REQUEST,
                r#"{"success":false,"error-codes":["invalid-input-response"]}"#,
            ),
            (StatusCode::BAD_REQUEST, "bad request"),
            (StatusCode::FORBIDDEN, "{}"),
            (StatusCode::NOT_FOUND, "<html>"),
            (StatusCode::FOUND, ""),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"success":false,"error-codes":["invalid-input-response"]}"#,
            ),
            // A success flag on an error status is not trusted either.
            (StatusCode::BAD_REQUEST, r#"{"success":true}"#),
        ] {
            let http = Arc::new(FakeHttpClient::default());
            http.respond(Method::POST, TURNSTILE_VERIFY_URL, status, body.to_owned());
            let v = verifier(CaptchaProvider::Turnstile, http);
            assert_eq!(
                v.verify("tok", &ctx()).await.unwrap(),
                CaptchaVerdict::Failed,
                "{status} {body}"
            );
        }
        // Genuine outages stay `Unavailable` (fail mode applies).
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let http = Arc::new(FakeHttpClient::default());
            http.respond(
                Method::POST,
                TURNSTILE_VERIFY_URL,
                status,
                "oops".to_owned(),
            );
            let v = verifier(CaptchaProvider::Turnstile, http);
            assert_eq!(
                v.verify("tok", &ctx()).await.unwrap(),
                CaptchaVerdict::Unavailable,
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn prt_05_implausible_tokens_fail_without_outbound_call() {
        let http = Arc::new(FakeHttpClient::default());
        let v = verifier(CaptchaProvider::Turnstile, http.clone());
        for token in ["", "a b", "tok\n", &"x".repeat(MAX_TOKEN_BYTES + 1)] {
            assert_eq!(
                v.verify(token, &ctx()).await.unwrap(),
                CaptchaVerdict::Failed
            );
        }
        assert!(http.requests().is_empty());
    }
}
