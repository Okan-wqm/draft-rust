//! CAPTCHA (PRT-05, ACC-13): verifiers and the policy gate.
//!
//! * [`SiteVerifyCaptcha`] — Cloudflare Turnstile and hCaptcha.
//! * [`ProofOfWorkCaptcha`] — self-hosted, HMAC-signed, single-use
//!   proof-of-work.
//! * [`DisabledCaptcha`] — no provider configured.
//! * [`CaptchaService`] — applies a [`CaptchaPolicy`] (`always` /
//!   `risk_based` / `never`), the provider fail mode (`fail_open`), audits
//!   failures (throttled) and serves `GET /v1/captcha/challenge`.

mod pow;
mod siteverify;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::common::CaptchaPolicy;
use authn_core::config::protect::CaptchaConfig;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::ports::{
    Actor, AuditSink, CaptchaChallenge, CaptchaContext, CaptchaProvider, CaptchaVerdict,
    CaptchaVerifier, Clock, HttpClient, RateLimitKey, RateLimitPolicy, RateLimiter, SecurityEvent,
    SecurityEventKind,
};
use authn_crypto::kdf::KeyRing;
use sqlx::PgPool;

pub use pow::{PURGE_GRACE, ProofOfWorkCaptcha, is_valid_action, leading_zero_bits, solve};
pub use siteverify::{HCAPTCHA_VERIFY_URL, SiteVerifyCaptcha, TURNSTILE_VERIFY_URL};

/// Actions accepted by `GET /v1/captcha/challenge`. Modules that protect
/// other actions pass them to [`CaptchaService::with_endpoint_actions`].
pub const DEFAULT_ENDPOINT_ACTIONS: &[&str] = &[
    "login",
    "register",
    "password_reset",
    "magic_link",
    "login_code",
    "email_verification",
    "phone_verification",
];

/// Rate-limit action of the challenge endpoint.
pub const CHALLENGE_ACTION: &str = "captcha_challenge";
const AUDIT_THROTTLE: Duration = Duration::from_secs(15 * 60);

/// The verifier when no provider is configured: no challenge, every
/// response passes. [`CaptchaService`] never *requires* a CAPTCHA with this
/// provider (configuration refuses `login_policy = "always"` without one).
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledCaptcha;

#[async_trait]
impl CaptchaVerifier for DisabledCaptcha {
    fn provider(&self) -> CaptchaProvider {
        CaptchaProvider::Disabled
    }

    async fn issue_challenge(&self, _ctx: &CaptchaContext) -> Result<CaptchaChallenge, AuthError> {
        Ok(CaptchaChallenge::None)
    }

    async fn verify(
        &self,
        _response: &str,
        _ctx: &CaptchaContext,
    ) -> Result<CaptchaVerdict, AuthError> {
        Ok(CaptchaVerdict::Passed)
    }
}

/// Builds the configured verifier (`protect.captcha.provider`).
pub fn build_captcha_verifier(
    config: &CaptchaConfig,
    http: Arc<dyn HttpClient>,
    pool: PgPool,
    clock: Arc<dyn Clock>,
    keys: &KeyRing,
) -> Result<Arc<dyn CaptchaVerifier>, AuthError> {
    match config.provider {
        CaptchaProvider::Disabled => Ok(Arc::new(DisabledCaptcha)),
        CaptchaProvider::ProofOfWork => Ok(Arc::new(ProofOfWorkCaptcha::new(
            pool,
            clock,
            keys,
            config.pow_difficulty,
            config.pow_ttl,
        )?)),
        provider @ (CaptchaProvider::Turnstile | CaptchaProvider::HCaptcha) => {
            let site_key = config
                .site_key
                .clone()
                .ok_or_else(|| AuthError::internal("protect.captcha.site_key is required"))?;
            let secret = config
                .secret_key
                .clone()
                .ok_or_else(|| AuthError::internal("protect.captcha.secret_key is required"))?;
            Ok(Arc::new(SiteVerifyCaptcha::new(
                provider,
                site_key,
                secret,
                config.verify_url.as_deref(),
                http,
            )?))
        }
    }
}

/// The CAPTCHA gate used by login (authn-session), registration
/// (authn-account) and the challenge endpoint. Cheap to clone.
#[derive(Clone)]
pub struct CaptchaService {
    verifier: Arc<dyn CaptchaVerifier>,
    limiter: Arc<dyn RateLimiter>,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
    fail_open: bool,
    challenge_per_ip: RateLimitPolicy,
    endpoint_actions: Arc<[&'static str]>,
}

impl std::fmt::Debug for CaptchaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaService")
            .field("provider", &self.verifier.provider())
            .field("fail_open", &self.fail_open)
            .finish_non_exhaustive()
    }
}

impl CaptchaService {
    /// A gate over `verifier` with the `[protect.captcha]` settings.
    #[must_use]
    pub fn new(
        verifier: Arc<dyn CaptchaVerifier>,
        limiter: Arc<dyn RateLimiter>,
        audit: Arc<dyn AuditSink>,
        clock: Arc<dyn Clock>,
        config: &CaptchaConfig,
    ) -> Self {
        Self {
            verifier,
            limiter,
            audit,
            clock,
            fail_open: config.fail_open,
            challenge_per_ip: config.challenge_per_ip,
            endpoint_actions: Arc::from(DEFAULT_ENDPOINT_ACTIONS.to_vec()),
        }
    }

    /// Replaces the actions accepted by the challenge endpoint.
    #[must_use]
    pub fn with_endpoint_actions(mut self, actions: &[&'static str]) -> Self {
        self.endpoint_actions = Arc::from(
            actions
                .iter()
                .copied()
                .filter(|a| is_valid_action(a))
                .collect::<Vec<_>>(),
        );
        self
    }

    /// The configured provider.
    #[must_use]
    pub fn provider(&self) -> CaptchaProvider {
        self.verifier.provider()
    }

    /// Whether `policy` demands a CAPTCHA now. `risky` is the caller's
    /// signal (failure counters, risk level). A disabled provider never
    /// demands one.
    #[must_use]
    pub fn is_required(&self, policy: CaptchaPolicy, risky: bool) -> bool {
        self.provider() != CaptchaProvider::Disabled
            && match policy {
                CaptchaPolicy::Always => true,
                CaptchaPolicy::RiskBased => risky,
                CaptchaPolicy::Never => false,
            }
    }

    /// A challenge for `action` (no rate limit; see the endpoint).
    pub async fn challenge(
        &self,
        action: &'static str,
        ip: IpAddr,
    ) -> Result<CaptchaChallenge, AuthError> {
        self.verifier
            .issue_challenge(&CaptchaContext { action, ip })
            .await
    }

    /// The challenge endpoint's logic: per-IP rate limit, known action.
    pub async fn endpoint_challenge(
        &self,
        action: &str,
        ip: IpAddr,
    ) -> Result<CaptchaChallenge, AuthError> {
        let Some(action) = self.endpoint_actions.iter().copied().find(|a| *a == action) else {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("unknown captcha action"));
        };
        self.limiter
            .check(
                &RateLimitKey::ip(CHALLENGE_ACTION, ip),
                self.challenge_per_ip,
                1,
            )
            .await?
            .into_result()?;
        self.challenge(action, ip).await
    }

    /// Enforces `policy` for `action`.
    ///
    /// * not required → `Ok(())` (a supplied response is ignored);
    /// * required, no response → `captcha_required` with the challenge in
    ///   the envelope `details`;
    /// * wrong / expired / replayed → `captcha_failed` (with a fresh
    ///   challenge) and a throttled `protect.captcha_failed` audit event;
    /// * provider unreachable → `Ok(())` when `fail_open`, otherwise
    ///   `service_unavailable`.
    pub async fn enforce(
        &self,
        action: &'static str,
        policy: CaptchaPolicy,
        risky: bool,
        response: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        if !self.is_required(policy, risky) {
            return Ok(());
        }
        let captcha_ctx = CaptchaContext {
            action,
            ip: ctx.client_ip,
        };
        let Some(response) = response.filter(|r| !r.is_empty()) else {
            return Err(self
                .with_challenge(
                    AuthError::new(codes::protect::CAPTCHA_REQUIRED),
                    &captcha_ctx,
                )
                .await);
        };
        match self.verifier.verify(response, &captcha_ctx).await? {
            CaptchaVerdict::Passed => Ok(()),
            CaptchaVerdict::Failed => {
                let event = SecurityEvent::new(SecurityEventKind::CaptchaFailed, self.clock.now())
                    .with_context(ctx)
                    .with_actor(Actor::Anonymous)
                    .failed("captcha_failed")
                    .with_meta("action", action)
                    .with_meta("provider", self.provider().as_str());
                crate::audit::record_throttled(
                    &self.limiter,
                    &self.audit,
                    &RateLimitKey::ip("audit_captcha_failed", ctx.client_ip),
                    AUDIT_THROTTLE,
                    event,
                )
                .await;
                Err(self
                    .with_challenge(AuthError::new(codes::protect::CAPTCHA_FAILED), &captcha_ctx)
                    .await)
            }
            CaptchaVerdict::Unavailable if self.fail_open => {
                tracing::warn!(
                    action,
                    "captcha provider unavailable; failing open (configured)"
                );
                Ok(())
            }
            CaptchaVerdict::Unavailable => Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("captcha provider unavailable")),
        }
    }

    async fn with_challenge(&self, err: AuthError, ctx: &CaptchaContext) -> AuthError {
        match self.verifier.issue_challenge(ctx).await {
            Ok(challenge) => match serde_json::to_value(&challenge) {
                Ok(value) => err.with_details(serde_json::json!({ "challenge": value })),
                Err(_) => err,
            },
            Err(issue_err) => {
                tracing::warn!(error = %issue_err, "could not attach a captcha challenge");
                err
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use authn_core::domain::Locale;
    use authn_testkit::TestPorts;
    use authn_testkit::fakes::FakeCaptcha;

    use super::*;

    fn service(
        ports: &TestPorts,
        verifier: Arc<dyn CaptchaVerifier>,
        fail_open: bool,
    ) -> CaptchaService {
        let config = CaptchaConfig {
            fail_open,
            ..CaptchaConfig::default()
        };
        CaptchaService::new(
            verifier,
            ports.rate_limiter.clone(),
            ports.audit.clone(),
            ports.clock.clone(),
            &config,
        )
    }

    fn ctx() -> RequestContext {
        let mut ctx = RequestContext::system(Locale::En);
        ctx.client_ip = "198.51.100.44".parse().unwrap();
        ctx
    }

    #[tokio::test]
    async fn prt_05_policy_modes_always_risk_based_never() {
        let ports = TestPorts::new();
        let svc = service(&ports, ports.captcha.clone(), false);
        assert!(svc.is_required(CaptchaPolicy::Always, false));
        assert!(svc.is_required(CaptchaPolicy::RiskBased, true));
        assert!(!svc.is_required(CaptchaPolicy::RiskBased, false));
        assert!(!svc.is_required(CaptchaPolicy::Never, true));
        // Not required: no verification, even with a bogus response.
        svc.enforce("login", CaptchaPolicy::Never, true, Some("bogus"), &ctx())
            .await
            .unwrap();
        assert!(ports.captcha.verified().is_empty());

        let disabled = service(&ports, Arc::new(DisabledCaptcha), false);
        assert!(!disabled.is_required(CaptchaPolicy::Always, true));
        disabled
            .enforce("login", CaptchaPolicy::Always, true, None, &ctx())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prt_05_required_captcha_is_enforced_with_challenge_details() {
        let ports = TestPorts::new();
        let svc = service(&ports, ports.captcha.clone(), false);
        let err = svc
            .enforce("login", CaptchaPolicy::Always, false, None, &ctx())
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::protect::CAPTCHA_REQUIRED);
        assert_eq!(err.details().unwrap()["challenge"]["type"], "widget");
        assert_eq!(
            err.details().unwrap()["challenge"]["site_key"],
            "test-site-key"
        );

        let err = svc
            .enforce("login", CaptchaPolicy::Always, false, Some("wrong"), &ctx())
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::protect::CAPTCHA_FAILED);
        let audited = ports.audit.of_kind(SecurityEventKind::CaptchaFailed);
        assert_eq!(audited.len(), 1);
        assert_eq!(audited[0].ip, Some(ctx().client_ip));
        // Repeated failures are audited once per window (no amplification).
        for _ in 0..10 {
            let _ = svc
                .enforce("login", CaptchaPolicy::Always, false, Some("wrong"), &ctx())
                .await;
        }
        assert_eq!(
            ports.audit.of_kind(SecurityEventKind::CaptchaFailed).len(),
            1
        );

        svc.enforce("login", CaptchaPolicy::Always, false, Some("pass"), &ctx())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prt_05_provider_outage_follows_fail_mode() {
        let ports = TestPorts::new();
        let captcha = Arc::new(FakeCaptcha::default());
        captcha.force(Some(CaptchaVerdict::Unavailable));
        let closed = service(&ports, captcha.clone(), false);
        let err = closed
            .enforce("login", CaptchaPolicy::Always, false, Some("x"), &ctx())
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
        let open = service(&ports, captcha, true);
        open.enforce("login", CaptchaPolicy::Always, false, Some("x"), &ctx())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prt_05_challenge_endpoint_logic_is_rate_limited_and_action_checked() {
        let ports = TestPorts::new();
        let config = CaptchaConfig {
            challenge_per_ip: RateLimitPolicy::new(2, Duration::from_secs(60)),
            ..CaptchaConfig::default()
        };
        let svc = CaptchaService::new(
            ports.captcha.clone(),
            ports.rate_limiter.clone(),
            ports.audit.clone(),
            ports.clock.clone(),
            &config,
        );
        let ip = ctx().client_ip;
        let err = svc.endpoint_challenge("Login'--", ip).await.unwrap_err();
        assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
        svc.endpoint_challenge("login", ip).await.unwrap();
        svc.endpoint_challenge("register", ip).await.unwrap();
        let err = svc.endpoint_challenge("login", ip).await.unwrap_err();
        assert_eq!(err.code(), codes::common::RATE_LIMITED);
        assert!(err.retry_after().is_some());
        let custom = svc.with_endpoint_actions(&["sms_send", "Bad Name"]);
        assert!(
            custom
                .endpoint_challenge("login", "203.0.113.1".parse().unwrap())
                .await
                .is_err()
        );
        custom
            .endpoint_challenge("sms_send", "203.0.113.1".parse().unwrap())
            .await
            .unwrap();
    }
}
