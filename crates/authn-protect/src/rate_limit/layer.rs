//! Coarse per-IP HTTP rate limit (PRT-02 IP dimension, PRT-04), for the
//! "rate limit" slot of the OPS-02 middleware order.

use std::sync::Arc;

use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::ports::{RateLimitKey, RateLimitPolicy, RateLimiter};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Action name of the HTTP-level limiter keys.
pub const HTTP_ACTION: &str = "http";

/// State of [`http_rate_limit`].
///
/// Install (inside the request-context middleware, which provides the
/// client IP):
///
/// ```ignore
/// router.layer(axum::middleware::from_fn_with_state(
///     HttpRateLimit::new(limiter, config.protect.rate_limit.requests_per_ip),
///     authn_protect::rate_limit::http_rate_limit,
/// ))
/// ```
#[derive(Clone)]
pub struct HttpRateLimit {
    limiter: Arc<dyn RateLimiter>,
    policy: RateLimitPolicy,
    exempt_prefixes: Arc<[String]>,
    fail_open: bool,
}

impl std::fmt::Debug for HttpRateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRateLimit")
            .field("policy", &self.policy)
            .field("exempt_prefixes", &self.exempt_prefixes)
            .field("fail_open", &self.fail_open)
            .finish_non_exhaustive()
    }
}

impl HttpRateLimit {
    /// Per-IP `policy` on every request except `/health/…`. Limiter
    /// failures let the request through (this layer is a coarse flood guard;
    /// security-relevant per-action limits fail closed in their modules).
    #[must_use]
    pub fn new(limiter: Arc<dyn RateLimiter>, policy: RateLimitPolicy) -> Self {
        Self {
            limiter,
            policy,
            exempt_prefixes: Arc::from(vec!["/health/".to_owned()]),
            fail_open: true,
        }
    }

    /// Replaces the exempt path prefixes.
    #[must_use]
    pub fn with_exempt_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.exempt_prefixes = Arc::from(prefixes);
        self
    }

    /// Whether limiter errors let requests through (default) or fail them
    /// with `service_unavailable`.
    #[must_use]
    pub fn fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }
}

/// The middleware: `429 rate_limited` + `Retry-After` once the client IP
/// (IPv6 aggregated to /64) exceeds the policy.
pub async fn http_rate_limit(
    State(state): State<HttpRateLimit>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if state
        .exempt_prefixes
        .iter()
        .any(|p| path.starts_with(p.as_str()))
    {
        return next.run(request).await;
    }
    let Some(ip) = request
        .extensions()
        .get::<RequestContext>()
        .map(|ctx| ctx.client_ip)
    else {
        return AuthError::internal("request context middleware must run before the rate limit")
            .into_response();
    };
    let key = RateLimitKey::ip(HTTP_ACTION, ip);
    match state.limiter.check(&key, state.policy, 1).await {
        Ok(decision) if decision.allowed => next.run(request).await,
        Ok(decision) => {
            metrics::counter!("authn_rate_limit_triggered_total", "action" => HTTP_ACTION)
                .increment(1);
            match decision.into_result() {
                Ok(_) => next.run(request).await,
                Err(err) => err.into_response(),
            }
        }
        Err(err) if state.fail_open => {
            tracing::warn!(error = %err, "HTTP rate limiter unavailable; failing open");
            next.run(request).await
        }
        Err(err) => AuthError::new(codes::common::SERVICE_UNAVAILABLE)
            .with_context(format!("rate limiter: {err}"))
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use authn_testkit::FakeClock;
    use authn_testkit::fakes::DenyAllRateLimiter;
    use authn_testkit::http::{TestRequest, with_request_context};
    use axum::Router;
    use axum::routing::get;
    use http::StatusCode;

    use super::*;
    use crate::keys::test_support::hasher;
    use crate::rate_limit::MemoryRateLimiter;

    fn app(limiter: Arc<dyn RateLimiter>, policy: RateLimitPolicy) -> Router {
        let router = Router::new()
            .route("/v1/thing", get(|| async { "ok" }))
            .route("/health/live", get(|| async { "live" }))
            .layer(axum::middleware::from_fn_with_state(
                HttpRateLimit::new(limiter, policy),
                http_rate_limit,
            ));
        with_request_context(router)
    }

    #[tokio::test]
    async fn prt_04_http_layer_answers_429_with_retry_after() {
        let clock = Arc::new(FakeClock::new());
        let limiter = Arc::new(MemoryRateLimiter::new(clock.clone(), hasher()));
        let app = app(limiter, RateLimitPolicy::new(2, Duration::from_secs(60)));
        let a = "198.51.100.1".parse().unwrap();
        let b = "198.51.100.2".parse().unwrap();
        for _ in 0..2 {
            TestRequest::get("/v1/thing")
                .peer_ip(a)
                .send(&app)
                .await
                .assert_status(StatusCode::OK);
        }
        let res = TestRequest::get("/v1/thing").peer_ip(a).send(&app).await;
        res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        assert_eq!(res.header("retry-after"), Some("30"));
        // Other clients and health probes are unaffected.
        TestRequest::get("/v1/thing")
            .peer_ip(b)
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
        TestRequest::get("/health/live")
            .peer_ip(a)
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
        clock.advance(Duration::from_secs(30));
        TestRequest::get("/v1/thing")
            .peer_ip(a)
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn prt_02_ipv6_clients_share_their_slash_64_budget() {
        let limiter = Arc::new(DenyAllRateLimiter::default());
        let deny_all = app(limiter, RateLimitPolicy::new(1, Duration::from_secs(60)));
        let res = TestRequest::get("/v1/thing")
            .peer_ip("2001:db8::1".parse().unwrap())
            .send(&deny_all)
            .await;
        res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        assert_eq!(res.header("retry-after"), Some("60"));

        let clock = Arc::new(FakeClock::new());
        let limiter = Arc::new(MemoryRateLimiter::new(clock, hasher()));
        let memory = app(limiter, RateLimitPolicy::new(1, Duration::from_secs(60)));
        TestRequest::get("/v1/thing")
            .peer_ip("2001:db8:0:1::1".parse().unwrap())
            .send(&memory)
            .await
            .assert_status(StatusCode::OK);
        TestRequest::get("/v1/thing")
            .peer_ip("2001:db8:0:1:ffff::9".parse().unwrap())
            .send(&memory)
            .await
            .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
}
