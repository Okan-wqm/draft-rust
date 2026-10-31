//! Fakes for every port of `authn_core::ports`.
//!
//! Recording fakes keep every call in memory (inspect with `.recorded()` /
//! `.take()`); configurable fakes have setters. All are `Send + Sync` and
//! meant to be shared as `Arc`.

mod audit;
mod captcha;
mod dns;
mod email;
mod exporter;
mod geoip;
mod http_client;
mod notifier;
mod password;
mod rate_limit;
mod risk;
mod session;

use std::sync::Arc;

pub use audit::{RecordingAuditSink, RecordingEventPublisher};
pub use captcha::FakeCaptcha;
pub use dns::FakeDnsTxtResolver;
pub use email::{RecordingEmailTransport, RecordingSmsSender};
pub use exporter::StaticDataExporter;
pub use geoip::FakeGeoIp;
pub use http_client::FakeHttpClient;
pub use notifier::RecordingNotifier;
pub use password::{FakeBreachedPasswordChecker, FakePasswordValidator};
pub use rate_limit::{AllowAllRateLimiter, DenyAllRateLimiter, InMemoryRateLimiter};
pub use risk::FakeRiskEvaluator;
pub use session::{FakeSessionIssuer, RecordingSessionRevoker, RevocationCall};

use crate::clock::FakeClock;

/// One fake per port, wired to a shared [`FakeClock`].
///
/// Fields are concrete types (to inspect recordings); coerce to the trait
/// object where a service expects one: `ports.audit.clone() as Arc<dyn AuditSink>`.
#[derive(Clone)]
pub struct TestPorts {
    /// Clock shared by the time-aware fakes.
    pub clock: Arc<FakeClock>,
    /// `AuditSink`.
    pub audit: Arc<RecordingAuditSink>,
    /// `EventPublisher`.
    pub events: Arc<RecordingEventPublisher>,
    /// `Notifier`.
    pub notifier: Arc<RecordingNotifier>,
    /// `EmailTransport`.
    pub email: Arc<RecordingEmailTransport>,
    /// `SmsSender`.
    pub sms: Arc<RecordingSmsSender>,
    /// `RateLimiter` (counting, deterministic).
    pub rate_limiter: Arc<InMemoryRateLimiter>,
    /// `CaptchaVerifier`.
    pub captcha: Arc<FakeCaptcha>,
    /// `RiskEvaluator`.
    pub risk: Arc<FakeRiskEvaluator>,
    /// `BreachedPasswordChecker`.
    pub breached_passwords: Arc<FakeBreachedPasswordChecker>,
    /// `PasswordValidator`.
    pub password_validator: Arc<FakePasswordValidator>,
    /// `SessionRevoker`.
    pub session_revoker: Arc<RecordingSessionRevoker>,
    /// `SessionIssuer`.
    pub session_issuer: Arc<FakeSessionIssuer>,
    /// `DnsTxtResolver`.
    pub dns: Arc<FakeDnsTxtResolver>,
    /// `GeoIpLookup`.
    pub geoip: Arc<FakeGeoIp>,
    /// `HttpClient`.
    pub http: Arc<FakeHttpClient>,
}

impl TestPorts {
    /// Fresh fakes with permissive defaults (everything allowed, nothing
    /// breached, low risk, CAPTCHA passes).
    #[must_use]
    pub fn new() -> Self {
        let clock = Arc::new(FakeClock::new());
        Self {
            audit: Arc::new(RecordingAuditSink::default()),
            events: Arc::new(RecordingEventPublisher::default()),
            notifier: Arc::new(RecordingNotifier::default()),
            email: Arc::new(RecordingEmailTransport::default()),
            sms: Arc::new(RecordingSmsSender::default()),
            rate_limiter: Arc::new(InMemoryRateLimiter::new(clock.clone())),
            captcha: Arc::new(FakeCaptcha::default()),
            risk: Arc::new(FakeRiskEvaluator::default()),
            breached_passwords: Arc::new(FakeBreachedPasswordChecker::default()),
            password_validator: Arc::new(FakePasswordValidator::default()),
            session_revoker: Arc::new(RecordingSessionRevoker::default()),
            session_issuer: Arc::new(FakeSessionIssuer::new(clock.clone())),
            dns: Arc::new(FakeDnsTxtResolver::default()),
            geoip: Arc::new(FakeGeoIp::default()),
            http: Arc::new(FakeHttpClient::default()),
            clock,
        }
    }
}

impl Default for TestPorts {
    fn default() -> Self {
        Self::new()
    }
}

/// Locks a std mutex, ignoring poisoning (a panicking test must not cascade).
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
