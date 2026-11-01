//! Ports (ARC-02): object-safe async traits behind which every side effect
//! and every cross-module service lives.
//!
//! Rules (see `docs/architecture/contracts.md`):
//! * Every port file is owned by the crate that *implements* it (table
//!   below). Only additive, backward-compatible changes are allowed; anything
//!   else goes through `docs/architecture/contract-change-requests.md`.
//! * Consumers code against the documented signature and semantics, and use
//!   the fakes in `authn-testkit` in their tests.
//! * All ports are `Send + Sync` and used as `Arc<dyn Port>`.
//! * Methods that take `&mut PgConnection` run inside the caller's
//!   transaction (ARC-06): their effects commit or roll back with it.
//!
//! | port | file | implemented by |
//! |------|------|----------------|
//! | [`Clock`] | `clock.rs` | authn-core ([`SystemClock`]) |
//! | [`AuditSink`] | `audit.rs` | authn-audit |
//! | [`EventPublisher`] | `event_publisher.rs` | authn-audit |
//! | [`Notifier`] | `notifier.rs` | authn-notify |
//! | [`EmailTransport`] | `email_transport.rs` | authn-notify |
//! | [`SmsSender`] | `sms.rs` | authn-notify |
//! | [`RateLimiter`] | `rate_limit.rs` | authn-protect |
//! | [`CaptchaVerifier`] | `captcha.rs` | authn-protect |
//! | [`RiskEvaluator`] | `risk.rs` | authn-protect |
//! | [`GeoIpLookup`] | `geoip.rs` | authn-protect (optional) |
//! | [`HttpClient`] | `http_client.rs` | authn-protect |
//! | [`BreachedPasswordChecker`] | `breached_password.rs` | authn-password |
//! | [`PasswordValidator`] | `password_validator.rs` | authn-password |
//! | [`DnsTxtResolver`] | `dns.rs` | authn-org |
//! | [`SessionRevoker`] | `session_revoker.rs` | authn-session |
//! | [`SessionIssuer`] | `session_issuer.rs` | authn-session |
//! | [`DataExporter`] | `data_exporter.rs` | every module (aggregated by authn-account) |

mod audit;
mod breached_password;
mod captcha;
mod clock;
mod data_exporter;
mod dns;
mod email_transport;
mod event_publisher;
mod geoip;
mod http_client;
mod notifier;
mod password_validator;
mod rate_limit;
mod risk;
mod session_issuer;
mod session_revoker;
mod sms;

pub use audit::{Actor, AuditSink, EventOutcome, ResourceRef, SecurityEvent, SecurityEventKind};
pub use breached_password::{BreachStatus, BreachedPasswordChecker};
pub use captcha::{
    CaptchaChallenge, CaptchaContext, CaptchaProvider, CaptchaVerdict, CaptchaVerifier,
};
pub use clock::{Clock, SystemClock};
pub use data_exporter::DataExporter;
pub use dns::DnsTxtResolver;
pub use email_transport::{EmailMessage, EmailTransport};
pub use event_publisher::{DomainEvent, DomainEventKind, EventPublisher};
pub use geoip::{GeoIpLookup, GeoLocation};
pub use http_client::{HttpClient, OutboundRequest, OutboundResponse, OutboundTarget};
pub use notifier::{
    Notification, NotificationKind, Notifier, Recipient, SmsNotification, SmsNotificationKind,
};
pub use password_validator::{
    PasswordCheck, PasswordContext, PasswordValidator, PasswordViolation,
};
pub use rate_limit::{
    RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimitScope, RateLimiter,
};
pub use risk::{RiskAssessment, RiskEvaluator, RiskInput, RiskLevel, RiskReason};
pub use session_issuer::{
    ImpersonationRequest, IssuedSession, LoginOutcome, PendingChallenge, PrimaryAuthentication,
    RequiredAction, SessionIssuer,
};
pub use session_revoker::{RevocationReason, RevokeOptions, SessionRevoker};
pub use sms::{SmsMessage, SmsReceipt, SmsSender};
