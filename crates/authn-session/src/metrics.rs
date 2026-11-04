//! Metric names (OPS-04). Labels are fixed vocabularies, never user data.

use authn_core::ports::RevocationReason;

/// Sessions created, by client kind.
pub const SESSIONS_CREATED: &str = "authn_sessions_created_total";
/// Sessions revoked, by reason.
pub const SESSIONS_REVOKED: &str = "authn_sessions_revoked_total";
/// Refresh requests, by outcome (`rotated`, `grace`, `invalid`, `reused`).
pub const REFRESH: &str = "authn_token_refresh_total";
/// Refresh-token reuse detections (SES-05).
pub const REFRESH_REUSE: &str = "authn_refresh_token_reuse_total";
/// CSRF rejections (SES-04).
pub const CSRF_REJECTED: &str = "authn_csrf_rejected_total";
/// Step-up attempts, by method and outcome (SES-13).
pub const STEP_UP: &str = "authn_step_up_total";
/// Bearer token rejections, by reason.
pub const BEARER_REJECTED: &str = "authn_bearer_rejected_total";
/// Introspection requests, by result (`active`, `inactive`).
pub const INTROSPECTION: &str = "authn_introspection_total";
/// Login outcomes (`succeeded`, `challenge`, `blocked`, `failed`).
pub const LOGINS: &str = "authn_logins_total";
/// Failed logins by stable reason code (OPS-04).
pub const LOGIN_FAILURES: &str = "authn_login_failures_total";
/// Second-factor verifications at login, by factor and outcome.
pub const LOGIN_FACTORS: &str = "authn_login_factor_total";
/// Sessions established for break-glass accounts (ADM-05, K-05; alert on
/// any increase).
pub const BREAK_GLASS_LOGINS: &str = "authn_break_glass_logins_total";

pub(crate) fn sessions_created(client: &'static str) {
    metrics::counter!(SESSIONS_CREATED, "client" => client).increment(1);
}

pub(crate) fn sessions_revoked(reason: RevocationReason, n: usize) {
    if n > 0 {
        metrics::counter!(SESSIONS_REVOKED, "reason" => reason.as_str())
            .increment(u64::try_from(n).unwrap_or(u64::MAX));
    }
}

pub(crate) fn refresh(outcome: &'static str) {
    metrics::counter!(REFRESH, "outcome" => outcome).increment(1);
}

pub(crate) fn refresh_reuse() {
    metrics::counter!(REFRESH_REUSE).increment(1);
}

pub(crate) fn break_glass_login() {
    metrics::counter!(BREAK_GLASS_LOGINS).increment(1);
}

pub(crate) fn csrf_rejected() {
    metrics::counter!(CSRF_REJECTED).increment(1);
}

pub(crate) fn step_up(method: &'static str, outcome: &'static str) {
    metrics::counter!(STEP_UP, "method" => method, "outcome" => outcome).increment(1);
}

pub(crate) fn bearer_rejected(reason: &'static str) {
    metrics::counter!(BEARER_REJECTED, "reason" => reason).increment(1);
}

pub(crate) fn introspection(result: &'static str) {
    metrics::counter!(INTROSPECTION, "result" => result).increment(1);
}

pub(crate) fn login(outcome: &'static str) {
    metrics::counter!(LOGINS, "outcome" => outcome).increment(1);
}

pub(crate) fn login_failed(method: &'static str, reason: &'static str) {
    metrics::counter!(LOGINS, "outcome" => "failed").increment(1);
    metrics::counter!(LOGIN_FAILURES, "method" => method, "reason" => reason).increment(1);
}

pub(crate) fn login_factor(factor: &'static str, outcome: &'static str) {
    metrics::counter!(LOGIN_FACTORS, "factor" => factor, "outcome" => outcome).increment(1);
}
