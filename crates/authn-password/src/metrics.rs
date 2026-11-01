//! Prometheus metrics of this crate (OPS-04). Labels never carry personal
//! data or anything derived from a password.

/// Breach lookups by source and result (PWD-03).
pub const BREACH_CHECKS: &str = "authn_password_breach_checks_total";
/// Breach lookups that could not be performed, by fail mode (PWD-03).
pub const BREACH_CHECK_UNAVAILABLE: &str = "authn_password_breach_check_unavailable_total";
/// Password reset requests accepted for processing (PWD-07). Counted for
/// known and unknown addresses alike.
pub const RESET_REQUESTS: &str = "authn_password_reset_requests_total";
/// Reset requests dropped because the background backlog was full.
pub const RESET_REQUESTS_DROPPED: &str = "authn_password_reset_requests_dropped_total";
/// Completed password resets by method (`link`, `code`) (PWD-09).
pub const RESETS_COMPLETED: &str = "authn_password_resets_completed_total";
/// Password changes by kind (`changed`, `added`, `removed`, `rehashed`).
pub const PASSWORD_UPDATES: &str = "authn_password_updates_total";

pub(crate) fn breach_check(source: &'static str, result: &'static str) {
    metrics::counter!(BREACH_CHECKS, "source" => source, "result" => result).increment(1);
}

pub(crate) fn breach_check_unavailable(fail_open: bool) {
    let mode = if fail_open {
        "fail_open"
    } else {
        "fail_closed"
    };
    metrics::counter!(BREACH_CHECK_UNAVAILABLE, "mode" => mode).increment(1);
}

pub(crate) fn reset_requested() {
    metrics::counter!(RESET_REQUESTS).increment(1);
}

pub(crate) fn reset_dropped() {
    metrics::counter!(RESET_REQUESTS_DROPPED).increment(1);
}

pub(crate) fn reset_completed(method: &'static str) {
    metrics::counter!(RESETS_COMPLETED, "method" => method).increment(1);
}

pub(crate) fn password_updated(kind: &'static str) {
    metrics::counter!(PASSWORD_UPDATES, "kind" => kind).increment(1);
}
