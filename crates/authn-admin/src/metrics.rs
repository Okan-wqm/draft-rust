//! Metric names of authn-admin (OPS-04).

/// Admin actions performed, labelled by `action`.
pub const ACTIONS_TOTAL: &str = "authn_admin_actions_total";
/// Requests to the admin API refused by the guard, labelled by `reason`.
pub const DENIED_TOTAL: &str = "authn_admin_denied_total";
/// Uses of a break-glass account (ADM-05).
pub const BREAK_GLASS_USED_TOTAL: &str = "authn_admin_break_glass_used_total";

/// Admin requests refused by a blast-radius limit (K-08, K-09), labelled by
/// `limit`. Alert on any increase.
pub const THROTTLED_TOTAL: &str = "authn_admin_throttled_total";

pub(crate) fn throttled(limit: &'static str) {
    metrics::counter!(THROTTLED_TOTAL, "limit" => limit).increment(1);
}

pub(crate) fn action(action: &'static str) {
    metrics::counter!(ACTIONS_TOTAL, "action" => action).increment(1);
}

pub(crate) fn denied(reason: &'static str) {
    metrics::counter!(DENIED_TOTAL, "reason" => reason).increment(1);
}

pub(crate) fn break_glass_used() {
    metrics::counter!(BREAK_GLASS_USED_TOTAL).increment(1);
}

/// Critical operations run without four-eyes approval under a defined
/// exception (K-66), labelled by `exception`. Alert on any increase.
pub const FOUR_EYES_BYPASSED_TOTAL: &str = "authn_admin_four_eyes_bypassed_total";
/// Critical operations or approval decisions refused by four-eyes (K-66),
/// labelled by `reason`.
pub const FOUR_EYES_REFUSED_TOTAL: &str = "authn_admin_four_eyes_refused_total";

pub(crate) fn four_eyes_bypassed(exception: &'static str) {
    metrics::counter!(FOUR_EYES_BYPASSED_TOTAL, "exception" => exception).increment(1);
}

pub(crate) fn four_eyes_refused(reason: &'static str) {
    metrics::counter!(FOUR_EYES_REFUSED_TOTAL, "reason" => reason).increment(1);
}
