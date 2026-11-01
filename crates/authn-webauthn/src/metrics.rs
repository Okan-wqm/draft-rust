//! Metric names and recorders (OPS-04). Labels are fixed, low-cardinality
//! strings — never user or credential ids.

/// Ceremonies started, by `kind` (`registration`, `login`,
/// `second_factor`, `step_up`).
pub const CEREMONIES_STARTED: &str = "authn_passkey_ceremonies_started_total";
/// Registrations finished, by `outcome`.
pub const REGISTRATIONS: &str = "authn_passkey_registrations_total";
/// Authentications finished, by `purpose` and `outcome`.
pub const AUTHENTICATIONS: &str = "authn_passkey_authentications_total";
/// Clone / tampering signals (PKY-05), by `reason`.
pub const CLONE_SUSPECTED: &str = "authn_passkey_clone_suspected_total";
/// Passkeys removed.
pub const REMOVED: &str = "authn_passkey_removed_total";

#[cfg_attr(not(feature = "passkey"), allow(dead_code))]
pub(crate) fn ceremony_started(kind: &'static str) {
    metrics::counter!(CEREMONIES_STARTED, "kind" => kind).increment(1);
}

#[cfg_attr(not(feature = "passkey"), allow(dead_code))]
pub(crate) fn registration_finished(outcome: &'static str) {
    metrics::counter!(REGISTRATIONS, "outcome" => outcome).increment(1);
}

#[cfg_attr(not(feature = "passkey"), allow(dead_code))]
pub(crate) fn authentication_finished(purpose: &'static str, outcome: &'static str) {
    metrics::counter!(AUTHENTICATIONS, "purpose" => purpose, "outcome" => outcome).increment(1);
}

#[cfg_attr(not(feature = "passkey"), allow(dead_code))]
pub(crate) fn clone_suspected(reason: &'static str) {
    metrics::counter!(CLONE_SUSPECTED, "reason" => reason).increment(1);
}

pub(crate) fn passkey_removed() {
    metrics::counter!(REMOVED).increment(1);
}
