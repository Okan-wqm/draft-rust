//! Prometheus metrics of this crate (OPS-04: "MFA usage"). Labels carry only
//! factor kinds and outcomes — never user ids, phone numbers or codes.

/// Second-factor verifications by factor kind and outcome
/// (`success`, `failure`, `locked`).
pub const VERIFICATIONS: &str = "authn_mfa_verifications_total";
/// One-time codes sent by channel (`email`, `sms`) and purpose
/// (`login`, `enrollment`).
pub const CODES_SENT: &str = "authn_mfa_codes_sent_total";
/// Factors activated by kind.
pub const ENROLLMENTS: &str = "authn_mfa_enrollments_total";
/// Factors removed by kind.
pub const REMOVALS: &str = "authn_mfa_removals_total";
/// SMS refused by pumping protection, by limit (`country`, `cooldown`,
/// `per_user`, `per_number`, `per_ip`, `global`).
pub const SMS_BLOCKED: &str = "authn_mfa_sms_blocked_total";

pub(crate) fn verification(kind: &'static str, outcome: &'static str) {
    metrics::counter!(VERIFICATIONS, "factor" => kind, "outcome" => outcome).increment(1);
}

pub(crate) fn code_sent(channel: &'static str, purpose: &'static str) {
    metrics::counter!(CODES_SENT, "channel" => channel, "purpose" => purpose).increment(1);
}

pub(crate) fn enrolled(kind: &'static str) {
    metrics::counter!(ENROLLMENTS, "factor" => kind).increment(1);
}

pub(crate) fn removed(kind: &'static str) {
    metrics::counter!(REMOVALS, "factor" => kind).increment(1);
}

pub(crate) fn sms_blocked(limit: &'static str) {
    metrics::counter!(SMS_BLOCKED, "limit" => limit).increment(1);
}
