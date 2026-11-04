//! Metric names and recorders (OPS-04). Labels are fixed, low-cardinality
//! strings (provider slugs and error codes) — never user or identity ids.

/// Social logins, by `provider` and `outcome` (`ok` or the error code).
pub const LOGINS: &str = "authn_social_logins_total";
/// Accounts created by social login, by `provider`.
pub const ACCOUNTS_CREATED: &str = "authn_social_accounts_created_total";

/// Bounded label value: configured slugs are `[a-z0-9-]{1,32}`; anything
/// else (an unknown provider in a request path) is folded into `other`.
fn provider_label(provider: &str) -> String {
    let ok = !provider.is_empty()
        && provider.len() <= 40
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b':');
    if ok {
        provider.to_owned()
    } else {
        "other".to_owned()
    }
}

pub(crate) fn login(provider: &str, outcome: &'static str) {
    metrics::counter!(LOGINS, "provider" => provider_label(provider), "outcome" => outcome)
        .increment(1);
}

pub(crate) fn account_created(provider: &str) {
    metrics::counter!(ACCOUNTS_CREATED, "provider" => provider_label(provider)).increment(1);
}

/// Provider token revocations (K-35), by `provider` and `outcome`
/// (`revoked`, `already_invalid`, `retry`, `abandoned`, `unreadable`).
pub const TOKEN_REVOCATIONS: &str = "authn_social_token_revocations_total";
/// JWKS downloads that failed (K-16), by `host`-independent label
/// `outcome` (`failed`, `backoff` = refused without a request).
pub const JWKS_FAILURES: &str = "authn_social_jwks_failures_total";

pub(crate) fn token_revocation(provider: &str, outcome: &'static str) {
    metrics::counter!(TOKEN_REVOCATIONS, "provider" => provider_label(provider), "outcome" => outcome)
        .increment(1);
}

pub(crate) fn jwks_failure(outcome: &'static str) {
    metrics::counter!(JWKS_FAILURES, "outcome" => outcome).increment(1);
}
