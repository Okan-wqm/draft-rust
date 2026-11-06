//! Metric names of authn-org (OPS-04). Labels never contain identifiers or
//! personal data.

/// Organizations created.
pub const ORGS_CREATED: &str = "authn_org_created_total";
/// API keys created (incl. rotations).
pub const API_KEYS_CREATED: &str = "authn_api_keys_created_total";
/// API key authentications by `result` (`success`, `malformed`,
/// `wrong_environment`, `unknown_key`, `revoked`, `expired`,
/// `owner_inactive`, `org_inactive`, `ip_not_allowed`).
pub const API_KEY_AUTH: &str = "authn_api_key_auth_total";
/// Domain verification checks by `result` (`verified`, `failed`).
pub const DOMAIN_CHECKS: &str = "authn_org_domain_checks_total";

pub(crate) fn org_created() {
    metrics::counter!(ORGS_CREATED).increment(1);
}

pub(crate) fn api_key_created() {
    metrics::counter!(API_KEYS_CREATED).increment(1);
}

pub(crate) fn api_key_auth(result: &'static str) {
    metrics::counter!(API_KEY_AUTH, "result" => result).increment(1);
}

pub(crate) fn domain_check(verified: bool) {
    let result = if verified { "verified" } else { "failed" };
    metrics::counter!(DOMAIN_CHECKS, "result" => result).increment(1);
}

/// Periodic domain re-verification checks (ORG-13), labelled by `outcome`
/// (`present`, `absent`, `inconclusive`).
pub const DOMAIN_REVERIFICATIONS: &str = "authn_org_domain_reverifications_total";
/// Verified domains that lost their verification (ORG-13), labelled by
/// `reason` (`absent`, `inconclusive`). Alert on `inconclusive`: the
/// resolver may be failing for every domain.
pub const DOMAINS_UNVERIFIED: &str = "authn_org_domains_unverified_total";

pub(crate) fn domain_reverification(outcome: &'static str) {
    metrics::counter!(DOMAIN_REVERIFICATIONS, "outcome" => outcome).increment(1);
}

pub(crate) fn domain_unverified(reason: &'static str) {
    metrics::counter!(DOMAINS_UNVERIFIED, "reason" => reason).increment(1);
}
