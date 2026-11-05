//! Organization security policy (ORG-07): the model, its validation and the
//! pure enforcement helpers.
//!
//! [`OrgPolicy`] is also the **read API for other modules**: authn-session
//! (allowed login methods, session lifetime cap, IP allow-list at login and
//! organization switch, SES-17 / SES-21) and authn-mfa (MFA requirement,
//! allowed factors, trusted-device permission, MFA-08 / MFA-09) receive it
//! from the server through [`crate::OrgService::policy`] /
//! [`crate::OrgService::policies_for_user`] (wave A crates do not depend on
//! each other; the server maps it onto their input structs).
//!
//! authn-org itself enforces the parts that can be checked on every request
//! inside [`crate::OrgService::authorize`]: IP allow-list (all principals,
//! API keys included), MFA / phishing-resistant MFA (user sessions, from
//! `amr`), the allowed login methods and second factors of the session
//! (K-57, [`OrgPolicy::check_session_methods`]) and the session lifetime
//! cap (time since the last authentication).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use authn_core::domain::{AuthMethodRef, FactorKind, LoginMethod};
use authn_core::error::AuthError;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::validate::invalid;

/// Most CIDR entries in an IP allow-list.
pub const MAX_IP_ALLOWLIST_ENTRIES: usize = 100;
/// Most AAGUIDs in a passkey allow-list (PKY-08).
pub const MAX_AAGUIDS: usize = 50;
/// Shortest session lifetime cap (5 minutes).
pub const MIN_SESSION_LIFETIME_SECONDS: u32 = 300;
/// Longest session lifetime cap (90 days).
pub const MAX_SESSION_LIFETIME_SECONDS: u32 = 90 * 86_400;

/// The security policy of one organization. `None` lists mean "no
/// restriction".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OrgPolicy {
    /// Members must sign in with MFA (a passkey counts, SES-21).
    pub mfa_required: bool,
    /// Members must use a phishing-resistant factor (passkey / security
    /// key). Implies `mfa_required`.
    pub phishing_resistant_mfa_required: bool,
    /// Allowed primary login methods (enforced by authn-session).
    pub allowed_login_methods: Option<Vec<LoginMethod>>,
    /// Allowed second factors (enforced by authn-mfa).
    pub allowed_mfa_factors: Option<Vec<FactorKind>>,
    /// Upper bound of a session in this organization, in seconds.
    pub max_session_lifetime_seconds: Option<u32>,
    /// Allowed client networks (CIDR). Applies to every principal,
    /// including API keys and service accounts.
    #[schema(value_type = Option<Vec<String>>, example = json!(["203.0.113.0/24"]))]
    pub ip_allowlist: Option<Vec<IpNet>>,
    /// Whether "trust this device" (MFA-09) may be used.
    pub trusted_devices_allowed: bool,
    /// Allowed passkey authenticator models (PKY-08, enforced by
    /// authn-webauthn).
    pub allowed_passkey_aaguids: Option<Vec<Uuid>>,
}

impl Default for OrgPolicy {
    /// No requirement, no restriction (the defaults of `org_policies`).
    fn default() -> Self {
        Self {
            mfa_required: false,
            phishing_resistant_mfa_required: false,
            allowed_login_methods: None,
            allowed_mfa_factors: None,
            max_session_lifetime_seconds: None,
            ip_allowlist: None,
            trusted_devices_allowed: true,
            allowed_passkey_aaguids: None,
        }
    }
}

/// Why a request does not satisfy the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyViolation {
    /// The client IP is outside the allow-list.
    IpNotAllowed,
    /// MFA is required and the session has none.
    MfaRequired,
    /// A phishing-resistant factor is required and the session has none.
    PhishingResistantRequired,
    /// The last authentication is older than the lifetime cap.
    SessionTooOld,
    /// The session's primary login method is not allowed (K-57).
    LoginMethodNotAllowed,
    /// The second factor behind the session's `mfa` is not allowed (K-57).
    SecondFactorNotAllowed,
}

impl OrgPolicy {
    /// Whether `ip` may access the organization. IPv4-mapped IPv6
    /// addresses are matched as IPv4.
    #[must_use]
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        let Some(list) = &self.ip_allowlist else {
            return true;
        };
        let ip = canonical_ip(ip);
        list.iter().any(|net| net.contains(&ip))
    }

    /// Whether the primary login method is allowed.
    #[must_use]
    pub fn allows_login_method(&self, method: LoginMethod) -> bool {
        self.allowed_login_methods
            .as_ref()
            .is_none_or(|list| list.contains(&method))
    }

    /// Whether the second factor is allowed (phishing-resistant policies
    /// allow only phishing-resistant factors).
    #[must_use]
    pub fn allows_factor(&self, factor: FactorKind) -> bool {
        if self.phishing_resistant_mfa_required && !factor.is_phishing_resistant() {
            return false;
        }
        self.allowed_mfa_factors
            .as_ref()
            .is_none_or(|list| list.contains(&factor))
    }

    /// Checks how a user session was established against the policy
    /// (ORG-07, SES-17; K-57): its primary login method and the second
    /// factor behind its `mfa` (K-78: the recorded `mfa_factors`, never
    /// inferred from `amr`). The same rules as the organization switch of
    /// authn-session, applied on **every** organization request: a
    /// session acting on the organization without having activated it is
    /// held to the policy too.
    ///
    /// * login method: an unknown method (`None`) passes only while the
    ///   policy does not restrict methods; a passkey proven later (step-up,
    ///   `hwk` / `swk` in `amr`) satisfies a policy that allows passkeys;
    /// * second factor: only when the policy requires MFA and restricts the
    ///   factors; a passkey is MFA on its own (SES-21).
    ///
    /// Impersonation sessions (`impersonated`) are exempt: they carry the
    /// admin's authentication, not the user's (ADM-04).
    pub fn check_session_methods(
        &self,
        login_method: Option<LoginMethod>,
        mfa_factors: &[FactorKind],
        amr: &[AuthMethodRef],
        impersonated: bool,
    ) -> Result<(), PolicyViolation> {
        if impersonated {
            return Ok(());
        }
        let passkey = amr
            .iter()
            .any(|a| matches!(a, AuthMethodRef::Hwk | AuthMethodRef::Swk));
        let method_allowed = match login_method {
            Some(method) => self.allows_login_method(method),
            None => self.allowed_login_methods.is_none(),
        };
        if !method_allowed && !(passkey && self.allows_login_method(LoginMethod::Passkey)) {
            return Err(PolicyViolation::LoginMethodNotAllowed);
        }
        if let Some(allowed) = &self.allowed_mfa_factors
            && (self.mfa_required || self.phishing_resistant_mfa_required)
            && !passkey
            && !mfa_factors.iter().any(|f| allowed.contains(f))
        {
            return Err(PolicyViolation::SecondFactorNotAllowed);
        }
        Ok(())
    }

    /// The session lifetime cap.
    #[must_use]
    pub fn session_lifetime_cap(&self) -> Option<Duration> {
        self.max_session_lifetime_seconds
            .map(|s| Duration::from_secs(u64::from(s)))
    }

    /// Checks the authentication strength of a user session against the
    /// policy: MFA, phishing resistance (from the session `amr`) and the
    /// lifetime cap (`now - auth_time`).
    pub fn check_session(
        &self,
        amr: &[AuthMethodRef],
        auth_time: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<(), PolicyViolation> {
        let phishing_resistant = amr
            .iter()
            .any(|a| matches!(a, AuthMethodRef::Hwk | AuthMethodRef::Swk));
        let multi_factor = phishing_resistant || amr.contains(&AuthMethodRef::Mfa);
        if self.phishing_resistant_mfa_required && !phishing_resistant {
            return Err(PolicyViolation::PhishingResistantRequired);
        }
        if self.mfa_required && !multi_factor {
            return Err(PolicyViolation::MfaRequired);
        }
        if let Some(cap) = self.session_lifetime_cap() {
            let fresh = auth_time.is_some_and(|t| {
                let age = now - t;
                age.is_negative() || age <= cap
            });
            if !fresh {
                return Err(PolicyViolation::SessionTooOld);
            }
        }
        Ok(())
    }

    /// Whether moving from `previous` to `self` removes access that existing
    /// sessions may rely on (then the organization's sessions are revoked
    /// so every member re-authenticates under the new rules).
    #[must_use]
    pub fn tightens(&self, previous: &Self) -> bool {
        fn narrower<T: Ord + Copy>(new: Option<&Vec<T>>, old: Option<&Vec<T>>) -> bool {
            match (new, old) {
                (None, _) => false,
                (Some(_), None) => true,
                // Something allowed before is no longer allowed.
                (Some(new), Some(old)) => {
                    let new: BTreeSet<T> = new.iter().copied().collect();
                    old.iter().any(|v| !new.contains(v))
                }
            }
        }
        (self.mfa_required && !previous.mfa_required)
            || (self.phishing_resistant_mfa_required && !previous.phishing_resistant_mfa_required)
            || narrower(
                self.allowed_login_methods.as_ref(),
                previous.allowed_login_methods.as_ref(),
            )
            || narrower(
                self.allowed_mfa_factors.as_ref(),
                previous.allowed_mfa_factors.as_ref(),
            )
            || narrower(
                self.allowed_passkey_aaguids.as_ref(),
                previous.allowed_passkey_aaguids.as_ref(),
            )
            || match (
                self.max_session_lifetime_seconds,
                previous.max_session_lifetime_seconds,
            ) {
                (Some(new), Some(old)) => new < old,
                (Some(_), None) => true,
                (None, _) => false,
            }
            || (self.ip_allowlist.is_some() && self.ip_allowlist != previous.ip_allowlist)
            || (!self.trusted_devices_allowed && previous.trusted_devices_allowed)
    }
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as IPv4.
#[must_use]
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Body of `PUT /v1/orgs/{org_id}/policy` (full replacement).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgPolicyInput {
    /// Require MFA.
    #[serde(default)]
    pub mfa_required: bool,
    /// Require phishing-resistant MFA (implies `mfa_required`).
    #[serde(default)]
    pub phishing_resistant_mfa_required: bool,
    /// Allowed primary login methods; omit for no restriction.
    pub allowed_login_methods: Option<Vec<LoginMethod>>,
    /// Allowed second factors; omit for no restriction.
    pub allowed_mfa_factors: Option<Vec<FactorKind>>,
    /// Session lifetime cap in seconds (300 – 7 776 000); omit for none.
    pub max_session_lifetime_seconds: Option<u32>,
    /// Allowed networks as CIDR (`203.0.113.0/24`) or single addresses;
    /// omit for no restriction. At most 100 entries.
    pub ip_allowlist: Option<Vec<String>>,
    /// Allow "trust this device" (default `true`).
    #[serde(default = "default_true")]
    pub trusted_devices_allowed: bool,
    /// Allowed passkey AAGUIDs; omit for no restriction. At most 50.
    pub allowed_passkey_aaguids: Option<Vec<Uuid>>,
}

fn default_true() -> bool {
    true
}

impl Default for OrgPolicyInput {
    /// The input of the default policy (no restriction, trusted devices
    /// allowed).
    fn default() -> Self {
        Self {
            mfa_required: false,
            phishing_resistant_mfa_required: false,
            allowed_login_methods: None,
            allowed_mfa_factors: None,
            max_session_lifetime_seconds: None,
            ip_allowlist: None,
            trusted_devices_allowed: true,
            allowed_passkey_aaguids: None,
        }
    }
}

impl OrgPolicyInput {
    /// Validates and canonicalizes (sorted, deduplicated lists; network
    /// addresses truncated to their prefix).
    pub fn validate(self) -> Result<OrgPolicy, AuthError> {
        let mfa_required = self.mfa_required || self.phishing_resistant_mfa_required;
        let allowed_login_methods =
            canonical_list(self.allowed_login_methods, "allowed_login_methods")?;
        let allowed_mfa_factors = canonical_list(self.allowed_mfa_factors, "allowed_mfa_factors")?;
        if self.phishing_resistant_mfa_required
            && allowed_mfa_factors
                .as_ref()
                .is_some_and(|f| !f.iter().any(|k| k.is_phishing_resistant()))
        {
            return Err(invalid("allowed_mfa_factors"));
        }
        if self.max_session_lifetime_seconds.is_some_and(|s| {
            !(MIN_SESSION_LIFETIME_SECONDS..=MAX_SESSION_LIFETIME_SECONDS).contains(&s)
        }) {
            return Err(invalid("max_session_lifetime_seconds"));
        }
        let ip_allowlist = match self.ip_allowlist {
            None => None,
            Some(entries) => {
                if entries.is_empty() || entries.len() > MAX_IP_ALLOWLIST_ENTRIES {
                    return Err(invalid("ip_allowlist"));
                }
                let mut nets = BTreeSet::new();
                for entry in &entries {
                    nets.insert(parse_network(entry).ok_or_else(|| invalid("ip_allowlist"))?);
                }
                Some(nets.into_iter().collect())
            }
        };
        let allowed_passkey_aaguids = match self.allowed_passkey_aaguids {
            None => None,
            Some(list) => {
                if list.is_empty() || list.len() > MAX_AAGUIDS || list.iter().any(Uuid::is_nil) {
                    return Err(invalid("allowed_passkey_aaguids"));
                }
                Some(
                    list.into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                )
            }
        };
        Ok(OrgPolicy {
            mfa_required,
            phishing_resistant_mfa_required: self.phishing_resistant_mfa_required,
            allowed_login_methods,
            allowed_mfa_factors,
            max_session_lifetime_seconds: self.max_session_lifetime_seconds,
            ip_allowlist,
            trusted_devices_allowed: self.trusted_devices_allowed,
            allowed_passkey_aaguids,
        })
    }
}

fn canonical_list<T: Ord + Copy>(
    list: Option<Vec<T>>,
    field: &'static str,
) -> Result<Option<Vec<T>>, AuthError> {
    match list {
        None => Ok(None),
        Some(values) if values.is_empty() || values.len() > 32 => Err(invalid(field)),
        Some(values) => Ok(Some(
            values
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        )),
    }
}

/// `a.b.c.d/nn`, `x::/nn` or a single address; host bits are cleared.
fn parse_network(entry: &str) -> Option<IpNet> {
    let entry = entry.trim();
    if entry.is_empty() || entry.len() > 64 {
        return None;
    }
    if let Ok(net) = entry.parse::<IpNet>() {
        let net = match net {
            IpNet::V6(v6) => match v6.addr().to_ipv4_mapped() {
                Some(v4) => {
                    let prefix = v6.prefix_len().checked_sub(96)?;
                    IpNet::new(IpAddr::V4(v4), prefix).ok()?
                }
                None => IpNet::V6(v6),
            },
            v4 @ IpNet::V4(_) => v4,
        };
        return Some(net.trunc());
    }
    let ip = canonical_ip(entry.parse::<IpAddr>().ok()?);
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    IpNet::new(ip, prefix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    #[test]
    fn org_07_defaults_restrict_nothing() {
        let p = OrgPolicy::default();
        assert!(p.allows_ip("198.51.100.7".parse().unwrap()));
        assert!(p.allows_login_method(LoginMethod::MagicLink));
        assert!(p.allows_factor(FactorKind::Sms));
        assert!(p.check_session(&[AuthMethodRef::Pwd], None, now()).is_ok());
        assert_eq!(OrgPolicyInput::default().validate().unwrap(), p);
    }

    #[test]
    fn org_07_ip_allowlist_matches_cidrs_and_mapped_addresses() {
        let p = OrgPolicyInput {
            ip_allowlist: Some(vec![
                "203.0.113.77/24".into(),
                "2001:db8::/32".into(),
                "198.51.100.9".into(),
            ]),
            ..OrgPolicyInput::default()
        }
        .validate()
        .unwrap();
        let list: Vec<String> = p
            .ip_allowlist
            .as_ref()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(list.contains(&"203.0.113.0/24".to_owned()), "{list:?}");
        assert!(list.contains(&"198.51.100.9/32".to_owned()), "{list:?}");
        assert!(p.allows_ip("203.0.113.200".parse().unwrap()));
        assert!(p.allows_ip("::ffff:203.0.113.5".parse().unwrap()));
        assert!(p.allows_ip("2001:db8:1::1".parse().unwrap()));
        assert!(p.allows_ip("198.51.100.9".parse().unwrap()));
        assert!(!p.allows_ip("198.51.100.10".parse().unwrap()));
        assert!(!p.allows_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn org_07_invalid_inputs_are_rejected() {
        let cases = [
            OrgPolicyInput {
                ip_allowlist: Some(vec![]),
                ..Default::default()
            },
            OrgPolicyInput {
                ip_allowlist: Some(vec!["not-an-ip".into()]),
                ..Default::default()
            },
            OrgPolicyInput {
                ip_allowlist: Some(vec!["10.0.0.0/33".into()]),
                ..Default::default()
            },
            OrgPolicyInput {
                ip_allowlist: Some(vec!["10.0.0.1".into(); 101]),
                ..Default::default()
            },
            OrgPolicyInput {
                allowed_login_methods: Some(vec![]),
                ..Default::default()
            },
            OrgPolicyInput {
                max_session_lifetime_seconds: Some(10),
                ..Default::default()
            },
            OrgPolicyInput {
                max_session_lifetime_seconds: Some(u32::MAX),
                ..Default::default()
            },
            OrgPolicyInput {
                allowed_passkey_aaguids: Some(vec![Uuid::nil()]),
                ..Default::default()
            },
            OrgPolicyInput {
                phishing_resistant_mfa_required: true,
                allowed_mfa_factors: Some(vec![FactorKind::Totp]),
                ..Default::default()
            },
        ];
        for case in cases {
            assert!(case.clone().validate().is_err(), "{case:?}");
        }
    }

    #[test]
    fn org_07_phishing_resistance_implies_mfa_and_only_passkeys_qualify() {
        let p = OrgPolicyInput {
            phishing_resistant_mfa_required: true,
            ..Default::default()
        }
        .validate()
        .unwrap();
        assert!(p.mfa_required);
        assert!(!p.allows_factor(FactorKind::Totp));
        assert!(p.allows_factor(FactorKind::Webauthn));
        assert_eq!(
            p.check_session(
                &[AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa],
                Some(now()),
                now()
            ),
            Err(PolicyViolation::PhishingResistantRequired)
        );
        assert!(
            p.check_session(
                &[AuthMethodRef::Hwk, AuthMethodRef::Mfa],
                Some(now()),
                now()
            )
            .is_ok()
        );
    }

    #[test]
    fn org_07_mfa_and_lifetime_are_checked_from_the_session() {
        let p = OrgPolicyInput {
            mfa_required: true,
            max_session_lifetime_seconds: Some(3600),
            ..Default::default()
        }
        .validate()
        .unwrap();
        assert_eq!(
            p.check_session(&[AuthMethodRef::Pwd], Some(now()), now()),
            Err(PolicyViolation::MfaRequired)
        );
        let mfa = [AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa];
        assert!(
            p.check_session(&mfa, Some(now() - Duration::from_secs(3600)), now())
                .is_ok()
        );
        assert_eq!(
            p.check_session(&mfa, Some(now() - Duration::from_secs(3601)), now()),
            Err(PolicyViolation::SessionTooOld)
        );
        assert_eq!(
            p.check_session(&mfa, None, now()),
            Err(PolicyViolation::SessionTooOld)
        );
        // A synced passkey alone is MFA (SES-21).
        assert!(
            p.check_session(&[AuthMethodRef::Swk], Some(now()), now())
                .is_ok()
        );
    }

    #[test]
    fn org_07_k57_login_method_and_second_factor_of_the_session_are_checked() {
        use AuthMethodRef::{Hwk, Mfa, Otp, Pwd};
        let open = OrgPolicy::default();
        assert!(open.check_session_methods(None, &[], &[Pwd], false).is_ok());

        let passkey_only = OrgPolicy {
            allowed_login_methods: Some(vec![LoginMethod::Passkey]),
            ..OrgPolicy::default()
        };
        let password = Some(LoginMethod::Password);
        assert_eq!(
            passkey_only.check_session_methods(password, &[], &[Pwd], false),
            Err(PolicyViolation::LoginMethodNotAllowed)
        );
        // Unknown method (unchecked bearer token): refused when restricted.
        assert_eq!(
            passkey_only.check_session_methods(None, &[], &[Pwd], false),
            Err(PolicyViolation::LoginMethodNotAllowed)
        );
        // A passkey proven later (step-up) satisfies a passkey policy.
        assert!(
            passkey_only
                .check_session_methods(password, &[], &[Pwd, Hwk, Mfa], false)
                .is_ok()
        );
        // Impersonation carries the admin's authentication (ADM-04).
        assert!(
            passkey_only
                .check_session_methods(None, &[], &[], true)
                .is_ok()
        );

        let webauthn_mfa = OrgPolicy {
            mfa_required: true,
            allowed_mfa_factors: Some(vec![FactorKind::Webauthn]),
            ..OrgPolicy::default()
        };
        assert_eq!(
            webauthn_mfa.check_session_methods(
                password,
                &[FactorKind::Totp],
                &[Pwd, Otp, Mfa],
                false
            ),
            Err(PolicyViolation::SecondFactorNotAllowed)
        );
        assert!(
            webauthn_mfa
                .check_session_methods(password, &[FactorKind::Webauthn], &[Pwd, Mfa], false)
                .is_ok()
        );
        // Factor restrictions apply only where MFA is required.
        let restricted_but_optional = OrgPolicy {
            allowed_mfa_factors: Some(vec![FactorKind::Webauthn]),
            ..OrgPolicy::default()
        };
        assert!(
            restricted_but_optional
                .check_session_methods(password, &[FactorKind::Totp], &[Pwd, Otp, Mfa], false)
                .is_ok()
        );
    }

    #[test]
    fn org_07_tightening_is_detected() {
        let base = OrgPolicy::default();
        let mut stricter = base.clone();
        assert!(!stricter.tightens(&base));
        stricter.mfa_required = true;
        assert!(stricter.tightens(&base));
        assert!(!base.tightens(&stricter), "relaxing is not tightening");
        let mut ips = base.clone();
        ips.ip_allowlist = Some(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(ips.tightens(&base));
        assert!(!ips.tightens(&ips.clone()));
        let mut methods = base.clone();
        methods.allowed_login_methods = Some(vec![LoginMethod::Passkey, LoginMethod::Password]);
        let mut fewer = methods.clone();
        fewer.allowed_login_methods = Some(vec![LoginMethod::Passkey]);
        assert!(fewer.tightens(&methods));
        assert!(!methods.tightens(&fewer));
        let mut no_trust = base.clone();
        no_trust.trusted_devices_allowed = false;
        assert!(no_trust.tightens(&base));
        let mut shorter = base.clone();
        shorter.max_session_lifetime_seconds = Some(3600);
        assert!(shorter.tightens(&base));
    }
}
