//! MFA policy evaluation (MFA-08): one pure function over an input struct.
//!
//! The caller (authn-session at login / step-up / organization switch,
//! authn-mfa itself for the "last factor" rule) collects the facts —
//! the user's usable factors, the user's own preference, the organization
//! policy (ORG-07, owned by authn-org), the platform-admin flag and whether
//! phishing-resistant MFA is demanded for another reason — and
//! [`evaluate`] decides:
//!
//! * [`MfaRequirement::NotRequired`] — no second factor is needed.
//! * [`MfaRequirement::Required`] — verify one of `allowed_factors` (every
//!   entry is enrolled *and* permitted).
//! * [`MfaRequirement::EnrollmentRequired`] — MFA is required but none of
//!   the user's factors is permitted; the user must enroll one of
//!   `allowed_factors`. **An empty list means that no factor can satisfy the
//!   policy: deny.** When the user still has enrolled (but no longer
//!   permitted) factors, the caller should have one of them verified before
//!   letting the user enroll a new factor, so a stolen password alone can
//!   never register an attacker's authenticator.
//!
//! Rules:
//! * Platform admins: MFA always required, phishing-resistant factors only
//!   (ADM-01).
//! * Phishing-resistant requirement (organization or caller): only
//!   [`FactorKind::is_phishing_resistant`] factors (WebAuthn).
//! * The organization's allowed-factor list and the deployment's available
//!   factors restrict the permitted kinds further; nothing ever widens them.
//! * MFA is required when an admin, the organization or the caller demand
//!   it, when the user opted in, or when the user enrolled a factor other
//!   than recovery codes (an enrolled factor is never silently skipped).
//! * Recovery codes are a fallback: they appear in `Required` when
//!   permitted and unused codes remain, but they never satisfy the
//!   requirement on their own and are never offered for enrollment.

use authn_core::domain::FactorKind;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Organization policy facts relevant to MFA (ORG-07). authn-org owns the
/// data; the caller copies it here (wave-A crates do not depend on each
/// other).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OrgMfaPolicy {
    /// The organization requires MFA for its members.
    pub mfa_required: bool,
    /// The organization requires phishing-resistant MFA (implies
    /// `mfa_required`).
    pub phishing_resistant_required: bool,
    /// Allowed factor kinds; `None` means no restriction.
    pub allowed_factors: Option<Vec<FactorKind>>,
    /// Whether "trust this device" is allowed (MFA-09).
    pub trusted_devices_allowed: bool,
}

impl Default for OrgMfaPolicy {
    /// No requirement, no restriction, trusted devices allowed (the
    /// defaults of `org_policies`).
    fn default() -> Self {
        Self {
            mfa_required: false,
            phishing_resistant_required: false,
            allowed_factors: None,
            trusted_devices_allowed: true,
        }
    }
}

impl OrgMfaPolicy {
    /// Combines two policies into the strictest one (a user who belongs to
    /// several organizations outside of a specific login context): every
    /// requirement of either applies, allowed lists intersect, trusted
    /// devices only if both allow them.
    #[must_use]
    pub fn strictest(&self, other: &Self) -> Self {
        let allowed_factors = match (&self.allowed_factors, &other.allowed_factors) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(canonical(a.iter().copied())),
            (Some(a), Some(b)) => Some(canonical(a.iter().copied().filter(|k| b.contains(k)))),
        };
        Self {
            mfa_required: self.mfa_required || other.mfa_required,
            phishing_resistant_required: self.phishing_resistant_required
                || other.phishing_resistant_required,
            allowed_factors,
            trusted_devices_allowed: self.trusted_devices_allowed && other.trusted_devices_allowed,
        }
    }
}

/// Everything [`evaluate`] looks at.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MfaPolicyInput {
    /// Factors the user can verify with right now: active TOTP / e-mail /
    /// SMS factors, `recovery_code` while unused codes remain, `webauthn`
    /// when a passkey usable as a second factor exists (authn-webauthn).
    pub enrolled_factors: Vec<FactorKind>,
    /// The user turned MFA on for their own account.
    pub user_opted_in: bool,
    /// Policy of the organization the login / action happens in (or the
    /// strictest combination, see [`OrgMfaPolicy::strictest`]).
    pub org_policy: Option<OrgMfaPolicy>,
    /// Platform administrator (ADM-01): always MFA, phishing-resistant only.
    pub is_platform_admin: bool,
    /// The caller demands phishing-resistant MFA for another reason (risk,
    /// admin API, explicit client request).
    pub phishing_resistant_required: bool,
    /// Factor kinds the deployment offers at all (configuration, SMS
    /// provider, passkey feature). `None` means all kinds.
    pub available_factors: Option<Vec<FactorKind>>,
}

/// The outcome of [`evaluate`] (MFA-08).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MfaRequirement {
    /// No second factor needed.
    NotRequired,
    /// Verify one of these (each enrolled and permitted; canonical order).
    Required {
        /// Usable factor kinds.
        allowed_factors: Vec<FactorKind>,
    },
    /// MFA is required but no enrolled factor is permitted: enroll one of
    /// these first (an empty list means the policy cannot be satisfied).
    EnrollmentRequired {
        /// Factor kinds that may be enrolled.
        allowed_factors: Vec<FactorKind>,
    },
}

impl MfaRequirement {
    /// Whether a second factor (verification or enrollment) is needed.
    #[must_use]
    pub fn is_required(&self) -> bool {
        !matches!(self, Self::NotRequired)
    }

    /// The factor kinds of the outcome (empty for `NotRequired`).
    #[must_use]
    pub fn allowed_factors(&self) -> &[FactorKind] {
        match self {
            Self::NotRequired => &[],
            Self::Required { allowed_factors } | Self::EnrollmentRequired { allowed_factors } => {
                allowed_factors
            }
        }
    }
}

/// Whether the requirement comes from someone other than the user (admin
/// role, organization, caller). Only such a requirement blocks the removal
/// of the last factor (MFA-07): the user's own preference never locks the
/// user in.
#[must_use]
pub fn required_by_policy(input: &MfaPolicyInput) -> bool {
    input.is_platform_admin
        || input.phishing_resistant_required
        || input
            .org_policy
            .as_ref()
            .is_some_and(|p| p.mfa_required || p.phishing_resistant_required)
}

/// Whether phishing-resistant factors are mandatory.
#[must_use]
pub fn phishing_resistant_required(input: &MfaPolicyInput) -> bool {
    input.is_platform_admin
        || input.phishing_resistant_required
        || input
            .org_policy
            .as_ref()
            .is_some_and(|p| p.phishing_resistant_required)
}

/// The factor kinds the policy permits, in canonical order.
#[must_use]
pub fn permitted_factors(input: &MfaPolicyInput) -> Vec<FactorKind> {
    let phishing_resistant = phishing_resistant_required(input);
    canonical(FactorKind::ALL.iter().copied().filter(|kind| {
        let available = input
            .available_factors
            .as_ref()
            .is_none_or(|list| list.contains(kind));
        let org_allows = input
            .org_policy
            .as_ref()
            .and_then(|p| p.allowed_factors.as_ref())
            .is_none_or(|list| list.contains(kind));
        available && org_allows && (!phishing_resistant || kind.is_phishing_resistant())
    }))
}

/// Evaluates the MFA policy (MFA-08). Pure and total.
#[must_use]
pub fn evaluate(input: &MfaPolicyInput) -> MfaRequirement {
    let has_primary_factor = input
        .enrolled_factors
        .iter()
        .any(|k| *k != FactorKind::RecoveryCode);
    let required = required_by_policy(input) || input.user_opted_in || has_primary_factor;
    if !required {
        return MfaRequirement::NotRequired;
    }
    let permitted = permitted_factors(input);
    let usable = canonical(
        permitted
            .iter()
            .copied()
            .filter(|k| input.enrolled_factors.contains(k)),
    );
    if usable.iter().any(|k| *k != FactorKind::RecoveryCode) {
        MfaRequirement::Required {
            allowed_factors: usable,
        }
    } else {
        MfaRequirement::EnrollmentRequired {
            allowed_factors: permitted
                .into_iter()
                .filter(|k| *k != FactorKind::RecoveryCode)
                .collect(),
        }
    }
}

/// Deduplicates and orders factor kinds as in [`FactorKind::ALL`].
fn canonical(kinds: impl Iterator<Item = FactorKind>) -> Vec<FactorKind> {
    let kinds: Vec<FactorKind> = kinds.collect();
    FactorKind::ALL
        .iter()
        .copied()
        .filter(|k| kinds.contains(k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: [FactorKind; 4] = [
        FactorKind::Totp,
        FactorKind::Webauthn,
        FactorKind::Email,
        FactorKind::Sms,
    ];

    fn subsets(kinds: &[FactorKind]) -> Vec<Vec<FactorKind>> {
        (0..(1_u32 << kinds.len()))
            .map(|mask| {
                kinds
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, k)| *k)
                    .collect()
            })
            .collect()
    }

    fn org_policies() -> Vec<Option<OrgMfaPolicy>> {
        let lists: Vec<Option<Vec<FactorKind>>> = vec![
            None,
            Some(vec![]),
            Some(vec![FactorKind::Totp]),
            Some(vec![FactorKind::Webauthn]),
            Some(vec![FactorKind::Sms, FactorKind::Email]),
            Some(vec![FactorKind::RecoveryCode]),
            Some(vec![FactorKind::Totp, FactorKind::RecoveryCode]),
            Some(FactorKind::ALL.to_vec()),
        ];
        let mut out = vec![None];
        for required in [false, true] {
            for pr in [false, true] {
                for list in &lists {
                    out.push(Some(OrgMfaPolicy {
                        mfa_required: required,
                        phishing_resistant_required: pr,
                        allowed_factors: list.clone(),
                        trusted_devices_allowed: true,
                    }));
                }
            }
        }
        out
    }

    fn availability() -> Vec<Option<Vec<FactorKind>>> {
        vec![
            None,
            Some(vec![
                FactorKind::Totp,
                FactorKind::Webauthn,
                FactorKind::RecoveryCode,
                FactorKind::Email,
            ]),
            Some(vec![FactorKind::Totp, FactorKind::RecoveryCode]),
        ]
    }

    fn subset_of(a: &[FactorKind], b: &[FactorKind]) -> bool {
        a.iter().all(|k| b.contains(k))
    }

    /// Exhaustive check of every invariant over 2^5 factor sets × opt-in ×
    /// admin × caller requirement × 33 organization policies × 3
    /// availability sets (25 344 inputs).
    #[test]
    fn mfa_08_exhaustive_invariants() {
        let mut checked = 0_u32;
        for enrolled in subsets(FactorKind::ALL) {
            for opted_in in [false, true] {
                for admin in [false, true] {
                    for caller_pr in [false, true] {
                        for org in org_policies() {
                            for available in availability() {
                                let input = MfaPolicyInput {
                                    enrolled_factors: enrolled.clone(),
                                    user_opted_in: opted_in,
                                    org_policy: org.clone(),
                                    is_platform_admin: admin,
                                    phishing_resistant_required: caller_pr,
                                    available_factors: available.clone(),
                                };
                                check_invariants(&input, &evaluate(&input));
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 32 * 2 * 2 * 2 * 33 * 3);
    }

    fn check_invariants(input: &MfaPolicyInput, out: &MfaRequirement) {
        let org = input.org_policy.clone().unwrap_or_default();
        let pr = input.is_platform_admin
            || input.phishing_resistant_required
            || org.phishing_resistant_required;
        let demanded = input.is_platform_admin
            || input.phishing_resistant_required
            || org.mfa_required
            || org.phishing_resistant_required
            || input.user_opted_in
            || input.enrolled_factors.iter().any(|k| PRIMARY.contains(k));
        assert_eq!(out.is_required(), demanded, "{input:?} -> {out:?}");

        let allowed = out.allowed_factors();
        // Canonical order, no duplicates.
        assert_eq!(
            allowed.to_vec(),
            canonical(allowed.iter().copied()),
            "{input:?}"
        );
        // Never wider than the organization, the deployment or the
        // phishing-resistance rule allow.
        if let Some(list) = &org.allowed_factors {
            assert!(subset_of(allowed, list), "{input:?} -> {out:?}");
        }
        if let Some(list) = &input.available_factors {
            assert!(subset_of(allowed, list), "{input:?} -> {out:?}");
        }
        if pr {
            assert!(
                allowed.iter().all(|k| k.is_phishing_resistant()),
                "{input:?} -> {out:?}"
            );
        }
        if input.is_platform_admin {
            assert!(out.is_required());
            assert!(subset_of(allowed, &[FactorKind::Webauthn]), "{out:?}");
        }
        let permitted = permitted_factors(input);
        match out {
            MfaRequirement::NotRequired => {}
            MfaRequirement::Required { allowed_factors } => {
                assert!(subset_of(allowed_factors, &input.enrolled_factors));
                assert!(
                    allowed_factors
                        .iter()
                        .any(|k| *k != FactorKind::RecoveryCode)
                );
                // Complete: every enrolled and permitted factor is offered.
                for k in &input.enrolled_factors {
                    assert_eq!(
                        permitted.contains(k),
                        allowed_factors.contains(k),
                        "{input:?}"
                    );
                }
            }
            MfaRequirement::EnrollmentRequired { allowed_factors } => {
                assert!(!allowed_factors.contains(&FactorKind::RecoveryCode));
                assert!(
                    !input
                        .enrolled_factors
                        .iter()
                        .any(|k| *k != FactorKind::RecoveryCode && permitted.contains(k)),
                    "a usable factor exists: {input:?}"
                );
                let expected: Vec<FactorKind> = permitted
                    .iter()
                    .copied()
                    .filter(|k| *k != FactorKind::RecoveryCode)
                    .collect();
                assert_eq!(allowed_factors, &expected);
            }
        }
    }

    #[test]
    fn mfa_08_user_without_factors_and_policy_needs_nothing() {
        assert_eq!(
            evaluate(&MfaPolicyInput::default()),
            MfaRequirement::NotRequired
        );
    }

    #[test]
    fn mfa_08_enrolled_factor_means_required() {
        let input = MfaPolicyInput {
            enrolled_factors: vec![FactorKind::RecoveryCode, FactorKind::Totp],
            ..MfaPolicyInput::default()
        };
        assert_eq!(
            evaluate(&input),
            MfaRequirement::Required {
                allowed_factors: vec![FactorKind::Totp, FactorKind::RecoveryCode]
            }
        );
        // Recovery codes alone never satisfy (nor trigger) the requirement.
        let only_codes = MfaPolicyInput {
            enrolled_factors: vec![FactorKind::RecoveryCode],
            user_opted_in: true,
            ..MfaPolicyInput::default()
        };
        assert_eq!(
            evaluate(&only_codes),
            MfaRequirement::EnrollmentRequired {
                allowed_factors: vec![
                    FactorKind::Totp,
                    FactorKind::Webauthn,
                    FactorKind::Email,
                    FactorKind::Sms
                ]
            }
        );
    }

    #[test]
    fn mfa_08_org_requirement_without_factors_requires_enrollment() {
        let input = MfaPolicyInput {
            org_policy: Some(OrgMfaPolicy {
                mfa_required: true,
                allowed_factors: Some(vec![FactorKind::Totp, FactorKind::Webauthn]),
                ..OrgMfaPolicy::default()
            }),
            ..MfaPolicyInput::default()
        };
        assert_eq!(
            evaluate(&input),
            MfaRequirement::EnrollmentRequired {
                allowed_factors: vec![FactorKind::Totp, FactorKind::Webauthn]
            }
        );
    }

    #[test]
    fn mfa_08_admin_needs_phishing_resistant_factor() {
        let with_totp = MfaPolicyInput {
            enrolled_factors: vec![FactorKind::Totp, FactorKind::RecoveryCode],
            is_platform_admin: true,
            ..MfaPolicyInput::default()
        };
        assert_eq!(
            evaluate(&with_totp),
            MfaRequirement::EnrollmentRequired {
                allowed_factors: vec![FactorKind::Webauthn]
            }
        );
        let with_passkey = MfaPolicyInput {
            enrolled_factors: vec![FactorKind::Totp, FactorKind::Webauthn],
            is_platform_admin: true,
            ..MfaPolicyInput::default()
        };
        assert_eq!(
            evaluate(&with_passkey),
            MfaRequirement::Required {
                allowed_factors: vec![FactorKind::Webauthn]
            }
        );
    }

    #[test]
    fn mfa_06_org_policy_can_forbid_sms() {
        let input = MfaPolicyInput {
            enrolled_factors: vec![FactorKind::Sms, FactorKind::Email],
            org_policy: Some(OrgMfaPolicy {
                mfa_required: true,
                allowed_factors: Some(vec![
                    FactorKind::Totp,
                    FactorKind::Webauthn,
                    FactorKind::Email,
                ]),
                ..OrgMfaPolicy::default()
            }),
            ..MfaPolicyInput::default()
        };
        assert_eq!(
            evaluate(&input),
            MfaRequirement::Required {
                allowed_factors: vec![FactorKind::Email]
            }
        );
    }

    #[test]
    fn mfa_08_impossible_policy_yields_empty_enrollment_list() {
        let input = MfaPolicyInput {
            org_policy: Some(OrgMfaPolicy {
                mfa_required: true,
                phishing_resistant_required: true,
                ..OrgMfaPolicy::default()
            }),
            available_factors: Some(vec![FactorKind::Totp]),
            ..MfaPolicyInput::default()
        };
        assert_eq!(
            evaluate(&input),
            MfaRequirement::EnrollmentRequired {
                allowed_factors: vec![]
            }
        );
    }

    #[test]
    fn mfa_08_strictest_combination_of_org_policies() {
        let a = OrgMfaPolicy {
            mfa_required: true,
            allowed_factors: Some(vec![FactorKind::Totp, FactorKind::Sms]),
            ..OrgMfaPolicy::default()
        };
        let b = OrgMfaPolicy {
            phishing_resistant_required: false,
            allowed_factors: Some(vec![FactorKind::Sms, FactorKind::Totp, FactorKind::Email]),
            trusted_devices_allowed: false,
            ..OrgMfaPolicy::default()
        };
        let c = a.strictest(&b);
        assert!(c.mfa_required);
        assert!(!c.trusted_devices_allowed);
        assert_eq!(
            c.allowed_factors,
            Some(vec![FactorKind::Totp, FactorKind::Sms])
        );
        assert_eq!(c, b.strictest(&a));
        assert_eq!(
            OrgMfaPolicy::default().strictest(&OrgMfaPolicy::default()),
            OrgMfaPolicy::default()
        );
    }

    #[test]
    fn mfa_08_outcome_serializes_with_status_tag() {
        let json = serde_json::to_value(MfaRequirement::Required {
            allowed_factors: vec![FactorKind::Totp],
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"status": "required", "allowed_factors": ["totp"]})
        );
    }
}
