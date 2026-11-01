//! Organization restrictions on authenticators (PKY-08).
//!
//! Attestation is `none` by default: any authenticator may be registered
//! and nothing about its model is trusted. An organization may restrict
//! passkeys to specific authenticator models (AAGUIDs), e.g. a hardware
//! security key fleet. Such a restriction is only meaningful with
//! *verified* attestation — an AAGUID reported under `none` attestation is
//! self-asserted and trivially forged by a software authenticator. Therefore:
//!
//! * registration under a restricting policy requests `direct` attestation
//!   and `webauthn-rs` verifies the attestation chain against the
//!   configured `[[webauthn.attestation_roots]]` restricted to the allowed
//!   AAGUIDs (a root that vouches for none of them is not trusted at all);
//! * the AAGUID is stored only when it was attested; credentials without a
//!   verified AAGUID never satisfy a restricting policy, also at
//!   authentication time (a policy introduced later applies to existing
//!   passkeys too).
//!
//! The policy is an *input*: authn-org owns organization policies and the
//! server (or authn-session) fills [`PasskeyPolicy`] — see
//! [`crate::hooks::PasskeyPolicySource`].

use std::collections::BTreeSet;

use uuid::Uuid;

/// Authenticator restrictions applying to a user (PKY-08).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasskeyPolicy {
    /// `None`: any authenticator, attestation `none` (default).
    /// `Some(set)`: only authenticators whose *attested* model is in `set`
    /// may be registered or used; an empty set allows none.
    pub allowed_aaguids: Option<BTreeSet<Uuid>>,
}

impl PasskeyPolicy {
    /// No restriction (attestation `none`).
    #[must_use]
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// Only the given attested authenticator models.
    #[must_use]
    pub fn allow_only(aaguids: impl IntoIterator<Item = Uuid>) -> Self {
        Self {
            allowed_aaguids: Some(aaguids.into_iter().collect()),
        }
    }

    /// Whether the policy restricts authenticator models.
    #[must_use]
    pub fn is_restricted(&self) -> bool {
        self.allowed_aaguids.is_some()
    }

    /// Whether a stored credential with the given *attested* AAGUID (`None`
    /// when attestation was not verified) satisfies the policy.
    #[must_use]
    pub fn permits(&self, attested_aaguid: Option<Uuid>) -> bool {
        match &self.allowed_aaguids {
            None => true,
            Some(allowed) => attested_aaguid.is_some_and(|aaguid| allowed.contains(&aaguid)),
        }
    }

    /// The strictest combination of several policies (e.g. every
    /// organization the user is an active member of): the intersection of
    /// the allow-lists. Unrestricted policies do not narrow the result.
    #[must_use]
    pub fn strictest(policies: impl IntoIterator<Item = PasskeyPolicy>) -> Self {
        policies
            .into_iter()
            .fold(Self::unrestricted(), |acc, next| {
                match (acc.allowed_aaguids, next.allowed_aaguids) {
                    (None, other) | (other, None) => Self {
                        allowed_aaguids: other,
                    },
                    (Some(a), Some(b)) => Self {
                        allowed_aaguids: Some(a.intersection(&b).copied().collect()),
                    },
                }
            })
    }
}

#[cfg(feature = "passkey")]
pub(crate) mod trust {
    //! Attestation trust anchors restricted to a policy.

    use std::collections::BTreeSet;

    use authn_core::config::webauthn::AttestationRoot;
    use authn_core::error::AuthError;
    use uuid::Uuid;
    use webauthn_rs::prelude::{AttestationCaList, AttestationCaListBuilder};

    /// Parses the configured roots (fail-fast at start-up; the error names
    /// the entry, never the PEM).
    pub(crate) fn from_config(roots: &[AttestationRoot]) -> Result<AttestationCaList, AuthError> {
        let mut builder = AttestationCaListBuilder::new();
        for (i, root) in roots.iter().enumerate() {
            for aaguid in &root.aaguids {
                builder
                    .insert_device_pem(
                        root.ca_pem.trim().as_bytes(),
                        *aaguid,
                        root.name.clone(),
                        Default::default(),
                    )
                    .map_err(|_| {
                        AuthError::internal(format!(
                            "webauthn.attestation_roots[{i}].ca_pem is not a valid PEM certificate"
                        ))
                    })?;
            }
        }
        Ok(builder.build())
    }

    /// The anchors of `all` that vouch for at least one allowed AAGUID,
    /// each restricted to the allowed AAGUIDs. Roots without an explicit
    /// AAGUID list ("blanket" roots) are never used for a restricting
    /// policy.
    pub(crate) fn restricted_to(
        all: &AttestationCaList,
        allowed: &BTreeSet<Uuid>,
    ) -> Result<AttestationCaList, AuthError> {
        let mut builder = AttestationCaListBuilder::new();
        for ca in all.cas().values() {
            for (aaguid, description) in ca.aaguids() {
                if allowed.contains(aaguid) {
                    builder
                        .insert_device_x509(
                            ca.ca().clone(),
                            *aaguid,
                            description.description_en().to_owned(),
                            description.description_localised().clone(),
                        )
                        .map_err(|_| AuthError::internal("attestation root cannot be encoded"))?;
                }
            }
        }
        Ok(builder.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn pky_08_default_policy_is_unrestricted() {
        let p = PasskeyPolicy::default();
        assert!(!p.is_restricted());
        assert!(p.permits(None));
        assert!(p.permits(Some(id(1))));
    }

    #[test]
    fn pky_08_restricted_policy_requires_an_attested_allowed_model() {
        let p = PasskeyPolicy::allow_only([id(1), id(2)]);
        assert!(p.is_restricted());
        assert!(p.permits(Some(id(1))));
        assert!(!p.permits(Some(id(3))));
        // Unattested credentials never satisfy a restriction.
        assert!(!p.permits(None));
        // An empty allow-list allows nothing (fail closed).
        assert!(!PasskeyPolicy::allow_only([]).permits(Some(id(1))));
    }

    #[test]
    fn pky_08_strictest_intersects_allow_lists() {
        let combined = PasskeyPolicy::strictest([
            PasskeyPolicy::unrestricted(),
            PasskeyPolicy::allow_only([id(1), id(2)]),
            PasskeyPolicy::allow_only([id(2), id(3)]),
        ]);
        assert_eq!(combined, PasskeyPolicy::allow_only([id(2)]));
        assert_eq!(PasskeyPolicy::strictest([]), PasskeyPolicy::unrestricted());
        let disjoint = PasskeyPolicy::strictest([
            PasskeyPolicy::allow_only([id(1)]),
            PasskeyPolicy::allow_only([id(2)]),
        ]);
        assert!(!disjoint.permits(Some(id(1))) && !disjoint.permits(Some(id(2))));
    }
}
