//! Typed identifiers (ARC-05).
//!
//! Every entity id is a UUIDv7 wrapped in its own newtype so that a `UserId`
//! can never be passed where an `OrgId` is expected. UUIDv7 values are time
//! ordered (good B-tree locality) and carry 74 random bits, so they are not
//! guessable; sequential integers are never exposed.
//!
//! All ids:
//! * serialize as the canonical hyphenated lowercase UUID string,
//! * map to the PostgreSQL `uuid` type (including `uuid[]` arrays),
//! * parse strictly from the 36-character hyphenated form via [`FromStr`].

use std::fmt;
use std::str::FromStr;

use uuid::Uuid;

/// Error returned when parsing a typed id from a string fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid identifier")]
pub struct IdParseError;

/// Parses a canonical, hyphenated UUID (36 characters). Other textual forms
/// accepted by the `uuid` crate (braced, URN, simple) are rejected so that a
/// given id has exactly one textual representation.
pub fn parse_canonical_uuid(input: &str) -> Result<Uuid, IdParseError> {
    if input.len() != 36 {
        return Err(IdParseError);
    }
    Uuid::try_parse(input).map_err(|_| IdParseError)
}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            sqlx::Type,
            utoipa::ToSchema,
        )]
        #[serde(transparent)]
        #[sqlx(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a fresh UUIDv7 identifier (CSPRNG-backed random bits).
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID (loaded from storage or parsed input).
            #[must_use]
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// Returns the wrapped UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.hyphenated())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_canonical_uuid(s).map(Self)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self(id)
            }
        }
    };
}

define_id!(
    /// A user account (`users.id`).
    UserId
);
define_id!(
    /// An organization / tenant (`organizations.id`).
    OrgId
);
define_id!(
    /// A login session; also the refresh-token family id (`sessions.id`).
    SessionId
);
define_id!(
    /// A refresh token in a rotation lineage (`refresh_tokens.id`).
    RefreshTokenId
);
define_id!(
    /// An organization membership (`memberships.id`).
    MembershipId
);
define_id!(
    /// A role, built-in or organization specific (`roles.id`).
    RoleId
);
define_id!(
    /// An organization invitation (`invitations.id`).
    InvitationId
);
define_id!(
    /// An API key (`api_keys.id`).
    ApiKeyId
);
define_id!(
    /// A service account (`service_accounts.id`).
    ServiceAccountId
);
define_id!(
    /// A WebAuthn credential row (`webauthn_credentials.id`); not the raw
    /// authenticator credential id.
    CredentialId
);
define_id!(
    /// A WebAuthn ceremony state (`webauthn_ceremonies.id`).
    CeremonyId
);
define_id!(
    /// An MFA factor (`mfa_factors.id`).
    FactorId
);
define_id!(
    /// A batch of recovery codes (`recovery_codes.batch_id`).
    RecoveryCodeBatchId
);
define_id!(
    /// A trusted device record (`trusted_devices.id`).
    TrustedDeviceId
);
define_id!(
    /// A pending authentication challenge (`auth_challenges.id`).
    ChallengeId
);
define_id!(
    /// A one-time token or code (`one_time_tokens.id`).
    OneTimeTokenId
);
define_id!(
    /// A federated identity link (`identities.id`).
    IdentityId
);
define_id!(
    /// A pending OAuth/OIDC authorization state (`oauth_states.id`).
    OAuthStateId
);
define_id!(
    /// A domain claimed by an organization (`org_domains.id`).
    OrgDomainId
);
define_id!(
    /// An audit / security event (`audit_events.id`) or a domain event.
    EventId
);
define_id!(
    /// An outbox message (`outbox.id`).
    OutboxMessageId
);
define_id!(
    /// A webhook endpoint (`webhook_endpoints.id`).
    WebhookEndpointId
);
define_id!(
    /// A webhook delivery attempt record (`webhook_deliveries.id`).
    WebhookDeliveryId
);
define_id!(
    /// A JWT signing key; its hyphenated form is the JWS `kid`.
    SigningKeyId
);
define_id!(
    /// A data encryption key (`data_encryption_keys.id`).
    DataKeyId
);
define_id!(
    /// A published terms / privacy-policy version (`terms_versions.id`).
    TermsVersionId
);
define_id!(
    /// A proof-of-work CAPTCHA challenge (`captcha_pow_challenges.id`).
    CaptchaChallengeId
);
define_id!(
    /// An account deletion request (`account_deletions.id`).
    DeletionRequestId
);
define_id!(
    /// The id of one HTTP request; echoed in `x-request-id` and error envelopes.
    RequestId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_05_generated_ids_are_uuid_v7_and_unique() {
        let a = UserId::generate();
        let b = UserId::generate();
        assert_ne!(a, b);
        assert_eq!(a.as_uuid().get_version_num(), 7);
    }

    #[test]
    fn arc_05_ids_round_trip_through_string_and_json() {
        let id = OrgId::generate();
        let text = id.to_string();
        assert_eq!(text.len(), 36);
        assert_eq!(text.parse::<OrgId>(), Ok(id));
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{text}\""));
        let back: OrgId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn arc_05_non_canonical_forms_are_rejected() {
        let id = UserId::generate().as_uuid();
        assert!(id.simple().to_string().parse::<UserId>().is_err());
        assert!(id.braced().to_string().parse::<UserId>().is_err());
        assert!(id.urn().to_string().parse::<UserId>().is_err());
        assert!("".parse::<UserId>().is_err());
        assert!(
            "not-a-uuid-not-a-uuid-not-a-uuid-xx"
                .parse::<UserId>()
                .is_err()
        );
    }

    #[test]
    fn arc_05_debug_names_the_type() {
        let id = SessionId::from_uuid(Uuid::nil());
        assert_eq!(
            format!("{id:?}"),
            "SessionId(00000000-0000-0000-0000-000000000000)"
        );
    }
}
