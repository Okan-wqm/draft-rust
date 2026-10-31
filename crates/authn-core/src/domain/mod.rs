//! Shared domain primitives.
//!
//! These types are used across module boundaries. Their *behaviour* beyond
//! basic parsing usually belongs to one module (documented on each type); for
//! example the account state machine lives in `authn-account`, while the
//! [`AccountStatus`] enum lives here so every module can read it.

mod account;
mod amr;
mod email;
mod locale;
mod pagination;
mod phone;
mod principal;

pub use account::AccountStatus;
pub use amr::{AuthMethodRef, ClientKind, FactorKind, LoginMethod};
pub use email::{EmailAddress, EmailError, MAX_EMAIL_INPUT_BYTES};
pub use locale::Locale;
pub use pagination::{Cursor, MAX_PAGE_LIMIT, Page, PageRequest};
pub use phone::{PhoneNumber, PhoneNumberError};
pub use principal::{Impersonation, Principal, PrincipalCredential, Subject};

/// Error returned when parsing one of the string-backed domain enums fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {kind} value")]
pub struct UnknownVariant {
    /// The enum that failed to parse (never the rejected input, which could be
    /// attacker controlled).
    pub kind: &'static str,
}
