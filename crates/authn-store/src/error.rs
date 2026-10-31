//! Database error classification.
//!
//! `?` on a raw `sqlx::Error` inside a handler yields `internal_error`
//! (see `impl From<sqlx::Error> for AuthError` in authn-core). Code that must
//! react to a specific condition converts to [`StoreError`] first:
//!
//! ```ignore
//! match UserRepository::create(&mut tx, &new).await {
//!     Err(StoreError::UniqueViolation { constraint })
//!         if constraint == "users_email_normalized_key" => { /* ACC-02 */ }
//!     other => other?,
//! }
//! ```
//!
//! **Never** turn a unique violation into a client-visible `conflict` where
//! that would reveal that an account exists (ACC-02, PWD-07).

use authn_core::error::{AuthError, codes};

/// PostgreSQL SQLSTATE codes we classify.
mod sqlstate {
    pub(super) const UNIQUE_VIOLATION: &str = "23505";
    pub(super) const FOREIGN_KEY_VIOLATION: &str = "23503";
    pub(super) const CHECK_VIOLATION: &str = "23514";
    pub(super) const NOT_NULL_VIOLATION: &str = "23502";
    pub(super) const SERIALIZATION_FAILURE: &str = "40001";
    pub(super) const DEADLOCK_DETECTED: &str = "40P01";
    pub(super) const INSUFFICIENT_PRIVILEGE: &str = "42501";
}

/// A classified database error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A unique constraint / index was violated.
    #[error("unique constraint `{constraint}` violated")]
    UniqueViolation {
        /// Constraint or index name.
        constraint: String,
    },
    /// A foreign key was violated.
    #[error("foreign key `{constraint}` violated")]
    ForeignKeyViolation {
        /// Constraint name.
        constraint: String,
    },
    /// A CHECK / NOT NULL constraint (or a tenant-isolation trigger) was
    /// violated — usually a bug in the caller's validation.
    #[error("check constraint `{constraint}` violated")]
    CheckViolation {
        /// Constraint name (may be empty for NOT NULL).
        constraint: String,
    },
    /// Serialization failure or deadlock: the transaction may be retried.
    #[error("transaction conflict (retryable)")]
    Retryable(#[source] sqlx::Error),
    /// The statement was refused by a guard (append-only audit table,
    /// missing privilege).
    #[error("operation not permitted by the database")]
    NotPermitted(#[source] sqlx::Error),
    /// Expected row not found.
    #[error("row not found")]
    NotFound,
    /// A stored value could not be mapped to the domain type.
    #[error("stored value is invalid: {0}")]
    Corrupt(&'static str),
    /// Invalid configuration (never contains the URL or credentials).
    #[error("invalid database configuration: {0}")]
    Config(&'static str),
    /// Any other database error.
    #[error("database error")]
    Other(#[source] sqlx::Error),
}

impl StoreError {
    /// Whether this is a unique violation of the named constraint.
    #[must_use]
    pub fn is_unique_violation(&self, constraint_name: &str) -> bool {
        matches!(self, Self::UniqueViolation { constraint } if constraint == constraint_name)
    }

    /// Whether retrying the whole transaction may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        if matches!(err, sqlx::Error::RowNotFound) {
            return Self::NotFound;
        }
        let Some(db) = err.as_database_error() else {
            return Self::Other(err);
        };
        let constraint = db.constraint().unwrap_or_default().to_owned();
        match db.code().as_deref() {
            Some(sqlstate::UNIQUE_VIOLATION) => Self::UniqueViolation { constraint },
            Some(sqlstate::FOREIGN_KEY_VIOLATION) => Self::ForeignKeyViolation { constraint },
            Some(sqlstate::CHECK_VIOLATION | sqlstate::NOT_NULL_VIOLATION) => {
                Self::CheckViolation { constraint }
            }
            Some(sqlstate::SERIALIZATION_FAILURE | sqlstate::DEADLOCK_DETECTED) => {
                Self::Retryable(err)
            }
            Some(sqlstate::INSUFFICIENT_PRIVILEGE) => Self::NotPermitted(err),
            _ => Self::Other(err),
        }
    }
}

/// Default mapping to the client-facing error model. Unique violations become
/// `conflict`; callers on anti-enumeration paths must handle them first.
impl From<StoreError> for AuthError {
    fn from(err: StoreError) -> Self {
        let code = match &err {
            StoreError::UniqueViolation { .. } => codes::common::CONFLICT,
            StoreError::NotFound => codes::common::NOT_FOUND,
            StoreError::Retryable(_) => codes::common::SERVICE_UNAVAILABLE,
            _ => codes::common::INTERNAL_ERROR,
        };
        AuthError::new(code).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_not_found_maps_to_not_found() {
        let err = StoreError::from(sqlx::Error::RowNotFound);
        assert!(matches!(err, StoreError::NotFound));
        assert_eq!(AuthError::from(err).code(), codes::common::NOT_FOUND);
    }

    #[test]
    fn unique_violation_helpers() {
        let err = StoreError::UniqueViolation {
            constraint: "users_email_normalized_key".into(),
        };
        assert!(err.is_unique_violation("users_email_normalized_key"));
        assert!(!err.is_unique_violation("other"));
        assert!(!err.is_retryable());
        assert_eq!(AuthError::from(err).code(), codes::common::CONFLICT);
    }
}
