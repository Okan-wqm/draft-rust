//! Account status values (ACC-06).
//!
//! The *state machine* (which transitions are legal, auditing every
//! transition) is owned by `authn-account`; this crate only defines the
//! values so that every module can read a user's status.

text_enum! {
    /// Lifecycle status of a user account, stored in `users.status`.
    pub enum AccountStatus {
        /// Registered, e-mail not yet verified.
        PendingVerification => "pending_verification",
        /// Normal, usable account.
        Active => "active",
        /// Temporarily locked until `users.locked_until`.
        Locked => "locked",
        /// Suspended by a platform admin.
        Suspended => "suspended",
        /// Disabled (e.g. by the user or an admin); no login possible.
        Disabled => "disabled",
        /// Deletion requested; cancellable during the grace period (ACC-09).
        PendingDeletion => "pending_deletion",
        /// Terminal state: personal data erased or anonymised.
        Deleted => "deleted",
    }
}

impl AccountStatus {
    /// Whether the status is terminal (no transition out of it is allowed).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acc_06_status_wire_format_matches_database_values() {
        for status in AccountStatus::ALL {
            let json = serde_json::to_string(status).unwrap();
            assert_eq!(json, format!("\"{}\"", status.as_str()));
            assert_eq!(status.as_str().parse::<AccountStatus>().unwrap(), *status);
        }
        assert!("ACTIVE".parse::<AccountStatus>().is_err());
        assert!(AccountStatus::Deleted.is_terminal());
        assert!(!AccountStatus::Active.is_terminal());
    }
}
