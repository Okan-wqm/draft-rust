//! Data this crate needs from other wave-A modules, behind small traits that
//! `authn-server` (or wave B) implements (contracts §2: wave-A crates never
//! depend on each other).
//!
//! | Trait | Data | Owner of the data |
//! |-------|------|-------------------|
//! | [`LoginMethodInventory`] | the user's other sign-in methods (PWD-11) | authn-webauthn (passkeys), authn-oidc-client (linked identities) |
//! | [`ProfileLookup`] | display name and preferred language (PWD-04, notifications) | authn-account (`user_profiles`) |
//!
//! The defaults ([`NoOtherLoginMethods`], [`NoProfiles`]) are safe: without
//! an inventory a password can never be removed; without profiles the
//! request language is used and the display name is not a zxcvbn input.

use async_trait::async_trait;
use authn_core::domain::{Locale, LoginMethod};
use authn_core::error::AuthError;
use authn_core::id::UserId;
use sqlx::PgConnection;

/// Lists a user's sign-in methods other than the password (PWD-11).
///
/// Called inside the password-removal transaction *after* the user row was
/// locked with `SELECT … FOR UPDATE`, so implementations must read through
/// `conn`. Modules that delete passkeys or unlink identities should lock the
/// same user row in their own transaction; then "remove the last passkey"
/// and "remove the password" can never both succeed concurrently.
#[async_trait]
pub trait LoginMethodInventory: Send + Sync {
    /// The user's sign-in methods other than [`LoginMethod::Password`]
    /// (one entry per method kind is enough).
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError>;
}

/// Whether `method` counts as a *strong* replacement for the password
/// (PWD-11): passkeys and linked external identities. E-mail based methods
/// (magic link, e-mail code) are only as strong as the mailbox and do not
/// count.
#[must_use]
pub const fn is_strong_login_method(method: LoginMethod) -> bool {
    matches!(method, LoginMethod::Passkey | LoginMethod::Social)
}

/// Inventory that reports no other methods: password removal is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOtherLoginMethods;

#[async_trait]
impl LoginMethodInventory for NoOtherLoginMethods {
    async fn other_login_methods(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError> {
        Ok(Vec::new())
    }
}

/// Profile data used for strength estimation and notifications.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileHints {
    /// Display name (a zxcvbn user input and the e-mail greeting).
    pub display_name: Option<String>,
    /// Preferred language of the user (ACC-08).
    pub locale: Option<Locale>,
}

/// Reads profile hints of a user (authn-account owns `user_profiles`).
#[async_trait]
pub trait ProfileLookup: Send + Sync {
    /// Profile hints of `user`; `ProfileHints::default()` when unknown.
    async fn profile(&self, user: UserId) -> Result<ProfileHints, AuthError>;
}

/// Lookup that knows no profiles.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProfiles;

#[async_trait]
impl ProfileLookup for NoProfiles {
    async fn profile(&self, _user: UserId) -> Result<ProfileHints, AuthError> {
        Ok(ProfileHints::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwd_11_only_passkeys_and_identities_are_strong() {
        assert!(is_strong_login_method(LoginMethod::Passkey));
        assert!(is_strong_login_method(LoginMethod::Social));
        assert!(!is_strong_login_method(LoginMethod::MagicLink));
        assert!(!is_strong_login_method(LoginMethod::EmailCode));
        assert!(!is_strong_login_method(LoginMethod::Password));
    }
}
