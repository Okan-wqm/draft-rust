//! Password verification for login and step-up (used by authn-session):
//! CRY-03 rehash, CRY-04 legacy upgrade, CRY-05 dummy verification, PWD-12
//! `must_change_password`.

use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{Actor, SecurityEventKind};
use authn_core::secret::SecretString;
use authn_crypto::password::{RehashReason, VerifyOutcome};
use authn_store::{NewPasswordHash, PasswordCredentialRecord, UserRepository, begin, commit};
use uuid::Uuid;

use super::{PasswordService, stored_hash};
use crate::metrics;

/// Result of [`PasswordService::verify_login_password`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum LoginPasswordOutcome {
    /// The password is correct.
    Valid,
    /// The password is correct, but an administrator requires a new one
    /// (PWD-12): issue the `change_password` required action (SES-22), never
    /// a full session.
    MustChangePassword,
    /// Wrong password, unknown account or account without a password. The
    /// caller answers `invalid_credentials` without distinguishing (SES-01).
    Invalid,
}

impl LoginPasswordOutcome {
    /// Whether the password was correct.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        !matches!(self, Self::Invalid)
    }
}

impl PasswordService {
    /// Verifies a password presented at login or step-up.
    ///
    /// * `user = None` (no account for the submitted identifier) performs
    ///   the same database read and an equal-cost Argon2 verification
    ///   against a dummy hash (CRY-05), then answers `Invalid`.
    /// * Accounts without a password (passwordless, PWD-10) do the same
    ///   dummy work.
    /// * A correct password whose stored hash uses outdated parameters, an
    ///   old pepper version or a legacy scheme (bcrypt, PBKDF2, wrapped
    ///   MD5/SHA-1) is re-hashed with the current Argon2id settings
    ///   (CRY-03, CRY-04). The upgrade is a compare-and-set on the verified
    ///   hash, so a concurrent password change is never overwritten; its
    ///   failure is logged and never fails the login.
    ///
    /// Account status (suspended, locked…) is *not* checked here: the login
    /// flow reveals it only after a correct password (SES-01).
    pub async fn verify_login_password(
        &self,
        ctx: &RequestContext,
        user: Option<UserId>,
        password: &SecretString,
    ) -> Result<LoginPasswordOutcome, AuthError> {
        // Same query for known and unknown accounts (the nil id never exists).
        let lookup = user.unwrap_or_else(|| UserId::from_uuid(Uuid::nil()));
        let credential = UserRepository::find_password(self.pool(), lookup).await?;
        let credential = if user.is_some() { credential } else { None };
        let stored = credential.as_ref().map(stored_hash);
        let outcome = self.deps().hasher.verify(password, stored.as_ref()).await?;
        let (VerifyOutcome::Valid { rehash }, Some(credential), Some(user)) =
            (outcome, credential, user)
        else {
            return Ok(LoginPasswordOutcome::Invalid);
        };
        // K-110: an expired password (the unused one-time initial password
        // of a break-glass admin) is refused like a wrong one, after the
        // same verification work (no status, body or timing difference).
        if credential.expires_at.is_some_and(|at| at <= self.now()) {
            tracing::warn!(user_id = %user, "expired password presented");
            return Ok(LoginPasswordOutcome::Invalid);
        }
        if let Some(reason) = rehash
            && let Err(err) = self
                .upgrade_hash(ctx, user, &credential, password, reason)
                .await
        {
            tracing::warn!(error = %err, user_id = %user, "password rehash failed");
        }
        Ok(if credential.must_change {
            LoginPasswordOutcome::MustChangePassword
        } else {
            LoginPasswordOutcome::Valid
        })
    }

    /// Replaces a stale hash of a verified password (CRY-03, CRY-04).
    async fn upgrade_hash(
        &self,
        ctx: &RequestContext,
        user: UserId,
        credential: &PasswordCredentialRecord,
        password: &SecretString,
        reason: RehashReason,
    ) -> Result<(), AuthError> {
        let record = self.deps().hasher.hash(password).await?;
        let mut tx = begin(self.pool()).await?;
        let replaced = UserRepository::rehash_password(
            &mut tx,
            user,
            &credential.password_hash,
            &NewPasswordHash {
                password_hash: &record.hash,
                algorithm: record.algorithm.as_str(),
                pepper_version: record.pepper_version,
            },
        )
        .await?;
        if !replaced {
            // The password changed concurrently: keep the newer hash.
            return Ok(());
        }
        let event = self
            .event(SecurityEventKind::PasswordRehashed, ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
            .with_meta("reason", rehash_reason(reason))
            .with_meta("from_algorithm", credential.algorithm.as_str())
            .with_meta("to_algorithm", record.algorithm.as_str());
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        commit(tx).await?;
        metrics::password_updated("rehashed");
        Ok(())
    }
}

const fn rehash_reason(reason: RehashReason) -> &'static str {
    match reason {
        RehashReason::OutdatedParameters => "outdated_parameters",
        RehashReason::OutdatedPepper => "outdated_pepper",
        RehashReason::LegacyAlgorithm => "legacy_algorithm",
    }
}
