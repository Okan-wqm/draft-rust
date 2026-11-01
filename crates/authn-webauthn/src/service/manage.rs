//! Passkey management (PKY-04): list, rename, delete.

use authn_core::domain::{LoginMethod, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::CredentialId;
use authn_core::ports::SecurityEventKind;
use authn_store::UserRepository;

use super::{PasskeySummary, WebauthnService, summary};
use crate::metrics;
use crate::name::normalize_name;
use crate::store::credentials;

impl WebauthnService {
    /// The caller's passkeys, oldest first (PKY-04). Readable under
    /// read-only impersonation; contains no key material.
    pub async fn list_passkeys(
        &self,
        principal: &Principal,
    ) -> Result<Vec<PasskeySummary>, AuthError> {
        let user = Self::reading_user(principal)?;
        let rows = credentials::list_for_user(self.pool(), user).await?;
        Ok(rows.iter().map(summary).collect())
    }

    /// Renames one of the caller's passkeys. Unknown ids and other users'
    /// passkeys answer `not_found` alike.
    pub async fn rename_passkey(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        id: CredentialId,
        name: &str,
    ) -> Result<PasskeySummary, AuthError> {
        principal.require_writable()?;
        let user = principal.require_user()?;
        let name = normalize_name(name)?;
        let mut tx = self.begin().await?;
        let row = credentials::rename(&mut tx, id, user, &name)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        // The (user-chosen) name never goes into the audit log (AUD-03).
        let event = self
            .event(
                SecurityEventKind::PasskeyRenamed,
                ctx,
                user,
                Some(principal),
            )
            .with_resource("passkey", row.id);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(summary(&row))
    }

    /// Deletes one of the caller's passkeys (PKY-04). Requires step-up
    /// (SES-13). Refused when it would leave the account without any way to
    /// sign in (`passkey_last_login_method`) or without a second factor
    /// while MFA is mandatory (`mfa_last_factor_required`). The user row is
    /// locked for the whole decision, which serializes it with password
    /// removal and identity unlinking.
    pub async fn delete_passkey(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        id: CredentialId,
    ) -> Result<(), AuthError> {
        principal.require_writable()?;
        let user = principal.require_user()?;
        self.require_step_up(principal)?;

        let mut tx = self.begin().await?;
        let account = UserRepository::lock_for_update(&mut tx, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let all = credentials::list_for_user(&mut *tx, user).await?;
        let Some(target) = all.iter().find(|row| row.id == id) else {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        };
        let remaining: Vec<_> = all.iter().filter(|row| row.id != id).collect();

        let remaining_login_capable = remaining
            .iter()
            .any(|row| row.usage().allows_passwordless());
        if target.usage().allows_passwordless() && !remaining_login_capable {
            let others = self
                .deps()
                .account_methods
                .other_login_methods(&mut tx, user)
                .await?;
            if !others.iter().any(|m| *m != LoginMethod::Passkey) {
                return Err(AuthError::new(codes::webauthn::PASSKEY_LAST_LOGIN_METHOD));
            }
        }
        if remaining.is_empty() {
            let mfa = self.deps().account_methods.mfa_facts(&mut tx, user).await?;
            if mfa.mfa_required && mfa.other_factor_count == 0 {
                return Err(AuthError::new(codes::mfa::MFA_LAST_FACTOR_REQUIRED));
            }
        }

        if !credentials::delete(&mut tx, id, user).await? {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        self.notify_factor_change(&mut tx, ctx, &account, false)
            .await?;
        let event = self
            .event(
                SecurityEventKind::PasskeyRemoved,
                ctx,
                user,
                Some(principal),
            )
            .with_resource("passkey", id)
            .with_meta("remaining", remaining.len());
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        metrics::passkey_removed();
        tracing::info!(user = %user, passkey = %id, "passkey removed");
        Ok(())
    }
}
