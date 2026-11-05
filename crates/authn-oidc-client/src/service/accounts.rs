//! Account matching, linking and unlinking (SOC-05, SOC-06, SOC-08),
//! with the pre-hijacking rules of ADR 0002.
//!
//! Login with an external identity:
//!
//! 1. `(provider, subject)` already linked → that account (never matched
//!    by e-mail, SOC-05). The identity's attributes are refreshed.
//! 2. Otherwise the provider must assert a **verified** address — checked
//!    *before* any account lookup, so the answer
//!    (`oauth_email_not_verified`) never depends on existing accounts.
//! 3. No account and no reservation for the address → a new account is
//!    created `active` with the address verified (the provider proved the
//!    mailbox), with its `user_profiles` row (display name, language), and
//!    the identity is linked, in one transaction. Account creation,
//!    the ACC-07 reservation check and the ACC-12 domain list are
//!    authn-account's (`AccountService::provision_verified_user_in_tx`,
//!    under the address lock; K-02, K-33) — there is no way to wire a
//!    reservation stand-in.
//! 4. An account with that address exists → **no automatic merge**
//!    (`oauth_link_required`: sign in and link), unless
//!    `oidc_client.auto_link_verified_email` is on **and** the provider is
//!    listed in `auto_link_trusted_providers`. Auto-linking locks the user
//!    row, and for an unverified (`pending_verification`) account first
//!    applies `AccountService::confirm_mailbox_control_in_tx(…,
//!    MailboxProof::Passwordless)`: pending registrations and the unproven
//!    password are discarded and every session is revoked, so nobody who
//!    registered the address without owning it keeps anything ("classic
//!    federated merge" / "trojan identifier" classes). Identities are never
//!    attached to a `pending_verification` account.
//!
//! Explicit linking (signed in, step-up) is allowed only for `active`
//! accounts with a verified address; a browser link flow re-validates the
//! session that started it ([`crate::SessionLiveness`], K-03). Unlinking
//! locks the user row first (`UserRepository::lock_for_update`, PWD-11)
//! and refuses to remove the last way to sign in
//! ([`crate::LoginMethodInventory`]). Linking (explicit or automatic) and
//! unlinking send an `identity_linked` / `identity_unlinked` notice to the
//! account's address in the same transaction (outbox, K-18); unlinking an
//! Apple identity queues the revocation of its stored token (K-35).

use authn_account::{MailboxProof, ProvisionOutcome, VerifiedUserProvision};
use authn_core::domain::{
    AccountStatus, AuthMethodRef, ClientKind, EmailAddress, LoginMethod, Principal,
};
use authn_core::error::{AuthError, codes as common};
use authn_core::http::RequestContext;
use authn_core::id::{IdentityId, SessionId, UserId};
use authn_core::ports::{
    Actor, LoginOutcome, Notification, NotificationKind, PrimaryAuthentication, SecurityEvent,
    SecurityEventKind,
};
use authn_core::secret::SensitiveString;
use authn_store::{UserRecord, UserRepository};
use serde::Serialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::OidcClientService;
use crate::codes;
use crate::identity::ExternalIdentity;
use crate::store::{
    self, IdentityRow, NewIdentity, PROVIDER_SUBJECT_KEY, SealedTokens, USER_PROVIDER_KEY,
};

/// Upper bound on waiting for the user row lock.
const LOCK_TIMEOUT_SQL: &str = "SET LOCAL lock_timeout = '5s'";

/// A linked identity as shown to its owner (no tokens, no subject).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IdentitySummary {
    /// Identity id (for `DELETE /v1/me/identities/{identity_id}`).
    pub id: IdentityId,
    /// Provider (`google`, `apple`, `microsoft`, `github`, `oidc:<slug>`).
    pub provider: String,
    /// Address asserted by the provider.
    pub email: Option<String>,
    /// Whether the provider verified it.
    pub email_verified: bool,
    /// Display name from the provider.
    pub display_name: Option<String>,
    /// When it was linked.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Last login with it.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
}

impl From<&IdentityRow> for IdentitySummary {
    fn from(row: &IdentityRow) -> Self {
        Self {
            id: row.id,
            provider: row.provider.clone(),
            email: row.email.clone(),
            email_verified: row.email_verified,
            display_name: row.display_name.clone(),
            created_at: row.created_at,
            last_login_at: row.last_login_at,
        }
    }
}

/// Decrypted provider tokens (SOC-08).
#[derive(Debug, Clone)]
pub struct StoredProviderTokens {
    /// Access token.
    pub access_token: SensitiveString,
    /// Refresh token.
    pub refresh_token: Option<SensitiveString>,
    /// Access-token expiry.
    pub expires_at: Option<OffsetDateTime>,
}

enum Resolution {
    User(UserId),
    /// A concurrent request created the account / identity first: run the
    /// decision again on the committed state.
    Retry,
}

fn linkable(user: &UserRecord) -> bool {
    user.status == AccountStatus::Active && user.is_email_verified()
}

/// A linked identity of a generic provider belongs to the issuer it was
/// created under. The slug → issuer mapping is configuration: after an
/// `issuer_url` change the same `subject` names somebody else (another
/// issuer's namespace), so it must not reach the old identity's account.
/// Built-in providers have fixed issuers (Microsoft's tenant is part of the
/// subject), so the rule applies to generic providers only.
fn ensure_same_issuer(row: &IdentityRow, external: &ExternalIdentity) -> Result<(), AuthError> {
    if external.provider.starts_with("oidc:") && row.issuer != external.issuer {
        return Err(crate::id_token::invalid(
            "linked identity belongs to another issuer",
        ));
    }
    Ok(())
}

impl OidcClientService {
    fn auto_link_allowed(&self, provider: &str) -> bool {
        let cfg = &self.settings().config;
        cfg.auto_link_verified_email
            && cfg
                .auto_link_trusted_providers
                .iter()
                .any(|p| p == provider || format!("oidc:{p}") == provider)
    }

    fn identity_event(
        &self,
        kind: SecurityEventKind,
        ctx: &RequestContext,
        user: UserId,
        identity: IdentityId,
        provider: &str,
    ) -> SecurityEvent {
        SecurityEvent::new(kind, self.now())
            .with_context(ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
            .with_resource("identity", identity)
            .with_meta("provider", provider.to_owned())
    }

    /// Stores or clears the sealed provider tokens of an identity (SOC-08):
    /// with `oidc_client.store_provider_tokens` every token is kept; with
    /// it off only a refresh token needed for revocation is kept (Apple,
    /// `revoke_tokens_on_deletion`, K-35) and everything else is cleared.
    /// Every column is envelope encrypted with the row as AAD.
    async fn store_tokens(
        &self,
        conn: &mut PgConnection,
        identity: IdentityId,
        external: &ExternalIdentity,
    ) -> Result<(), AuthError> {
        let store_all = self.settings().config.store_provider_tokens;
        let keep_refresh = self
            .provider_by_storage_id(&external.provider)
            .is_some_and(|p| p.keep_refresh_token_for_revocation);
        if !store_all && !keep_refresh {
            self.queue_replaced_refresh_token(conn, identity, None)
                .await?;
            store::set_tokens(conn, identity, &SealedTokens::default()).await?;
            return Ok(());
        }
        let Some(tokens) = &external.tokens else {
            // Nothing new (e.g. a native login without an authorization
            // code): the stored tokens stay as they are.
            return Ok(());
        };
        if !store_all && tokens.refresh_token.is_none() {
            return Ok(());
        }
        // K-59: the refresh token about to be overwritten (or cleared)
        // stays valid at the provider until revoked.
        self.queue_replaced_refresh_token(
            conn,
            identity,
            tokens.refresh_token.as_ref().map(|r| r.expose().as_bytes()),
        )
        .await?;
        let access = if store_all {
            Some(
                self.seal(
                    "identities",
                    "access_token_ciphertext",
                    identity,
                    tokens.access_token.expose().as_bytes(),
                )
                .await?,
            )
        } else {
            None
        };
        let refresh = match &tokens.refresh_token {
            Some(r) => Some(
                self.seal(
                    "identities",
                    "refresh_token_ciphertext",
                    identity,
                    r.expose().as_bytes(),
                )
                .await?,
            ),
            None => None,
        };
        store::set_tokens(
            conn,
            identity,
            &SealedTokens {
                access: access.as_deref(),
                refresh: refresh.as_deref(),
                expires_at: if store_all { tokens.expires_at } else { None },
                client_id: external.client_id.as_deref(),
            },
        )
        .await?;
        Ok(())
    }

    /// K-59: queues the stored refresh token of `identity` for revocation
    /// when a sign-in replaces it with `replacement` (`None`: cleared). The
    /// row is locked first, so concurrent sign-ins each queue the token
    /// they actually replace.
    async fn queue_replaced_refresh_token(
        &self,
        conn: &mut PgConnection,
        identity: IdentityId,
        replacement: Option<&[u8]>,
    ) -> Result<(), AuthError> {
        let Some(row) = store::lock_identity(&mut *conn, identity).await? else {
            return Ok(());
        };
        if row.refresh_token_ciphertext.is_none() {
            return Ok(());
        }
        super::revocation::queue_replaced_token(
            conn,
            &self.deps().envelopes,
            self.deps().audit.as_ref(),
            self.now(),
            row.user_id,
            &row,
            replacement,
        )
        .await?;
        Ok(())
    }

    /// Queues an `identity_linked` / `identity_unlinked` notice to the
    /// account's current address in the caller's transaction (K-18).
    async fn notify_identity_change(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        provider: &str,
        linked: bool,
    ) -> Result<(), AuthError> {
        let Some((recipient, locale)) = self
            .deps()
            .accounts
            .notification_recipient_in(&mut *conn, user, ctx.locale)
            .await?
        else {
            return Ok(());
        };
        let provider = self
            .provider_by_storage_id(provider)
            .map_or_else(|| provider.to_owned(), |p| p.display_name.clone());
        let at = self.now();
        let kind = if linked {
            NotificationKind::IdentityLinked { provider, at }
        } else {
            NotificationKind::IdentityUnlinked { provider, at }
        };
        self.deps()
            .notifier
            .notify_in_tx(
                conn,
                Notification {
                    recipient,
                    locale,
                    kind,
                },
            )
            .await
    }

    async fn insert_identity(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        external: &ExternalIdentity,
    ) -> Result<Result<IdentityId, &'static str>, AuthError> {
        let id = IdentityId::generate();
        let result = store::insert_identity(
            conn,
            &NewIdentity {
                id,
                user_id: user,
                provider: &external.provider,
                subject: &external.subject,
                issuer: external.issuer.as_deref(),
                email: external.email.as_deref(),
                email_verified: external.email_verified,
                display_name: external.display_name.as_deref(),
                now: self.now(),
            },
        )
        .await;
        match result {
            Ok(()) => Ok(Ok(id)),
            Err(e) if e.is_unique_violation(PROVIDER_SUBJECT_KEY) => Ok(Err(PROVIDER_SUBJECT_KEY)),
            Err(e) if e.is_unique_violation(USER_PROVIDER_KEY) => Ok(Err(USER_PROVIDER_KEY)),
            Err(e) => Err(e.into()),
        }
    }

    /// Turns a verified external identity into a login (session or
    /// challenge) through the `SessionIssuer` port (SOC-05, SOC-09).
    pub(crate) async fn login_with_identity(
        &self,
        ctx: &RequestContext,
        external: &ExternalIdentity,
        client: ClientKind,
        remember_me: bool,
        shared_device: bool,
    ) -> Result<LoginOutcome, AuthError> {
        let mut user = None;
        for _ in 0..2 {
            match self.resolve(ctx, external).await? {
                Resolution::User(id) => {
                    user = Some(id);
                    break;
                }
                Resolution::Retry => {}
            }
        }
        let user = user.ok_or_else(|| {
            AuthError::new(common::common::SERVICE_UNAVAILABLE)
                .with_context("identity resolution kept conflicting")
        })?;
        let auth = PrimaryAuthentication {
            user_id: user,
            method: LoginMethod::Social,
            amr: vec![AuthMethodRef::Fed],
            client,
            remember_me,
            shared_device,
            requested_org: None,
            // SOC-09: the provider's MFA is forwarded only when trusted by
            // configuration; the session pipeline applies the policy (and
            // never accepts it where phishing resistance is required).
            provider_asserted_mfa: self.settings().config.trust_provider_mfa
                && external.provider_mfa,
        };
        self.deps()
            .sessions
            .complete_primary_authentication(ctx, auth)
            .await
    }

    async fn resolve(
        &self,
        ctx: &RequestContext,
        external: &ExternalIdentity,
    ) -> Result<Resolution, AuthError> {
        let now = self.now();
        let mut tx = authn_store::begin(&self.deps().pool).await?;
        if let Some(row) =
            store::find_identity(&mut *tx, &external.provider, &external.subject).await?
        {
            ensure_same_issuer(&row, external)?;
            store::touch_identity(
                &mut tx,
                row.id,
                external.email.as_deref(),
                external.email_verified,
                external.display_name.as_deref(),
                now,
            )
            .await?;
            self.store_tokens(&mut tx, row.id, external).await?;
            authn_store::commit(tx).await?;
            return Ok(Resolution::User(row.user_id));
        }

        // Only a provider-verified address may create or reach an account;
        // decided before any lookup (no account-existence signal).
        let email = external
            .verified_email()
            .and_then(|e| EmailAddress::parse(e).ok())
            .ok_or_else(|| AuthError::new(codes::OAUTH_EMAIL_NOT_VERIFIED))?;

        let provisioned = self
            .deps()
            .accounts
            .provision_verified_user_in_tx(
                &mut tx,
                ctx,
                VerifiedUserProvision {
                    email: &email,
                    display_name: external.display_name.as_deref(),
                    locale: ctx.locale,
                    method: "social",
                    provider: Some(&external.provider),
                },
            )
            .await?;
        match provisioned {
            // ACC-07: the address is held for its previous owner during an
            // e-mail change's revert period — never a new account.
            ProvisionOutcome::Reserved => Err(AuthError::new(codes::OAUTH_LINK_REQUIRED)),
            ProvisionOutcome::Conflict => Ok(Resolution::Retry),
            ProvisionOutcome::Created(user) => {
                let Ok(identity) = self.insert_identity(&mut tx, user, external).await? else {
                    return Ok(Resolution::Retry);
                };
                self.store_tokens(&mut tx, identity, external).await?;
                let linked = self
                    .identity_event(
                        SecurityEventKind::IdentityLinked,
                        ctx,
                        user,
                        identity,
                        &external.provider,
                    )
                    .with_meta("linked_by", "signup");
                self.deps().audit.record_in_tx(&mut tx, linked).await?;
                authn_store::commit(tx).await?;
                crate::metrics::account_created(&external.provider);
                Ok(Resolution::User(user))
            }
            ProvisionOutcome::Existing(existing) => {
                // The identity may have been linked by a concurrent first
                // sign-in that held the address lock before us (double
                // submit, app retry): look again under the lock and, if
                // so, run the decision again (it then signs in by
                // `(provider, subject)`) instead of refusing the user's
                // own identity with `oauth_link_required`.
                if store::find_identity(&mut *tx, &external.provider, &external.subject)
                    .await?
                    .is_some()
                {
                    return Ok(Resolution::Retry);
                }
                let eligible = matches!(
                    existing.status,
                    AccountStatus::Active | AccountStatus::PendingVerification
                );
                if !self.auto_link_allowed(&external.provider) || !eligible {
                    return Err(AuthError::new(codes::OAUTH_LINK_REQUIRED));
                }
                sqlx::query(LOCK_TIMEOUT_SQL).execute(&mut *tx).await?;
                let locked = UserRepository::lock_for_update(&mut tx, existing.id)
                    .await?
                    .ok_or_else(|| AuthError::new(codes::OAUTH_LINK_REQUIRED))?;
                if !matches!(
                    locked.status,
                    AccountStatus::Active | AccountStatus::PendingVerification
                ) {
                    return Err(AuthError::new(codes::OAUTH_LINK_REQUIRED));
                }
                if !locked.is_email_verified() {
                    // ADR 0002: the provider proved the mailbox; discard
                    // whatever an unproven registrant left on the account
                    // before attaching the identity.
                    self.deps()
                        .accounts
                        .confirm_mailbox_control_in_tx(
                            &mut tx,
                            Some(ctx),
                            locked.id,
                            MailboxProof::Passwordless,
                        )
                        .await?;
                }
                let identity = match self.insert_identity(&mut tx, locked.id, external).await? {
                    Ok(id) => id,
                    Err(PROVIDER_SUBJECT_KEY) => return Ok(Resolution::Retry),
                    Err(_) => return Err(AuthError::new(codes::IDENTITY_PROVIDER_ALREADY_LINKED)),
                };
                self.store_tokens(&mut tx, identity, external).await?;
                let linked = self
                    .identity_event(
                        SecurityEventKind::IdentityLinked,
                        ctx,
                        locked.id,
                        identity,
                        &external.provider,
                    )
                    .with_meta("linked_by", "auto_link_verified_email");
                self.deps().audit.record_in_tx(&mut tx, linked).await?;
                // K-18: an automatic link is exactly what the owner must
                // hear about.
                self.notify_identity_change(&mut tx, ctx, locked.id, &external.provider, true)
                    .await?;
                authn_store::commit(tx).await?;
                Ok(Resolution::User(locked.id))
            }
        }
    }

    /// Pre-check of the link flows: only `active` accounts with a verified
    /// address may link (re-checked under the row lock when linking).
    pub(crate) async fn ensure_linkable(&self, user: UserId) -> Result<(), AuthError> {
        let record = UserRepository::find_by_id(&self.deps().pool, user)
            .await?
            .ok_or_else(|| AuthError::new(common::common::NOT_FOUND))?;
        if linkable(&record) {
            Ok(())
        } else {
            Err(AuthError::new(codes::IDENTITY_LINK_NOT_ALLOWED))
        }
    }

    /// Links `external` to `user` (SOC-06) in one transaction holding the
    /// user row lock. `session` is the session that started a browser link
    /// flow: it must still be an active session of `user` (K-03), checked
    /// under the row lock; `None` for the native link, whose request is
    /// itself authenticated.
    pub(crate) async fn link_identity(
        &self,
        ctx: &RequestContext,
        user: UserId,
        session: Option<SessionId>,
        external: &ExternalIdentity,
    ) -> Result<IdentitySummary, AuthError> {
        let mut tx = authn_store::begin(&self.deps().pool).await?;
        sqlx::query(LOCK_TIMEOUT_SQL).execute(&mut *tx).await?;
        let record = UserRepository::lock_for_update(&mut tx, user)
            .await?
            .ok_or_else(|| AuthError::new(common::common::NOT_FOUND))?;
        if let Some(session) = session
            && !self
                .deps()
                .session_liveness
                .is_active(&mut tx, session, user, self.now())
                .await?
        {
            // Signed out, reset, revoked or expired since the flow
            // started: the flow dies with the session.
            tracing::info!(user = %user, "link callback for a session that is no longer active");
            return Err(AuthError::new(codes::OAUTH_STATE_INVALID));
        }
        if !linkable(&record) {
            return Err(AuthError::new(codes::IDENTITY_LINK_NOT_ALLOWED));
        }
        if let Some(row) =
            store::find_identity(&mut *tx, &external.provider, &external.subject).await?
        {
            ensure_same_issuer(&row, external)?;
            if row.user_id != user {
                return Err(AuthError::new(codes::IDENTITY_ALREADY_LINKED));
            }
            store::touch_identity(
                &mut tx,
                row.id,
                external.email.as_deref(),
                external.email_verified,
                external.display_name.as_deref(),
                self.now(),
            )
            .await?;
            self.store_tokens(&mut tx, row.id, external).await?;
            authn_store::commit(tx).await?;
            return Ok(IdentitySummary::from(&row));
        }
        let identity = match self.insert_identity(&mut tx, user, external).await? {
            Ok(id) => id,
            Err(PROVIDER_SUBJECT_KEY) => {
                return Err(AuthError::new(codes::IDENTITY_ALREADY_LINKED));
            }
            Err(_) => return Err(AuthError::new(codes::IDENTITY_PROVIDER_ALREADY_LINKED)),
        };
        self.store_tokens(&mut tx, identity, external).await?;
        let event = self
            .identity_event(
                SecurityEventKind::IdentityLinked,
                ctx,
                user,
                identity,
                &external.provider,
            )
            .with_meta("linked_by", "user");
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        self.notify_identity_change(&mut tx, ctx, user, &external.provider, true)
            .await?;
        let rows = store::identities_of(&mut *tx, user).await?;
        authn_store::commit(tx).await?;
        tracing::info!(user = %user, identity = %identity, "identity linked");
        rows.iter()
            .find(|r| r.id == identity)
            .map(IdentitySummary::from)
            .ok_or_else(|| AuthError::internal("linked identity vanished"))
    }

    /// The caller's linked identities (SOC-06). Readable under read-only
    /// impersonation; API keys are refused.
    pub async fn list_identities(
        &self,
        principal: &Principal,
    ) -> Result<Vec<IdentitySummary>, AuthError> {
        if principal.session_id().is_none() {
            return Err(AuthError::new(common::common::FORBIDDEN));
        }
        let user = principal.require_user()?;
        let rows = store::identities_of(&self.deps().pool, user).await?;
        Ok(rows.iter().map(IdentitySummary::from).collect())
    }

    /// Unlinks one of the caller's identities (SOC-06). Requires step-up;
    /// refused with `identity_last_login_method` when nothing else could
    /// sign in. Unknown and foreign ids answer `not_found` alike.
    pub async fn unlink(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        identity: IdentityId,
    ) -> Result<(), AuthError> {
        let user = self.require_step_up(principal)?;
        let mut tx = authn_store::begin(&self.deps().pool).await?;
        sqlx::query(LOCK_TIMEOUT_SQL).execute(&mut *tx).await?;
        // PWD-11: serialize with password removal and passkey deletion.
        UserRepository::lock_for_update(&mut tx, user)
            .await?
            .ok_or_else(|| AuthError::new(common::common::NOT_FOUND))?;
        let rows = store::identities_of(&mut *tx, user).await?;
        let Some(target) = rows.iter().find(|r| r.id == identity) else {
            return Err(AuthError::new(common::common::NOT_FOUND));
        };
        if rows.len() == 1 {
            let others = self
                .deps()
                .login_methods
                .other_login_methods(&mut tx, user)
                .await?;
            if others.iter().all(|m| *m == LoginMethod::Social) {
                return Err(AuthError::new(codes::IDENTITY_LAST_LOGIN_METHOD));
            }
        }
        let provider = target.provider.clone();
        // K-35: the provider token outlives the row only as a queued
        // revocation (same transaction).
        super::revocation::queue_identity_revocation(
            &mut tx,
            &self.deps().envelopes,
            self.deps().audit.as_ref(),
            self.now(),
            user,
            target,
        )
        .await?;
        if !store::delete_identity(&mut tx, identity, user).await? {
            return Err(AuthError::new(common::common::NOT_FOUND));
        }
        let mut event = self.identity_event(
            SecurityEventKind::IdentityUnlinked,
            ctx,
            user,
            identity,
            &provider,
        );
        if let Some(imp) = principal.impersonation {
            event.impersonator = Some(imp.admin_user_id);
        }
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        self.notify_identity_change(&mut tx, ctx, user, &provider, false)
            .await?;
        authn_store::commit(tx).await?;
        tracing::info!(user = %user, identity = %identity, "identity unlinked");
        Ok(())
    }

    /// Removes **every** identity linked to `user` inside the caller's
    /// transaction (ACC-07 e-mail change revert, K-20: whoever held the
    /// account may have linked their own provider account). For the
    /// server's `authn_account::EmailChangeRevertHook`; the caller has
    /// locked the user row. Uses only `conn`; no last-login-method check
    /// (the owner regains access through the restored mailbox with a
    /// password reset). Each stored Apple token is queued for revocation
    /// (K-35) and each removal is audited as `identity.unlinked`
    /// (`Actor::System`, `reason = email_change_reverted`); no notice is
    /// sent (the revert notice covers it). Returns how many were removed.
    pub async fn remove_all_identities_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<u32, AuthError> {
        let now = self.now();
        let mut removed = 0_u32;
        for row in store::identities_of(&mut *conn, user).await? {
            super::revocation::queue_identity_revocation(
                &mut *conn,
                &self.deps().envelopes,
                self.deps().audit.as_ref(),
                now,
                user,
                &row,
            )
            .await?;
            if !store::delete_identity(&mut *conn, row.id, user).await? {
                continue;
            }
            removed = removed.saturating_add(1);
            let event = SecurityEvent::new(SecurityEventKind::IdentityUnlinked, now)
                .with_context(ctx)
                .with_actor(Actor::System)
                .with_subject(user)
                .with_resource("identity", row.id)
                .with_meta("provider", row.provider.clone())
                .with_meta("reason", "email_change_reverted");
            self.deps().audit.record_in_tx(&mut *conn, event).await?;
            tracing::info!(user = %user, identity = %row.id, "identity removed by e-mail change revert");
        }
        Ok(removed)
    }

    /// The decrypted provider tokens of one of `user`'s identities, if
    /// stored (SOC-08). `None` when storage is off or nothing was stored.
    pub async fn stored_provider_tokens(
        &self,
        user: UserId,
        identity: IdentityId,
    ) -> Result<Option<StoredProviderTokens>, AuthError> {
        let rows = store::identities_of(&self.deps().pool, user).await?;
        let Some(row) = rows.iter().find(|r| r.id == identity) else {
            return Err(AuthError::new(common::common::NOT_FOUND));
        };
        let Some(access) = row.access_token_ciphertext.as_deref() else {
            return Ok(None);
        };
        let text = |bytes: &[u8]| -> Result<SensitiveString, AuthError> {
            std::str::from_utf8(bytes)
                .map(SensitiveString::new)
                .map_err(|_| AuthError::internal("corrupt provider token"))
        };
        let access = self
            .open("identities", "access_token_ciphertext", row.id, access)
            .await?;
        let refresh = match row.refresh_token_ciphertext.as_deref() {
            Some(sealed) => Some(text(
                self.open("identities", "refresh_token_ciphertext", row.id, sealed)
                    .await?
                    .expose(),
            )?),
            None => None,
        };
        Ok(Some(StoredProviderTokens {
            access_token: text(access.expose())?,
            refresh_token: refresh,
            expires_at: row.token_expires_at,
        }))
    }

    /// Number of identities linked to `user`, read through `conn` (for the
    /// server's adapters of `authn_password::LoginMethodInventory` and
    /// `authn_webauthn::AccountMethodsSource`: a linked identity is a
    /// `LoginMethod::Social`).
    pub async fn linked_identity_count_in(
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<u64, AuthError> {
        let count = store::count_identities(&mut *conn, user).await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Deletes up to `limit` expired authorization states and native nonces
    /// (OPS-06 background job; safe on several instances). Returns how many.
    pub async fn purge_expired_states(&self, limit: u32) -> Result<u64, AuthError> {
        Ok(store::purge_expired_states(&self.deps().pool, self.now(), i64::from(limit)).await?)
    }
}
