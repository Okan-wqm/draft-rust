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
//!    mailbox) and the identity linked, in one transaction.
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
//! accounts with a verified address. Unlinking locks the user row first
//! (`UserRepository::lock_for_update`, PWD-11) and refuses to remove the
//! last way to sign in ([`crate::LoginMethodInventory`]).

use authn_account::MailboxProof;
use authn_core::domain::{
    AccountStatus, AuthMethodRef, ClientKind, EmailAddress, LoginMethod, Principal,
};
use authn_core::error::{AuthError, codes as common};
use authn_core::http::RequestContext;
use authn_core::id::{IdentityId, UserId};
use authn_core::ports::{
    Actor, DomainEvent, DomainEventKind, LoginOutcome, PrimaryAuthentication, SecurityEvent,
    SecurityEventKind,
};
use authn_core::secret::SensitiveString;
use authn_store::users::EMAIL_UNIQUE_CONSTRAINT;
use authn_store::{NewUser, UserRecord, UserRepository};
use serde::Serialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::OidcClientService;
use crate::codes;
use crate::identity::ExternalIdentity;
use crate::store::{self, IdentityRow, NewIdentity, PROVIDER_SUBJECT_KEY, USER_PROVIDER_KEY};

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
    /// nothing is kept unless `oidc_client.store_provider_tokens` is on;
    /// otherwise every column is envelope encrypted with the row as AAD.
    async fn store_tokens(
        &self,
        conn: &mut PgConnection,
        identity: IdentityId,
        external: &ExternalIdentity,
    ) -> Result<(), AuthError> {
        if !self.settings().config.store_provider_tokens {
            store::set_tokens(conn, identity, None, None, None).await?;
            return Ok(());
        }
        let Some(tokens) = &external.tokens else {
            return Ok(());
        };
        let access = self
            .seal(
                "identities",
                "access_token_ciphertext",
                identity,
                tokens.access_token.expose().as_bytes(),
            )
            .await?;
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
            Some(&access),
            refresh.as_deref(),
            tokens.expires_at,
        )
        .await?;
        Ok(())
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

        match UserRepository::find_by_email(&mut *tx, &email).await? {
            None => {
                if self
                    .deps()
                    .reservations
                    .is_reserved(&mut tx, &email)
                    .await?
                {
                    return Err(AuthError::new(codes::OAUTH_LINK_REQUIRED));
                }
                let user = UserId::generate();
                match UserRepository::create(
                    &mut tx,
                    &NewUser {
                        id: user,
                        email,
                        status: AccountStatus::Active,
                        created_at: now,
                    },
                )
                .await
                {
                    Ok(_) => {}
                    Err(e) if e.is_unique_violation(EMAIL_UNIQUE_CONSTRAINT) => {
                        return Ok(Resolution::Retry);
                    }
                    Err(e) => return Err(e.into()),
                }
                UserRepository::mark_email_verified(&mut tx, user, now).await?;
                let Ok(identity) = self.insert_identity(&mut tx, user, external).await? else {
                    return Ok(Resolution::Retry);
                };
                self.store_tokens(&mut tx, identity, external).await?;
                self.deps()
                    .events
                    .publish(
                        &mut tx,
                        DomainEvent {
                            user_id: Some(user),
                            ..DomainEvent::new(
                                DomainEventKind::UserCreated,
                                now,
                                serde_json::json!({
                                    "user_id": user,
                                    "status": AccountStatus::Active,
                                    "method": "social",
                                }),
                            )
                        },
                    )
                    .await?;
                let registered = SecurityEvent::new(SecurityEventKind::AccountRegistered, now)
                    .with_context(ctx)
                    .with_actor(Actor::Anonymous)
                    .with_subject(user)
                    .with_resource("user", user)
                    .with_meta("method", "social")
                    .with_meta("provider", external.provider.clone());
                self.deps().audit.record_in_tx(&mut tx, registered).await?;
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
            Some(existing) => {
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
    /// user row lock.
    pub(crate) async fn link_identity(
        &self,
        ctx: &RequestContext,
        user: UserId,
        external: &ExternalIdentity,
    ) -> Result<IdentitySummary, AuthError> {
        let mut tx = authn_store::begin(&self.deps().pool).await?;
        sqlx::query(LOCK_TIMEOUT_SQL).execute(&mut *tx).await?;
        let record = UserRepository::lock_for_update(&mut tx, user)
            .await?
            .ok_or_else(|| AuthError::new(common::common::NOT_FOUND))?;
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
        authn_store::commit(tx).await?;
        tracing::info!(user = %user, identity = %identity, "identity unlinked");
        Ok(())
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
