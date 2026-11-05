//! Account facts and account creation for other modules that prove
//! mailbox control themselves (authn-oidc-client, SOC-05):
//!
//! * [`AccountService::is_address_reserved_in`] — ACC-07 reservation
//!   lookup on the caller's connection (K-02).
//! * [`AccountService::provision_verified_user_in_tx`] — a new `active`
//!   account with a verified address **and** its `user_profiles` row
//!   (display name, language), in the caller's transaction (K-33).
//! * [`AccountService::notification_recipient_in`] — recipient and
//!   language of a security notice to the account's current address, read
//!   on the caller's connection (no second pool connection inside a
//!   transaction).
//!
//! ADR 0002 invariants kept here: a provisioned account is created
//! `active` + verified **only** for an address whose mailbox the caller has
//! already proven (provider-verified e-mail); an existing account is never
//! touched (the caller decides about linking), a reserved address is never
//! handed out, and the address check-then-create runs under the same
//! per-address advisory lock as registration and e-mail change, so a
//! concurrent sign-up of the same address cannot slip in between.

use authn_core::domain::{AccountStatus, EmailAddress, Locale};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, DomainEvent, DomainEventKind, Recipient, SecurityEvent, SecurityEventKind,
};
use authn_store::users::EMAIL_UNIQUE_CONSTRAINT;
use authn_store::{NewUser, UserRecord, UserRepository};
use sqlx::PgConnection;

use super::{AccountService, stored_email};
use crate::profile::{DEFAULT_TIME_ZONE, normalize_display_name};
use crate::repo::{ProfileRepository, ProfileValues, ReservationRepository, lock_email};

/// Input of [`AccountService::provision_verified_user_in_tx`].
#[derive(Clone, Copy)]
pub struct VerifiedUserProvision<'a> {
    /// The address whose mailbox the caller proved (e.g. a provider's
    /// verified `email` claim). **Never** pass an unproven address.
    pub email: &'a EmailAddress,
    /// Display name for `user_profiles` (unvalidated input: normalized
    /// with the ACC-03 rules; a name that fails them is not stored).
    pub display_name: Option<&'a str>,
    /// Preferred language.
    pub locale: Locale,
    /// How the account was created (`social`) — audit / event metadata.
    pub method: &'static str,
    /// Provider id (`google`, `oidc:<slug>`…) — audit metadata.
    pub provider: Option<&'a str>,
}

impl std::fmt::Debug for VerifiedUserProvision<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The address and the name are personal data.
        f.debug_struct("VerifiedUserProvision")
            .field(
                "email",
                &authn_core::redact::mask_email(self.email.as_str()),
            )
            .field("display_name", &self.display_name.map(|_| "[REDACTED]"))
            .field("locale", &self.locale)
            .field("method", &self.method)
            .field("provider", &self.provider)
            .finish()
    }
}

/// Result of [`AccountService::provision_verified_user_in_tx`].
#[derive(Debug, Clone)]
pub enum ProvisionOutcome {
    /// A new `active`, verified account with a profile row was created.
    Created(UserId),
    /// An account with this address already exists; nothing was written.
    /// Whether (and how) an identity may be attached is the caller's
    /// decision (SOC-05: never automatically, unless configured).
    Existing(UserRecord),
    /// The address is reserved for the previous owner during an e-mail
    /// change's revert period (ACC-07); nothing was written.
    Reserved,
    /// A concurrent writer that does not take the address lock created
    /// the address first: the transaction is aborted — roll back and run
    /// the decision again.
    Conflict,
}

impl AccountService {
    /// ACC-07: whether `email` is reserved (for anybody) during an e-mail
    /// change's revert period. Read-only, on the caller's connection.
    pub async fn is_address_reserved_in(
        &self,
        conn: &mut PgConnection,
        email: &EmailAddress,
    ) -> Result<bool, AuthError> {
        Ok(
            ReservationRepository::active_owner(conn, email.normalized(), self.now())
                .await?
                .is_some(),
        )
    }

    /// Creates an `active` account whose address is already verified, with
    /// its `user_profiles` row, in the caller's transaction (K-33, SOC-05).
    ///
    /// The caller must have **proven mailbox control** for
    /// `request.email` (ADR 0002: e.g. the provider's verified `email`
    /// claim). In order, under the address's advisory lock:
    ///
    /// 1. the disposable-domain list (ACC-12) refuses the domain →
    ///    `email_domain_not_allowed` — decided from the address alone,
    ///    before any lookup, so the answer is the same whether or not an
    ///    account or a reservation exists (K-63);
    /// 2. an account with the address exists → [`ProvisionOutcome::Existing`]
    ///    (nothing written);
    /// 3. the address is reserved (ACC-07) → [`ProvisionOutcome::Reserved`];
    /// 4. otherwise the account (`active`, verified), the profile (display
    ///    name normalized with the ACC-03 rules — dropped when it fails
    ///    them —, language, `UTC`), the `user.created` domain event and the
    ///    `account.registered` audit event are written.
    ///
    /// No account lookup happens before the caller's own decisions, so
    /// whether the answer reveals an existing account is the caller's
    /// responsibility (authn-oidc-client answers only the proven mailbox
    /// owner).
    pub async fn provision_verified_user_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        request: VerifiedUserProvision<'_>,
    ) -> Result<ProvisionOutcome, AuthError> {
        let now = self.now();
        let email = request.email;
        // K-63: the domain is decided first, from the address alone, so
        // `email_domain_not_allowed` is the answer whether or not an
        // account or a reservation exists (no existence signal in body,
        // status or time).
        if let Some(list) = &self.settings().disposable_domains {
            list.check(email)?;
        }
        lock_email(&mut *conn, email.normalized()).await?;
        if let Some(existing) = UserRepository::find_by_email(&mut *conn, email).await? {
            return Ok(ProvisionOutcome::Existing(existing));
        }
        if self.is_address_reserved_in(&mut *conn, email).await? {
            return Ok(ProvisionOutcome::Reserved);
        }
        let user = UserId::generate();
        match UserRepository::create(
            &mut *conn,
            &NewUser {
                id: user,
                email: email.clone(),
                status: AccountStatus::Active,
                created_at: now,
            },
        )
        .await
        {
            Ok(_) => {}
            Err(e) if e.is_unique_violation(EMAIL_UNIQUE_CONSTRAINT) => {
                return Ok(ProvisionOutcome::Conflict);
            }
            Err(e) => return Err(e.into()),
        }
        UserRepository::mark_email_verified(&mut *conn, user, now).await?;
        let display_name = request.display_name.and_then(|name| {
            normalize_display_name(name, self.config().display_name_max_chars).ok()
        });
        ProfileRepository::upsert(
            &mut *conn,
            user,
            &ProfileValues {
                display_name: display_name.as_deref(),
                locale: request.locale,
                time_zone: DEFAULT_TIME_ZONE,
            },
            now,
        )
        .await?;
        self.deps()
            .events
            .publish(
                &mut *conn,
                DomainEvent {
                    user_id: Some(user),
                    ..DomainEvent::new(
                        DomainEventKind::UserCreated,
                        now,
                        serde_json::json!({
                            "user_id": user,
                            "status": AccountStatus::Active,
                            "method": request.method,
                        }),
                    )
                },
            )
            .await?;
        let mut registered = SecurityEvent::new(SecurityEventKind::AccountRegistered, now)
            .with_context(ctx)
            .with_actor(Actor::Anonymous)
            .with_subject(user)
            .with_resource("user", user)
            .with_meta("method", request.method);
        if let Some(provider) = request.provider {
            registered = registered.with_meta("provider", provider.to_owned());
        }
        self.deps()
            .audit
            .record_in_tx(&mut *conn, registered)
            .await?;
        metrics::counter!("authn_account_registrations_total", "outcome" => "provisioned")
            .increment(1);
        Ok(ProvisionOutcome::Created(user))
    }

    /// Recipient (current address, display name) and language of a notice
    /// to `user`, read on the caller's connection. `None` when the account
    /// does not exist or its stored address is unusable.
    pub async fn notification_recipient_in(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        fallback: Locale,
    ) -> Result<Option<(Recipient, Locale)>, AuthError> {
        let Some(record) = UserRepository::find_by_id(&mut *conn, user).await? else {
            return Ok(None);
        };
        let Some(email) = stored_email(&record) else {
            tracing::error!(user_id = %user, "stored e-mail address is unusable; notification skipped");
            return Ok(None);
        };
        Ok(Some(self.recipient_at(conn, user, email, fallback).await?))
    }
}
