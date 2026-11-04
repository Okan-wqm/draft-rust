//! E-mail change (ACC-07).
//!
//! 1. **Request** (`POST /v1/me/email`, session + step-up): validated and
//!    rate limited synchronously, answered `202`; the background job checks
//!    whether the new address is free. Free → link + code
//!    (`email_change` / `email_change_code`, bound to the new address) are
//!    sent to the new address. Taken or reserved → nothing is sent to the
//!    requester; the address owner gets a "someone tried to use your
//!    address" notice. The requester therefore cannot learn whether an
//!    address is registered (ACC-02 applies to signed-in attackers too).
//! 2. **Confirm** (link or code, both by the signed-in account holder — a
//!    link alone would let whoever clicks an unsolicited e-mail attach
//!    their mailbox to someone else's account, ADR 0002): the
//!    address is replaced and marked verified, the old address is
//!    **reserved** for the revert period (nobody else can register it and
//!    block the revert), every token delivered to an address of the user
//!    is revoked (password reset, magic link, verification…), and the old
//!    address receives an `email_changed` notice with a revert link
//!    (`email_change_revert`, default 7 days).
//! 3. **Revert** (link, no session): restores the old address, revokes
//!    every outstanding address-bound token and the revert links of
//!    **later** changes (links of earlier changes stay valid, and the
//!    address left behind stays reserved for them — an intermediate
//!    address must never be able to cancel the original owner's revert),
//!    cancels a deletion scheduled in the meantime, revokes **all**
//!    sessions and trusted devices (`SessionRevoker`, same transaction) and
//!    forces a password reset by replacing the password hash with an
//!    unusable random one (`must_change_password` set) — an attacker who
//!    knew the password cannot sign in with it any more; the owner resets
//!    it through the restored address. The restored address receives an
//!    `email_change_reverted` notice in the same transaction (outbox).
//!
//! Address check-then-write sequences take advisory locks on the involved
//! addresses (sorted, deadlock-free) before the user row lock.

use authn_core::domain::{AccountStatus, EmailAddress, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, DomainEvent, DomainEventKind, Notification, NotificationKind, RateLimitKey,
    RevocationReason, RevokeOptions, SecurityEventKind,
};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::otp::OtpCode;
use authn_crypto::password::PasswordHashRecord;
use authn_crypto::token::OpaqueToken;
use authn_store::{
    CodeVerification, NewPasswordHash, OneTimeTokenRecord, OneTimeTokenRepository, TokenPurpose,
    UserRecord, UserRepository,
};

use super::verification::{invalid_code, invalid_token};
use super::{AccountService, LinkSpec, actions, after, parse_email, stored_email};
use crate::lifecycle::lock_user;
use crate::model::RevertOutcome;
use crate::repo::{ReservationRepository, lock_emails};
use crate::tx::AccountTx;

impl AccountService {
    /// ACC-07 step 1: requests a change to `new_email` (session + step-up).
    /// `202` whether or not the new address is available.
    pub async fn request_email_change(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        new_email: &str,
    ) -> Result<(), AuthError> {
        let user_id = Self::self_service_user(principal)?;
        self.require_step_up(principal)?;
        let user = self.principal_user(user_id).await?;
        match user.status {
            AccountStatus::Active => {}
            AccountStatus::PendingVerification => {
                return Err(AuthError::new(codes::account::EMAIL_VERIFICATION_REQUIRED));
            }
            _ => return Err(AuthError::new(codes::common::FORBIDDEN)),
        }
        self.limit(
            &RateLimitKey::user(actions::EMAIL_CHANGE, user.id),
            self.config().email_change_per_user,
        )
        .await?;
        let new_email = parse_email(new_email)?;
        if let Some(list) = &self.settings().disposable_domains {
            list.check(&new_email)?;
        }
        if user.email_normalized.as_deref() == Some(new_email.normalized()) {
            return Err(AuthError::new(codes::account::EMAIL_UNCHANGED));
        }
        let service = self.clone();
        let ctx = ctx.clone();
        self.inner.jobs.spawn("email_change_request", async move {
            service
                .process_email_change_request(&ctx, user.id, &new_email)
                .await
        })
    }

    async fn process_email_change_request(
        &self,
        ctx: &RequestContext,
        user_id: UserId,
        new_email: &EmailAddress,
    ) -> Result<(), AuthError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        lock_emails(tx.conn(), &[new_email.normalized()]).await?;
        let user = lock_user(&mut tx, user_id).await?;
        if user.status != AccountStatus::Active {
            return Ok(());
        }
        let owner = match UserRepository::find_by_email(tx.conn(), new_email).await? {
            Some(other) if other.id != user.id => Some(other.id),
            Some(_) => return Ok(()),
            None => ReservationRepository::active_owner(tx.conn(), new_email.normalized(), now)
                .await?
                .filter(|owner| *owner != user.id),
        };
        if let Some(owner) = owner {
            // A new request ends the previous pending change whether or not
            // the new address can be used — exactly like issuing a new link
            // and code would. Otherwise an earlier link that keeps working
            // would tell the requester that this address is registered.
            OneTimeTokenRepository::revoke_for_user(
                tx.conn(),
                user.id,
                &[TokenPurpose::EmailChange, TokenPurpose::EmailChangeCode],
                now,
            )
            .await?;
            self.address_in_use_notice(&mut tx, ctx, owner, new_email)
                .await?;
            tx.audit(
                self.event(SecurityEventKind::EmailChangeRequested, ctx)
                    .with_actor(Actor::User(user.id))
                    .with_subject(user.id)
                    .failed("address_unavailable"),
            );
            return tx.commit().await;
        }
        let secrets = self
            .issue_link_and_code(
                tx.conn(),
                (TokenPurpose::EmailChange, TokenPurpose::EmailChangeCode),
                user.id,
                new_email,
                Some(ctx.client_ip),
            )
            .await?;
        let (recipient, locale) = self
            .unproven_recipient_at(tx.conn(), user.id, new_email.clone(), ctx.locale)
            .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                tx.conn(),
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::EmailChangeVerification {
                        token: secrets.token.into_sensitive(),
                        code: secrets.code.into_sensitive(),
                        expires_at: secrets.link_expires_at,
                    },
                },
            )
            .await?;
        tx.audit(
            self.event(SecurityEventKind::EmailChangeRequested, ctx)
                .with_actor(Actor::User(user.id))
                .with_subject(user.id),
        );
        tx.commit().await
    }

    /// Notice to the owner of an address somebody tried to take over
    /// (throttled like registration notices).
    async fn address_in_use_notice(
        &self,
        tx: &mut AccountTx,
        ctx: &RequestContext,
        owner: UserId,
        address: &EmailAddress,
    ) -> Result<(), AuthError> {
        let key = RateLimitKey::account(actions::REGISTRATION_NOTICE, address.normalized());
        if !self
            .allowed(&key, self.config().registration_notice_per_email)
            .await?
        {
            return Ok(());
        }
        let (recipient, locale) = self
            .recipient_at(tx.conn(), owner, address.clone(), ctx.locale)
            .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                tx.conn(),
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::RegistrationAttempt,
                },
            )
            .await
    }

    /// ACC-07 step 2 with the link sent to the new address. The link proves
    /// control of the new mailbox; the **signed-in account holder** must
    /// open it (any of their sessions, also on another device after signing
    /// in). Otherwise anybody who clicks an unsolicited "confirm your
    /// address" e-mail would attach their mailbox to the requester's
    /// account and credentials — a pre-hijacked, verified account (ADR
    /// 0002). Without a principal: `unauthenticated` before the token is
    /// even looked at; another user's link: `invalid_or_expired_token`
    /// (not consumed).
    pub async fn confirm_email_change_link(
        &self,
        principal: Option<&Principal>,
        ctx: &RequestContext,
        token: &SecretString,
    ) -> Result<(), AuthError> {
        let principal = principal.ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))?;
        let user_id = Self::self_service_user(principal)?;
        self.limit(
            &RateLimitKey::ip(actions::LINK_ACTION_IP, ctx.client_ip),
            self.config().link_actions_per_ip,
        )
        .await?;
        let token = OpaqueToken::parse(token.expose_secret()).map_err(|_| invalid_token())?;
        let hash = token.hash();
        // Find the owner first (no consumption) so the address locks can be
        // taken before the row lock; the consumption below is atomic.
        let Some(found) = OneTimeTokenRepository::find_active_link(
            self.pool(),
            TokenPurpose::EmailChange,
            &hash,
            self.now(),
        )
        .await?
        .filter(|found| found.user_id == Some(user_id)) else {
            return Err(invalid_token());
        };
        let mut tx = self.begin().await?;
        let locked = self.lock_change_addresses(&mut tx, &found).await?;
        let Some(record) = OneTimeTokenRepository::consume_link(
            tx.conn(),
            TokenPurpose::EmailChange,
            &hash,
            self.now(),
        )
        .await?
        else {
            return Err(invalid_token());
        };
        if record.id != found.id {
            return Err(invalid_token());
        }
        self.apply_email_change(
            tx,
            ctx,
            &record,
            locked,
            Actor::User(user_id),
            invalid_token,
        )
        .await
    }

    /// ACC-07 step 2 with the code, by the signed-in user.
    ///
    /// No code is issued when the requested address is taken, so every
    /// failure (no code, wrong code, locked-out code) answers the same
    /// `invalid_code`, no faster than `code_failure_floor`: the requester
    /// must not learn whether the address is registered (ACC-02).
    pub async fn confirm_email_change_code(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let started = std::time::Instant::now();
        let result = self
            .confirm_email_change_code_inner(principal, ctx, code)
            .await;
        if result.is_err() {
            self.failure_floor(started).await;
        }
        result
    }

    async fn confirm_email_change_code_inner(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        code: &SecretString,
    ) -> Result<(), AuthError> {
        let user_id = Self::self_service_user(principal)?;
        self.limit(
            &RateLimitKey::user(actions::EMAIL_CHANGE_CODE, user_id),
            self.config().verification.code_attempts_per_email,
        )
        .await?;
        let code = OtpCode::parse(code.expose_secret()).map_err(|_| invalid_code())?;
        let record = match self
            .check_code(TokenPurpose::EmailChangeCode, user_id, &code)
            .await?
        {
            CodeVerification::Verified(record) => record,
            CodeVerification::LockedOut
            | CodeVerification::Invalid { .. }
            | CodeVerification::NotFound => return Err(invalid_code()),
        };
        let mut tx = self.begin().await?;
        let locked = self.lock_change_addresses(&mut tx, &record).await?;
        self.apply_email_change(tx, ctx, &record, locked, Actor::User(user_id), invalid_code)
            .await
    }

    /// Advisory locks on the user's current and the token's target address.
    /// Returns the current address that was locked; callers check it is
    /// still current once the row is locked.
    async fn lock_change_addresses(
        &self,
        tx: &mut AccountTx,
        record: &OneTimeTokenRecord,
    ) -> Result<Option<String>, AuthError> {
        let current = match record.user_id {
            Some(user) => UserRepository::find_by_id(tx.conn(), user)
                .await?
                .and_then(|u| u.email_normalized),
            None => None,
        };
        let target = record
            .target
            .as_deref()
            .and_then(|t| EmailAddress::parse(t).ok());
        let mut addresses: Vec<&str> = Vec::new();
        if let Some(current) = current.as_deref() {
            addresses.push(current);
        }
        if let Some(target) = target.as_ref() {
            addresses.push(target.normalized());
        }
        lock_emails(tx.conn(), &addresses).await?;
        Ok(current)
    }

    /// Performs the change after a successful link / code verification.
    async fn apply_email_change(
        &self,
        mut tx: AccountTx,
        ctx: &RequestContext,
        record: &OneTimeTokenRecord,
        locked_current: Option<String>,
        actor: Actor,
        failure: fn() -> AuthError,
    ) -> Result<(), AuthError> {
        let now = self.now();
        let (Some(user_id), Some(new_email)) = (
            record.user_id,
            record
                .target
                .as_deref()
                .and_then(|t| EmailAddress::parse(t).ok()),
        ) else {
            return Err(failure());
        };
        let user = lock_user(&mut tx, user_id).await.map_err(|_| failure())?;
        let Some(old_email) = stored_email(&user) else {
            return Err(failure());
        };
        if locked_current.is_none() || locked_current != user.email_normalized {
            // The address changed concurrently; it is not covered by our lock.
            return Err(failure());
        }
        if user.status != AccountStatus::Active || old_email.normalized() == new_email.normalized()
        {
            return Err(failure());
        }
        if !self
            .address_available_for(&mut tx, user.id, &new_email)
            .await?
        {
            return Err(failure());
        }
        UserRepository::update_email(tx.conn(), user.id, &new_email, Some(now)).await?;
        let revert_expires_at = after(now, self.config().email_change_revert_ttl)?;
        ReservationRepository::reserve(
            tx.conn(),
            old_email.normalized(),
            user.id,
            revert_expires_at,
            now,
        )
        .await?;
        ReservationRepository::release(tx.conn(), new_email.normalized(), user.id).await?;
        self.revoke_address_bound_tokens(tx.conn(), user.id).await?;
        let revert_token = self
            .issue_link(
                tx.conn(),
                LinkSpec {
                    purpose: TokenPurpose::EmailChangeRevert,
                    user: user.id,
                    target: Some(old_email.as_str()),
                    expires_at: revert_expires_at,
                    invalidate_previous: false,
                },
                Some(ctx.client_ip),
            )
            .await?;
        let (recipient, locale) = self
            .recipient_at(tx.conn(), user.id, old_email, ctx.locale)
            .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                tx.conn(),
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::EmailChanged {
                        new_email_masked: new_email.masked(),
                        revert_token: revert_token.into_sensitive(),
                        revert_expires_at,
                    },
                },
            )
            .await?;
        self.publish_email_changed(&mut tx, user.id, false).await?;
        tx.audit(
            self.event(SecurityEventKind::EmailChanged, ctx)
                .with_actor(actor)
                .with_subject(user.id),
        );
        tx.commit().await
    }

    /// Whether `email` is free for `user`: not registered by someone else
    /// and not reserved for someone else.
    async fn address_available_for(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        email: &EmailAddress,
    ) -> Result<bool, AuthError> {
        if let Some(other) = UserRepository::find_by_email(tx.conn(), email).await?
            && other.id != user
        {
            return Ok(false);
        }
        let reserved =
            ReservationRepository::active_owner(tx.conn(), email.normalized(), self.now()).await?;
        Ok(reserved.is_none_or(|owner| owner == user))
    }

    async fn publish_email_changed(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        reverted: bool,
    ) -> Result<(), AuthError> {
        self.deps()
            .events
            .publish(
                tx.conn(),
                DomainEvent {
                    user_id: Some(user),
                    ..DomainEvent::new(
                        DomainEventKind::UserEmailChanged,
                        self.now(),
                        serde_json::json!({ "user_id": user, "reverted": reverted }),
                    )
                },
            )
            .await
    }

    /// ACC-07 step 3: reverts a change with the link sent to the old
    /// address (see the module docs for every effect).
    pub async fn revert_email_change(
        &self,
        ctx: &RequestContext,
        token: &SecretString,
    ) -> Result<RevertOutcome, AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::LINK_ACTION_IP, ctx.client_ip),
            self.config().link_actions_per_ip,
        )
        .await?;
        let token = OpaqueToken::parse(token.expose_secret()).map_err(|_| invalid_token())?;
        let hash = token.hash();
        let Some(found) = OneTimeTokenRepository::find_active_link(
            self.pool(),
            TokenPurpose::EmailChangeRevert,
            &hash,
            self.now(),
        )
        .await?
        else {
            return Err(invalid_token());
        };
        // Computed before the transaction: Argon2 must not run under locks.
        let unusable = self.unusable_password_hash().await?;
        let mut tx = self.begin().await?;
        let locked = self.lock_change_addresses(&mut tx, &found).await?;
        let Some(record) = OneTimeTokenRepository::consume_link(
            tx.conn(),
            TokenPurpose::EmailChangeRevert,
            &hash,
            self.now(),
        )
        .await?
        else {
            return Err(invalid_token());
        };
        if record.id != found.id {
            return Err(invalid_token());
        }
        let (Some(user_id), Some(old_email)) = (
            record.user_id,
            record
                .target
                .as_deref()
                .and_then(|t| EmailAddress::parse(t).ok()),
        ) else {
            return Err(invalid_token());
        };
        let user = lock_user(&mut tx, user_id)
            .await
            .map_err(|_| invalid_token())?;
        if user.status == AccountStatus::Deleted || user.email_normalized != locked {
            return Err(invalid_token());
        }
        self.restore_address(&mut tx, &user, &old_email).await?;
        self.revoke_address_bound_tokens(tx.conn(), user.id).await?;
        // Revert links of *later* changes end here. Links of *earlier*
        // changes stay valid: otherwise whoever controls an intermediate
        // address (an attacker who changed it twice) could revert to it and
        // thereby cancel the original owner's revert link.
        OneTimeTokenRepository::revoke_for_user_since(
            tx.conn(),
            user.id,
            &[TokenPurpose::EmailChangeRevert],
            (record.created_at, record.id),
            self.now(),
        )
        .await?;
        self.keep_reserved_for_earlier_reverts(&mut tx, user.id, locked.as_deref(), &old_email)
            .await?;
        if user.status == AccountStatus::PendingDeletion {
            self.cancel_deletion_in_tx(
                &mut tx,
                user.id,
                Actor::Anonymous,
                ctx,
                "email_change_reverted",
            )
            .await?;
        }
        self.deps()
            .sessions
            .revoke_all_for_user(
                tx.conn(),
                user.id,
                RevocationReason::EmailChangeReverted,
                RevokeOptions {
                    also_trusted_devices: true,
                },
            )
            .await?;
        let password_reset_required = self
            .invalidate_password(&mut tx, user.id, &unusable)
            .await?;
        self.publish_email_changed(&mut tx, user.id, true).await?;
        // K-40: the restored address learns about the revert and the forced
        // password reset in the same transaction (outbox): the notice is
        // queued exactly when the revert commits.
        let (recipient, locale) = self
            .recipient_at(tx.conn(), user.id, old_email.clone(), ctx.locale)
            .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                tx.conn(),
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::EmailChangeReverted { at: self.now() },
                },
            )
            .await?;
        tx.audit(
            self.event(SecurityEventKind::EmailChangeReverted, ctx)
                .with_actor(Actor::Anonymous)
                .with_subject(user.id)
                .with_meta("password_reset_required", password_reset_required),
        );
        tx.commit().await?;
        Ok(RevertOutcome {
            password_reset_required,
        })
    }

    /// The address the account leaves with a revert stays reserved for the
    /// user while an earlier, still valid revert link points to it, so that
    /// nobody can register it and make that revert impossible.
    async fn keep_reserved_for_earlier_reverts(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        left: Option<&str>,
        restored: &EmailAddress,
    ) -> Result<(), AuthError> {
        let Some(left) = left.filter(|left| *left != restored.normalized()) else {
            return Ok(());
        };
        let now = self.now();
        let until = OneTimeTokenRepository::active_for_user(
            tx.conn(),
            user,
            &[TokenPurpose::EmailChangeRevert],
            now,
        )
        .await?
        .into_iter()
        .filter(|link| {
            link.target
                .as_deref()
                .and_then(|t| EmailAddress::parse(t).ok())
                .is_some_and(|t| t.normalized() == left)
        })
        .map(|link| link.expires_at)
        .max();
        if let Some(until) = until {
            ReservationRepository::reserve(tx.conn(), left, user, until, now).await?;
        }
        Ok(())
    }

    async fn restore_address(
        &self,
        tx: &mut AccountTx,
        user: &UserRecord,
        old_email: &EmailAddress,
    ) -> Result<(), AuthError> {
        if user.email_normalized.as_deref() == Some(old_email.normalized()) {
            return Ok(());
        }
        if !self.address_available_for(tx, user.id, old_email).await? {
            return Err(AuthError::new(codes::account::EMAIL_CHANGE_REVERT_CONFLICT));
        }
        UserRepository::update_email(tx.conn(), user.id, old_email, Some(self.now())).await?;
        ReservationRepository::release(tx.conn(), old_email.normalized(), user.id).await?;
        Ok(())
    }

    /// Replaces an existing password with an unusable hash and sets
    /// `must_change_password` (forced reset). Returns whether the account
    /// had a password.
    async fn invalidate_password(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        unusable: &PasswordHashRecord,
    ) -> Result<bool, AuthError> {
        if UserRepository::find_password(tx.conn(), user)
            .await?
            .is_none()
        {
            return Ok(false);
        }
        UserRepository::set_password(
            tx.conn(),
            user,
            &NewPasswordHash {
                password_hash: &unusable.hash,
                algorithm: unusable.algorithm.as_str(),
                pepper_version: unusable.pepper_version,
            },
            true,
            self.now(),
        )
        .await?;
        Ok(true)
    }

    /// Argon2id hash of a random 256-bit secret that is immediately
    /// discarded: no password can ever match it.
    async fn unusable_password_hash(&self) -> Result<PasswordHashRecord, AuthError> {
        // 256 random bits (base64url), never stored or shown anywhere.
        let random = OpaqueToken::generate()?;
        let secret = SecretString::from(random.expose().to_owned());
        Ok(self.deps().hasher.hash(&secret).await?)
    }
}
