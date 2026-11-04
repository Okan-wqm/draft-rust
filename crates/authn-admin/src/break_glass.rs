//! Break-glass admin accounts (ADM-05).
//!
//! [`create_break_glass_admin`] backs the CLI command `create-admin`: it
//! creates an active, verified platform admin flagged `is_break_glass`
//! with a strong random password (256 bits of CSPRNG output) that is
//! returned **once** for the operator to print and store offline. Nothing
//! else keeps it. The creation is a high-priority audit event.
//!
//! Using the account:
//! * platform admins must sign in with phishing-resistant MFA, so the first
//!   login with the password is required by authn-session to enroll a
//!   passkey before a session is issued (SES-22, MFA-08);
//! * every request of a break-glass account to the admin API records a
//!   high-priority `admin.break_glass_used` event ([`crate::AdminService::authorize`]);
//! * break-glass accounts cannot be impersonated and the admin console
//!   cannot reset their password, MFA or verification state.

use std::sync::Arc;

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::error::{AuthError, codes};
use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, Clock, SecurityEvent, SecurityEventKind};
use authn_core::secret::{SecretString, SensitiveString};
use authn_crypto::password::PasswordHasher;
use authn_crypto::token::OpaqueToken;
use authn_store::{NewPasswordHash, NewUser, StoreError, UserRepository};
use sqlx::PgPool;

/// A created break-glass admin.
pub struct BreakGlassAdmin {
    /// The account.
    pub user_id: UserId,
    /// The one-time display of the generated password (43 characters,
    /// base64url). Print it once; it is never stored in clear.
    pub password: SensitiveString,
}

impl std::fmt::Debug for BreakGlassAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakGlassAdmin")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// Creates a break-glass platform admin for `email` (ADM-05). Fails with
/// `conflict` when the address is already registered (an existing account
/// is never promoted silently) and `validation_failed` for an invalid
/// address.
pub async fn create_break_glass_admin(
    pool: &PgPool,
    hasher: &PasswordHasher,
    clock: &dyn Clock,
    audit: &Arc<dyn AuditSink>,
    email: &str,
) -> Result<BreakGlassAdmin, AuthError> {
    let email = EmailAddress::parse(email).map_err(|_| {
        AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(serde_json::json!({ "field": "email" }))
    })?;
    let password = OpaqueToken::generate().map_err(AuthError::from)?;
    let record = hasher
        .hash(&SecretString::from(password.expose().to_owned()))
        .await
        .map_err(AuthError::from)?;
    let now = clock.now();
    let id = UserId::generate();
    let mut tx = authn_store::begin(pool).await?;
    match UserRepository::create(
        &mut tx,
        &NewUser {
            id,
            email,
            status: AccountStatus::Active,
            created_at: now,
        },
    )
    .await
    {
        Ok(_) => {}
        Err(StoreError::UniqueViolation { .. }) => {
            return Err(AuthError::new(codes::common::CONFLICT)
                .with_context("the address is already registered"));
        }
        Err(e) => return Err(e.into()),
    }
    UserRepository::mark_email_verified(&mut tx, id, now).await?;
    UserRepository::set_password(
        &mut tx,
        id,
        &NewPasswordHash {
            password_hash: &record.hash,
            algorithm: record.algorithm.as_str(),
            pepper_version: record.pepper_version,
        },
        false,
        now,
    )
    .await?;
    UserRepository::set_admin_flags(&mut tx, id, true, true).await?;
    let event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
        .with_actor(Actor::System)
        .with_subject(id)
        .with_meta("action", "break_glass_admin_created")
        .with_meta("priority", "high");
    audit.record_in_tx(&mut tx, event).await?;
    authn_store::commit(tx).await?;
    tracing::warn!(admin = %id, "break-glass admin created (high priority)");
    Ok(BreakGlassAdmin {
        user_id: id,
        password: password.into_sensitive(),
    })
}
