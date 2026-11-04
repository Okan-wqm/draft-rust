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
//!
//! [`create_break_glass_admin_with_passkey_link`] backs `create-admin
//! --passkey-link` (K-11): the account gets **no password**; instead a
//! single-use enrollment link token (256 bits of CSPRNG output, only its
//! SHA-256 stored in `admin_passkey_enrollments`, default lifetime 30
//! minutes, at most 24 hours) is returned once. Whoever opens the link
//! registers the account's first passkey
//! ([`crate::AdminService::start_break_glass_enrollment`] /
//! [`crate::AdminService::finish_break_glass_enrollment`]); the link is
//! consumed in the transaction that stores the passkey.

use std::sync::Arc;

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::error::{AuthError, codes};
use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, Clock, SecurityEvent, SecurityEventKind};
use authn_core::secret::{SecretString, SensitiveString};
use authn_crypto::password::PasswordHasher;
use authn_crypto::token::OpaqueToken;
use authn_store::{NewPasswordHash, NewUser, StoreError, UserRepository};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use crate::settings::ENROLLMENT_LINK_HARD_CAP;
use crate::store;

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
    insert_admin_account(&mut tx, id, email, now).await?;
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
    let event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
        .with_actor(Actor::System)
        .with_subject(id)
        .with_meta("action", "break_glass_admin_created")
        .with_meta("enrollment", "password")
        .with_meta("priority", "high");
    audit.record_in_tx(&mut tx, event).await?;
    authn_store::commit(tx).await?;
    tracing::warn!(admin = %id, "break-glass admin created (high priority)");
    Ok(BreakGlassAdmin {
        user_id: id,
        password: password.into_sensitive(),
    })
}

/// A created break-glass admin waiting for its passkey (K-11).
pub struct BreakGlassEnrollmentLink {
    /// The account.
    pub user_id: UserId,
    /// The one-time display of the link token (43 characters, base64url).
    /// Print it once (e.g. in the URL fragment of the enrollment page); it
    /// is never stored in clear.
    pub token: SensitiveString,
    /// The link stops working at this time.
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for BreakGlassEnrollmentLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakGlassEnrollmentLink")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Creates a break-glass platform admin **without a password** and a
/// single-use passkey enrollment link for it (ADM-05, K-11; CLI
/// `create-admin --passkey-link`). `ttl` is the link lifetime (1 second to
/// 24 hours; `validation_failed` otherwise). Fails with `conflict` for an
/// address that is already registered. The creation is a high-priority
/// audit event; the token is returned once and only its SHA-256 is stored.
pub async fn create_break_glass_admin_with_passkey_link(
    pool: &PgPool,
    clock: &dyn Clock,
    audit: &Arc<dyn AuditSink>,
    email: &str,
    ttl: std::time::Duration,
) -> Result<BreakGlassEnrollmentLink, AuthError> {
    let email = EmailAddress::parse(email).map_err(|_| {
        AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(serde_json::json!({ "field": "email" }))
    })?;
    if ttl.is_zero() || ttl > ENROLLMENT_LINK_HARD_CAP {
        return Err(AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(serde_json::json!({ "field": "ttl" })));
    }
    let token = OpaqueToken::generate().map_err(AuthError::from)?;
    let now = clock.now();
    let expires_at = now + ttl;
    let id = UserId::generate();
    let mut tx = authn_store::begin(pool).await?;
    insert_admin_account(&mut tx, id, email, now).await?;
    store::insert_enrollment(
        &mut tx,
        uuid::Uuid::now_v7(),
        id,
        token.hash().as_bytes(),
        now,
        expires_at,
    )
    .await?;
    let event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
        .with_actor(Actor::System)
        .with_subject(id)
        .with_meta("action", "break_glass_admin_created")
        .with_meta("enrollment", "passkey_link")
        .with_meta("link_expires_unix", expires_at.unix_timestamp())
        .with_meta("priority", "high");
    audit.record_in_tx(&mut tx, event).await?;
    authn_store::commit(tx).await?;
    tracing::warn!(admin = %id, "break-glass admin created with a passkey enrollment link (high priority)");
    Ok(BreakGlassEnrollmentLink {
        user_id: id,
        token: token.into_sensitive(),
        expires_at,
    })
}

/// An active, verified, flagged break-glass platform admin row.
async fn insert_admin_account(
    conn: &mut PgConnection,
    id: UserId,
    email: EmailAddress,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    match UserRepository::create(
        &mut *conn,
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
    UserRepository::mark_email_verified(&mut *conn, id, now).await?;
    UserRepository::set_admin_flags(&mut *conn, id, true, true).await?;
    Ok(())
}
