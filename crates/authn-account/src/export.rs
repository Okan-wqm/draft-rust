//! Personal data export (ACC-10): this crate's own [`DataExporter`] section
//! and the section-name rules for the aggregate.
//!
//! The `account` section contains everything stored in the tables owned by
//! authn-account and in the base `users` / `password_credentials` rows:
//! account record, password metadata (never the hash), profile, consents
//! (with IP and user agent), deletion requests, address reservations,
//! pending registrations (address, profile values, requesting IP and user
//! agent, times — never the password hash, handle, link or code) and the
//! pending account links/codes (purpose, target address, requesting IP,
//! times — never the token hashes). Other modules contribute their own
//! sections through the `DataExporter` port.

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{Clock, DataExporter};
use authn_store::UserRepository;
use serde_json::{Value, json};
use sqlx::PgConnection;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::registration_store::RegistrationRepository;
use crate::repo::{
    ConsentRepository, DeletionRepository, ProfileRepository, ReservationRepository, SharedReads,
};

/// Section name of this crate.
pub const ACCOUNT_SECTION: &str = "account";
/// Format identifier of the export document.
pub const EXPORT_FORMAT: &str = "rust-authentication/personal-data-export/v1";

/// Whether `section` is a valid exporter section name
/// (`^[a-z][a-z0-9_]{0,63}$`).
#[must_use]
pub fn is_valid_section(section: &str) -> bool {
    let mut bytes = section.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && section.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// RFC 3339 timestamp (JSON `null` when absent or unformattable).
pub(crate) fn ts(value: Option<OffsetDateTime>) -> Value {
    value
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

/// The `account` section of the export.
#[derive(Clone)]
pub struct AccountDataExporter {
    clock: Arc<dyn Clock>,
}

impl AccountDataExporter {
    /// An exporter reading "now" from `clock` (ARC-04).
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

impl std::fmt::Debug for AccountDataExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountDataExporter")
    }
}

#[async_trait]
impl DataExporter for AccountDataExporter {
    fn section(&self) -> &'static str {
        ACCOUNT_SECTION
    }

    async fn export(&self, conn: &mut PgConnection, user: UserId) -> Result<Value, AuthError> {
        let Some(record) = UserRepository::find_by_id(&mut *conn, user).await? else {
            return Ok(Value::Null);
        };
        let now = self.clock.now();
        let password = UserRepository::find_password(&mut *conn, user).await?;
        let profile = ProfileRepository::find(&mut *conn, user).await?;
        let consents = ConsentRepository::for_user(&mut *conn, user).await?;
        let deletions = DeletionRepository::for_user(&mut *conn, user).await?;
        let reservations = ReservationRepository::for_user(&mut *conn, user).await?;
        let pending = SharedReads::pending_account_tokens(&mut *conn, user, now).await?;
        let registrations = RegistrationRepository::live_for_user(&mut *conn, user, now).await?;
        Ok(json!({
            "user": {
                "id": record.id,
                "email": record.email,
                "email_verified_at": ts(record.email_verified_at),
                "status": record.status,
                "status_reason": record.status_reason,
                "status_changed_at": ts(Some(record.status_changed_at)),
                "locked_until": ts(record.locked_until),
                "is_platform_admin": record.is_platform_admin,
                "last_login_at": ts(record.last_login_at),
                "created_at": ts(Some(record.created_at)),
                "updated_at": ts(Some(record.updated_at)),
            },
            "password": password.map(|p| json!({
                "set": true,
                "algorithm": p.algorithm,
                "must_change": p.must_change,
                "changed_at": ts(Some(p.changed_at)),
            })),
            "profile": profile.map(|p| json!({
                "display_name": p.display_name,
                "locale": p.locale,
                "time_zone": p.time_zone,
                "updated_at": ts(Some(p.updated_at)),
            })),
            "consents": consents.into_iter().map(|c| json!({
                "document": c.document,
                "version": c.version,
                "accepted_at": ts(Some(c.accepted_at)),
                "ip": c.ip.map(|ip| ip.to_string()),
                "user_agent": c.user_agent,
            })).collect::<Vec<_>>(),
            "deletion_requests": deletions.into_iter().map(|d| json!({
                "status": d.status,
                "requested_at": ts(Some(d.requested_at)),
                "scheduled_for": ts(Some(d.scheduled_for)),
                "cancelled_at": ts(d.cancelled_at),
                "completed_at": ts(d.completed_at),
            })).collect::<Vec<_>>(),
            "email_reservations": reservations.into_iter().map(|r| json!({
                "email_normalized": r.email_normalized,
                "reserved_until": ts(Some(r.reserved_until)),
                "created_at": ts(Some(r.created_at)),
            })).collect::<Vec<_>>(),
            "pending_registrations": registrations.into_iter().map(|r| json!({
                "email_normalized": r.email_normalized,
                "display_name": r.display_name,
                "locale": r.locale,
                "time_zone": r.time_zone,
                "requested_from_ip": r.created_ip.map(|ip| ip.to_string()),
                "user_agent": r.user_agent,
                "created_at": ts(Some(r.created_at)),
                "expires_at": ts(Some(r.expires_at)),
            })).collect::<Vec<_>>(),
            "pending_requests": pending.into_iter().map(|t| json!({
                "purpose": t.purpose,
                "target": t.target,
                "requested_from_ip": t.created_ip.map(|ip| ip.to_string()),
                "created_at": ts(Some(t.created_at)),
                "expires_at": ts(Some(t.expires_at)),
            })).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acc_10_section_names_are_validated() {
        assert!(is_valid_section("account"));
        assert!(is_valid_section("mfa_factors2"));
        assert!(!is_valid_section(""));
        assert!(!is_valid_section("Account"));
        assert!(!is_valid_section("2fa"));
        assert!(!is_valid_section("a-b"));
        assert!(!is_valid_section(&"a".repeat(65)));
    }

    #[test]
    fn acc_10_timestamps_are_rfc3339() {
        assert_eq!(ts(None), Value::Null);
        assert_eq!(
            ts(Some(OffsetDateTime::UNIX_EPOCH)),
            Value::String("1970-01-01T00:00:00Z".to_owned())
        );
    }
}
