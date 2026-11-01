//! Personal data export of this module (ACC-10): the `mfa` section.
//!
//! Contains the user's factors (kind, label, phone number, timestamps),
//! recovery-code counters and trusted devices. Never contains a secret: no
//! TOTP secret, no code hash, no token hash (contracts §4 `DataExporter`).

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::DataExporter;
use serde_json::json;
use sqlx::PgConnection;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::store::{factors, recovery, settings, trusted};

/// The `mfa` section exporter (register it with authn-account's export
/// aggregator).
#[derive(Debug, Clone, Copy, Default)]
pub struct MfaDataExporter;

fn ts(at: Option<OffsetDateTime>) -> serde_json::Value {
    at.and_then(|t| t.format(&Rfc3339).ok())
        .map_or(serde_json::Value::Null, serde_json::Value::String)
}

#[async_trait]
impl DataExporter for MfaDataExporter {
    fn section(&self) -> &'static str {
        "mfa"
    }

    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        let factor_rows = factors::list(&mut *conn, user).await?;
        let recovery = recovery::status(&mut *conn, user).await?;
        let preference = settings::find(&mut *conn, user).await?.unwrap_or_default();
        let devices = trusted::list_unrevoked(&mut *conn, user).await?;
        Ok(json!({
            "mfa_enabled": preference.mfa_enabled,
            "factors": factor_rows.iter().map(|f| json!({
                "id": f.id,
                "kind": f.kind,
                "status": f.status.as_str(),
                "label": f.label,
                "phone_number": f.phone_e164,
                "created_at": ts(Some(f.created_at)),
                "confirmed_at": ts(f.confirmed_at),
                "last_used_at": ts(f.last_used_at),
            })).collect::<Vec<_>>(),
            "recovery_codes": {
                "remaining": recovery.remaining,
                "total": recovery.total,
                "generated_at": ts(recovery.generated_at),
            },
            "trusted_devices": devices.iter().map(|d| json!({
                "id": d.id,
                "name": d.device_name,
                "ip": d.created_ip.map(|ip| ip.to_string()),
                "created_at": ts(Some(d.created_at)),
                "expires_at": ts(Some(d.expires_at)),
                "last_used_at": ts(d.last_used_at),
            })).collect::<Vec<_>>(),
        }))
    }
}
