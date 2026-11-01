//! The `sessions` section of the personal data export (ACC-10).

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::DataExporter;
use serde_json::{Value, json};
use sqlx::PgConnection;

use crate::store::sessions;

/// Exports the user's sessions (no token material).
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionDataExporter;

#[async_trait]
impl DataExporter for SessionDataExporter {
    fn section(&self) -> &'static str {
        "sessions"
    }

    async fn export(&self, conn: &mut PgConnection, user: UserId) -> Result<Value, AuthError> {
        let records = sessions::list_all_for_user(conn, user).await?;
        let rows: Vec<Value> = records
            .iter()
            .map(|s| {
                json!({
                    "id": s.id,
                    "client_kind": s.client_kind,
                    "device": s.device_name,
                    "user_agent_recorded": s.device_name.is_some(),
                    "created_at": s.created_at.unix_timestamp(),
                    "last_seen_at": s.last_seen_at.unix_timestamp(),
                    "created_ip": s.created_ip.map(|ip| ip.to_string()),
                    "last_seen_ip": s.last_seen_ip.map(|ip| ip.to_string()),
                    "amr": s.amr,
                    "active_org_id": s.active_org_id,
                    "impersonated_by": s.impersonator_user_id,
                    "absolute_expires_at": s.absolute_expires_at.unix_timestamp(),
                })
            })
            .collect();
        Ok(json!({ "sessions": rows }))
    }
}
