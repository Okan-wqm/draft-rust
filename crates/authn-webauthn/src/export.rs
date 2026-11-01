//! The `passkeys` section of the personal data export (ACC-10).
//!
//! Lists what the system stores about the user's passkeys — names, dates,
//! flags, transports, the attested model and the WebAuthn user handle —
//! but no public keys, raw credential ids or ceremony state (not personal
//! data in any useful sense, and the export must stay free of key
//! material).

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::DataExporter;
use sqlx::PgConnection;

use crate::service::summary;
use crate::store::{credentials, handles};

/// Exporter registered with authn-account's export aggregator.
#[derive(Debug, Clone, Copy, Default)]
pub struct PasskeyDataExporter;

#[async_trait]
impl DataExporter for PasskeyDataExporter {
    fn section(&self) -> &'static str {
        "passkeys"
    }

    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        let rows = credentials::list_for_user(&mut *conn, user).await?;
        let handle = handles::find(&mut *conn, user).await?;
        let passkeys: Vec<_> = rows.iter().map(summary).collect();
        let handle = handle.map(|h| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h)
        });
        Ok(serde_json::json!({
            "user_handle": handle,
            "passkeys": passkeys,
        }))
    }
}
