//! The `identities` section of the personal data export (ACC-10).
//!
//! Lists the linked external identities — provider, subject, issuer,
//! asserted address, display name, dates and whether provider tokens are
//! stored — but never the (encrypted) tokens themselves.

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::DataExporter;
use sqlx::PgConnection;

use crate::store;

/// Exporter registered with authn-account's export aggregator.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityDataExporter;

#[async_trait]
impl DataExporter for IdentityDataExporter {
    fn section(&self) -> &'static str {
        "identities"
    }

    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        let rows = store::identities_of(&mut *conn, user).await?;
        let rfc3339 = |t: time::OffsetDateTime| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        };
        let identities: Vec<_> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "provider": r.provider,
                    "subject": r.subject,
                    "issuer": r.issuer,
                    "email": r.email,
                    "email_verified": r.email_verified,
                    "display_name": r.display_name,
                    "provider_tokens_stored": r.access_token_ciphertext.is_some(),
                    "created_at": rfc3339(r.created_at),
                    "last_login_at": r.last_login_at.and_then(rfc3339),
                })
            })
            .collect();
        Ok(serde_json::json!({ "identities": identities }))
    }
}
