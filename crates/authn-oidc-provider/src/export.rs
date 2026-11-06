//! Personal-data export section `oauth_provider` (ACC-10, OIDP-05): the
//! applications the user granted access and the live grants — never a
//! token, code or hash.

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::DataExporter;
use sqlx::PgConnection;
use time::OffsetDateTime;

/// The `oauth_provider` export section.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProviderDataExporter;

#[derive(sqlx::FromRow)]
struct GrantExport {
    client_id: String,
    client_name: String,
    scopes: Vec<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

fn rfc3339(t: OffsetDateTime) -> serde_json::Value {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_or(serde_json::Value::Null, serde_json::Value::String)
}

#[async_trait]
impl DataExporter for ProviderDataExporter {
    fn section(&self) -> &'static str {
        "oauth_provider"
    }

    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        let consents = crate::store::list_consents(&mut *conn, user).await?;
        let grants = sqlx::query_as::<_, GrantExport>(
            "SELECT c.client_id, c.name AS client_name, g.scopes, g.created_at, g.expires_at, \
             g.revoked_at FROM oidc_grants g JOIN oidc_clients c ON c.id = g.client_id \
             WHERE g.user_id = $1 ORDER BY g.created_at LIMIT 1000",
        )
        .bind(user)
        .fetch_all(&mut *conn)
        .await?;
        Ok(serde_json::json!({
            "consents": consents.iter().map(|c| serde_json::json!({
                "client_id": c.client_id,
                "client_name": c.client_name,
                "scopes": c.scopes,
                "resources": c.resources,
                "granted_at": rfc3339(c.granted_at),
                "updated_at": rfc3339(c.updated_at),
            })).collect::<Vec<_>>(),
            "grants": grants.iter().map(|g| serde_json::json!({
                "client_id": g.client_id,
                "client_name": g.client_name,
                "scopes": g.scopes,
                "created_at": rfc3339(g.created_at),
                "expires_at": rfc3339(g.expires_at),
                "revoked_at": g.revoked_at.map_or(serde_json::Value::Null, rfc3339),
            })).collect::<Vec<_>>(),
        }))
    }
}
