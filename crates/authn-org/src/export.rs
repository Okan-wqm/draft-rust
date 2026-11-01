//! The `organizations` section of the personal data export (ACC-10):
//! the user's memberships, personal API keys (metadata only, never the key
//! or its hash), invitations addressed to the user's current address and
//! the organizations whose domain auto-join skips the user (removed / left).

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::{ApiKeyId, InvitationId, OrgId, UserId};
use authn_core::ports::DataExporter;
use authn_store::UserRepository;
use ipnet::IpNet;
use serde::Serialize;
use sqlx::PgConnection;
use time::OffsetDateTime;

/// [`DataExporter`] of authn-org.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrgDataExporter;

#[derive(Serialize, sqlx::FromRow)]
struct MembershipExport {
    org_id: OrgId,
    org_name: String,
    org_slug: String,
    role: String,
    status: String,
    #[serde(with = "time::serde::rfc3339")]
    joined_at: OffsetDateTime,
}

#[derive(Serialize, sqlx::FromRow)]
struct ApiKeyExport {
    id: ApiKeyId,
    org_id: OrgId,
    name: String,
    display_prefix: String,
    scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_used_at: Option<OffsetDateTime>,
    last_used_ip: Option<IpNet>,
    #[serde(with = "time::serde::rfc3339::option")]
    revoked_at: Option<OffsetDateTime>,
}

#[derive(Serialize, sqlx::FromRow)]
struct InvitationExport {
    id: InvitationId,
    org_id: OrgId,
    org_name: String,
    status: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Serialize, sqlx::FromRow)]
struct AutoJoinExclusionExport {
    org_id: OrgId,
    reason: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[async_trait]
impl DataExporter for OrgDataExporter {
    fn section(&self) -> &'static str {
        "organizations"
    }

    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        let memberships = sqlx::query_as::<_, MembershipExport>(
            "SELECT o.id AS org_id, o.name AS org_name, o.slug AS org_slug, r.key AS role, \
             m.status, m.created_at AS joined_at FROM memberships m \
             JOIN organizations o ON o.id = m.org_id JOIN roles r ON r.id = m.role_id \
             WHERE m.user_id = $1 ORDER BY m.created_at, m.id",
        )
        .bind(user)
        .fetch_all(&mut *conn)
        .await?;
        let api_keys = sqlx::query_as::<_, ApiKeyExport>(
            "SELECT id, org_id, name, display_prefix, scopes, created_at, expires_at, \
             last_used_at, last_used_ip, revoked_at FROM api_keys WHERE user_id = $1 \
             ORDER BY created_at, id",
        )
        .bind(user)
        .fetch_all(&mut *conn)
        .await?;
        let email = UserRepository::find_by_id(&mut *conn, user)
            .await?
            .and_then(|u| u.email_normalized);
        let invitations = match email {
            Some(email) => {
                sqlx::query_as::<_, InvitationExport>(
                    "SELECT i.id, i.org_id, o.name AS org_name, i.status, i.created_at, \
                     i.expires_at FROM invitations i JOIN organizations o ON o.id = i.org_id \
                     WHERE i.email_normalized = $1 ORDER BY i.created_at, i.id",
                )
                .bind(email)
                .fetch_all(&mut *conn)
                .await?
            }
            None => Vec::new(),
        };
        let auto_join_exclusions = sqlx::query_as::<_, AutoJoinExclusionExport>(
            "SELECT x.org_id, x.reason, x.created_at FROM org_auto_join_exclusions x \
             WHERE x.user_id = $1 ORDER BY x.created_at, x.org_id",
        )
        .bind(user)
        .fetch_all(&mut *conn)
        .await?;
        Ok(serde_json::json!({
            "memberships": memberships,
            "api_keys": api_keys,
            "invitations": invitations,
            "auto_join_exclusions": auto_join_exclusions,
        }))
    }
}
