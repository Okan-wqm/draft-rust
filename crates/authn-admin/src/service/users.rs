//! User search and details (ADM-02).
//!
//! Listings use keyset pagination on `(created_at DESC, id DESC)` — never
//! `OFFSET` — so concurrent sign-ups neither duplicate nor skip rows of a
//! walk. Nothing secret is ever selected: no password hash, no MFA secret,
//! no token.

use authn_core::domain::{AccountStatus, Cursor, Page, PageRequest};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::SecurityEventKind;
use authn_mfa::MfaStatus;
use authn_store::{UserRecord, UserRepository, UserSearchFilter};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{IntoParams, ToSchema};

use super::{AdminService, meta};
use crate::guard::AdminCaller;
use crate::roles::AdminPermission;

/// Status filter of the user listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserStatusFilter {
    /// `pending_verification`.
    PendingVerification,
    /// `active`.
    Active,
    /// `locked`.
    Locked,
    /// `suspended`.
    Suspended,
    /// `disabled`.
    Disabled,
    /// `pending_deletion`.
    PendingDeletion,
    /// `deleted`.
    Deleted,
}

impl From<UserStatusFilter> for AccountStatus {
    fn from(s: UserStatusFilter) -> Self {
        match s {
            UserStatusFilter::PendingVerification => Self::PendingVerification,
            UserStatusFilter::Active => Self::Active,
            UserStatusFilter::Locked => Self::Locked,
            UserStatusFilter::Suspended => Self::Suspended,
            UserStatusFilter::Disabled => Self::Disabled,
            UserStatusFilter::PendingDeletion => Self::PendingDeletion,
            UserStatusFilter::Deleted => Self::Deleted,
        }
    }
}

/// Query of `GET /v1/admin/users`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct UserSearch {
    /// Page size, 1–100 (default 20).
    pub limit: Option<u32>,
    /// Cursor returned as `next_cursor` by the previous page.
    pub cursor: Option<String>,
    /// Case-insensitive prefix of the e-mail address (1–254 characters).
    pub email: Option<String>,
    /// Account status.
    pub status: Option<UserStatusFilter>,
    /// Only platform admins (`true`) or only non-admins (`false`).
    pub platform_admin: Option<bool>,
    /// Only verified (`true`) or unverified (`false`) addresses.
    pub email_verified: Option<bool>,
    /// Accounts created at or after this instant (RFC 3339).
    pub created_after: Option<String>,
    /// Accounts created before this instant (RFC 3339).
    pub created_before: Option<String>,
}

fn invalid(field: &'static str) -> AuthError {
    AuthError::new(codes::common::VALIDATION_FAILED)
        .with_details(serde_json::json!({ "field": field }))
}

fn parse_time(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<OffsetDateTime>, AuthError> {
    value
        .map(|v| {
            if v.len() > 64 {
                return Err(invalid(field));
            }
            OffsetDateTime::parse(v, &Rfc3339).map_err(|_| invalid(field))
        })
        .transpose()
}

impl UserSearch {
    fn into_filter(self) -> Result<(UserSearchFilter, PageRequest), AuthError> {
        let email_prefix = match self.email.as_deref().map(str::trim) {
            None => None,
            Some(e)
                if e.is_empty() || e.chars().count() > 254 || e.chars().any(char::is_control) =>
            {
                return Err(invalid("email"));
            }
            Some(e) => Some(e.to_lowercase()),
        };
        let filter = UserSearchFilter {
            email_prefix,
            status: self.status.map(AccountStatus::from),
            platform_admin: self.platform_admin,
            email_verified: self.email_verified,
            created_after: parse_time(self.created_after.as_deref(), "created_after")?,
            created_before: parse_time(self.created_before.as_deref(), "created_before")?,
        };
        let page = PageRequest {
            limit: self.limit,
            cursor: self.cursor,
        };
        page.cursor()?;
        Ok((filter, page))
    }
}

/// One account of the listing. Contains no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminUserSummary {
    /// User id.
    pub id: UserId,
    /// Address (`None` only for deleted accounts).
    pub email: Option<String>,
    /// Whether the address is verified.
    pub email_verified: bool,
    /// Lifecycle status.
    #[schema(value_type = String)]
    pub status: AccountStatus,
    /// Platform administrator.
    pub is_platform_admin: bool,
    /// Break-glass account (ADM-05).
    pub is_break_glass: bool,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Last successful login.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_login_at: Option<OffsetDateTime>,
}

impl From<UserRecord> for AdminUserSummary {
    fn from(row: UserRecord) -> Self {
        Self {
            id: row.id,
            email: row.email,
            email_verified: row.email_verified_at.is_some(),
            status: row.status,
            is_platform_admin: row.is_platform_admin,
            is_break_glass: row.is_break_glass,
            created_at: row.created_at,
            last_login_at: row.last_login_at,
        }
    }
}

/// Password facts of an account (never the hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PasswordState {
    /// The account has a password.
    pub set: bool,
    /// The user must change it at the next login (PWD-12).
    pub must_change: bool,
    /// Last change.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub changed_at: Option<OffsetDateTime>,
}

/// Details of one account (ADM-02). Contains no secret: no password hash,
/// no MFA secret or recovery code, contact data of SMS factors masked.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminUserDetail {
    /// User id.
    pub id: UserId,
    /// Address (`None` only for deleted accounts).
    pub email: Option<String>,
    /// When the address was verified.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub email_verified_at: Option<OffsetDateTime>,
    /// Lifecycle status.
    #[schema(value_type = String)]
    pub status: AccountStatus,
    /// Reason code of the last status change.
    pub status_reason: Option<String>,
    /// When the status last changed.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub status_changed_at: OffsetDateTime,
    /// End of a temporary account lock (ACC-06).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub locked_until: Option<OffsetDateTime>,
    /// End of a login soft lock (PRT-03).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub soft_locked_until: Option<OffsetDateTime>,
    /// Platform administrator.
    pub is_platform_admin: bool,
    /// Break-glass account.
    pub is_break_glass: bool,
    /// Last successful login.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_login_at: Option<OffsetDateTime>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Password facts.
    pub password: PasswordState,
    /// Second factors (no secrets; passkeys are listed by authn-webauthn).
    #[schema(value_type = Object)]
    pub mfa: MfaStatus,
}

fn time_to_micros(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000).unwrap_or(i64::MAX)
}

fn micros_to_time(micros: i64) -> Result<OffsetDateTime, AuthError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
        .map_err(|_| AuthError::new(codes::common::VALIDATION_FAILED))
}

impl AdminService {
    /// Searches accounts (ADM-02): keyset pages, newest first.
    pub async fn search_users(
        &self,
        caller: &AdminCaller,
        query: UserSearch,
    ) -> Result<Page<AdminUserSummary>, AuthError> {
        caller.require(AdminPermission::UsersRead)?;
        let (filter, page) = query.into_filter()?;
        let after = match page.cursor()? {
            Some(c) => Some((micros_to_time(c.sort_key)?, UserId::from_uuid(c.id))),
            None => None,
        };
        let limit = page.limit();
        let rows =
            UserRepository::search(self.pool(), &filter, after, i64::from(limit) + 1).await?;
        let items: Vec<AdminUserSummary> = rows.into_iter().map(AdminUserSummary::from).collect();
        Ok(Page::from_overfetch(items, limit, |u| Cursor {
            sort_key: time_to_micros(u.created_at),
            id: u.id.as_uuid(),
        }))
    }

    /// Details of one account (ADM-02). The access is audited
    /// (`admin.action`, `user_viewed`).
    pub async fn user_detail(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<AdminUserDetail, AuthError> {
        caller.require(AdminPermission::UsersRead)?;
        let record = UserRepository::find_by_id(self.pool(), user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let password = UserRepository::find_password(self.pool(), user).await?;
        let mfa = self.deps().mfa.status_for_user(user).await?;
        let soft_locked_until = self.deps().protection.locked_until(user).await?;
        let mut tx = self.begin().await?;
        self.record_action(
            &mut tx,
            ctx,
            caller,
            SecurityEventKind::AdminAction,
            "user_viewed",
            Some(user),
            None,
            meta([]),
        )
        .await?;
        authn_store::commit(tx).await?;
        Ok(AdminUserDetail {
            id: record.id,
            email: record.email,
            email_verified_at: record.email_verified_at,
            status: record.status,
            status_reason: record.status_reason,
            status_changed_at: record.status_changed_at,
            locked_until: record.locked_until,
            soft_locked_until,
            is_platform_admin: record.is_platform_admin,
            is_break_glass: record.is_break_glass,
            last_login_at: record.last_login_at,
            created_at: record.created_at,
            password: PasswordState {
                set: password.is_some(),
                must_change: password.as_ref().is_some_and(|p| p.must_change),
                changed_at: password.map(|p| p.changed_at),
            },
            mfa,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adm_02_search_validation() {
        let (filter, page) = UserSearch {
            email: Some("  Alice@Example ".into()),
            status: Some(UserStatusFilter::Suspended),
            limit: Some(500),
            created_after: Some("2026-01-01T00:00:00Z".into()),
            ..UserSearch::default()
        }
        .into_filter()
        .unwrap();
        assert_eq!(filter.email_prefix.as_deref(), Some("alice@example"));
        assert_eq!(filter.status, Some(AccountStatus::Suspended));
        assert_eq!(page.limit(), 100);
        for bad in [
            UserSearch {
                email: Some(String::new()),
                ..UserSearch::default()
            },
            UserSearch {
                email: Some("a\u{0}b".into()),
                ..UserSearch::default()
            },
            UserSearch {
                created_before: Some("yesterday".into()),
                ..UserSearch::default()
            },
            UserSearch {
                cursor: Some("!!".into()),
                ..UserSearch::default()
            },
        ] {
            let err = bad.into_filter().unwrap_err();
            assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
        }
    }

    #[test]
    fn adm_02_cursor_time_round_trip() {
        let at = OffsetDateTime::from_unix_timestamp_nanos(1_800_000_000_123_456_000).unwrap();
        assert_eq!(micros_to_time(time_to_micros(at)).unwrap(), at);
    }
}
