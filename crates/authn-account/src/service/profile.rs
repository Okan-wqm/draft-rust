//! Profile (ACC-08): display name, language, time zone.

use authn_core::domain::{Locale, Principal};
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{DomainEvent, DomainEventKind};
use authn_store::{UserRecord, UserRepository};

use super::AccountService;
use crate::lifecycle::lock_user;
use crate::model::{ProfileUpdate, ProfileView};
use crate::profile::{DEFAULT_TIME_ZONE, normalize_display_name, validate_time_zone};
use crate::repo::{ProfileRecord, ProfileRepository, ProfileValues};

fn view(user: &UserRecord, profile: Option<ProfileRecord>, fallback: Locale) -> ProfileView {
    ProfileView {
        user_id: user.id,
        email: user.email.clone(),
        email_verified: user.is_email_verified(),
        status: user.status,
        display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
        locale: profile.as_ref().map_or(fallback, |p| p.locale),
        time_zone: profile.map_or_else(|| DEFAULT_TIME_ZONE.to_owned(), |p| p.time_zone),
    }
}

impl AccountService {
    /// The signed-in user's profile (allowed during read-only
    /// impersonation).
    pub async fn profile(&self, principal: &Principal) -> Result<ProfileView, AuthError> {
        let user = self.principal_user(principal.require_user()?).await?;
        let profile = ProfileRepository::find(self.pool(), user.id).await?;
        Ok(view(&user, profile, Locale::default()))
    }

    /// A user's profile for other modules (display name / language for
    /// notifications, PWD-04 inputs, admin views). `None` for unknown users.
    pub async fn profile_of(&self, user: UserId) -> Result<Option<ProfileView>, AuthError> {
        let Some(user) = UserRepository::find_by_id(self.pool(), user).await? else {
            return Ok(None);
        };
        let profile = ProfileRepository::find(self.pool(), user.id).await?;
        Ok(Some(view(&user, profile, Locale::default())))
    }

    /// [`Self::profile_of`] through the caller's connection (inside its
    /// transaction): never waits for a second pooled connection while the
    /// caller holds one (K-58, pool pattern).
    pub async fn profile_of_in(
        &self,
        conn: &mut sqlx::PgConnection,
        user: UserId,
    ) -> Result<Option<ProfileView>, AuthError> {
        let Some(user) = UserRepository::find_by_id(&mut *conn, user).await? else {
            return Ok(None);
        };
        let profile = ProfileRepository::find(&mut *conn, user.id).await?;
        Ok(Some(view(&user, profile, Locale::default())))
    }

    /// ACC-08: updates the signed-in user's profile. Display names are
    /// checked for confusable / mixed-script / invisible characters
    /// (ACC-03), time zones against the IANA database.
    pub async fn update_profile(
        &self,
        principal: &Principal,
        update: ProfileUpdate,
    ) -> Result<ProfileView, AuthError> {
        let user_id = Self::self_service_user(principal)?;
        let display_name = match &update.display_name {
            Some(Some(name)) => Some(Some(normalize_display_name(
                name,
                self.config().display_name_max_chars,
            )?)),
            Some(None) => Some(None),
            None => None,
        };
        let time_zone = update
            .time_zone
            .as_deref()
            .map(validate_time_zone)
            .transpose()?;
        let now = self.now();
        let mut tx = self.begin().await?;
        let user = lock_user(&mut tx, user_id).await?;
        let current = ProfileRepository::find(tx.conn(), user.id).await?;
        let merged_name = match display_name {
            Some(name) => name,
            None => current.as_ref().and_then(|p| p.display_name.clone()),
        };
        let merged_locale = update
            .locale
            .or(current.as_ref().map(|p| p.locale))
            .unwrap_or_default();
        let merged_tz = time_zone
            .map(str::to_owned)
            .or_else(|| current.as_ref().map(|p| p.time_zone.clone()))
            .unwrap_or_else(|| DEFAULT_TIME_ZONE.to_owned());
        ProfileRepository::upsert(
            tx.conn(),
            user.id,
            &ProfileValues {
                display_name: merged_name.as_deref(),
                locale: merged_locale,
                time_zone: &merged_tz,
            },
            now,
        )
        .await?;
        self.deps()
            .events
            .publish(
                tx.conn(),
                DomainEvent {
                    user_id: Some(user.id),
                    ..DomainEvent::new(
                        DomainEventKind::UserUpdated,
                        now,
                        serde_json::json!({ "user_id": user.id, "profile_updated": true }),
                    )
                },
            )
            .await?;
        let profile = ProfileRepository::find(tx.conn(), user.id).await?;
        tx.commit().await?;
        Ok(view(&user, profile, merged_locale))
    }
}
