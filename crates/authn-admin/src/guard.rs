//! Who may use `/v1/admin/**` (ADM-01).
//!
//! Every admin request — reads included — must satisfy **all** of:
//!
//! 1. the request is not made under impersonation, read-only or not (the
//!    impersonating admin acts *as the user* there, never as an admin);
//! 2. the credential is a session of a human user (no API key, no service
//!    account);
//! 3. the principal is a platform admin **and** the database still says so
//!    for an `active` account (the flag is re-read on every request, so a
//!    demoted or suspended admin is refused at once);
//! 4. the client IP is in `admin.ip_allow_list` when one is configured;
//! 5. the session was established with phishing-resistant MFA: a passkey
//!    (`amr` `hwk` or `swk`) that counted as multi-factor (`mfa`);
//! 6. the last (re-)authentication is at most `admin.step_up_max_age`
//!    (default 10 minutes) old.
//!
//! Failures 1–4 answer the same `403 forbidden` (a non-admin learns nothing
//! about the admin API or its allow-list); 5 answers
//! `admin_phishing_resistant_mfa_required`, 6 `401 step_up_required`.
//! The checks are a pure function ([`authorize`]) applied by the
//! [`AdminCaller`] extractor that every admin handler takes.

use std::net::IpAddr;

use authn_core::domain::{AccountStatus, AuthMethodRef, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{SessionId, UserId};
use authn_store::UserRecord;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use time::OffsetDateTime;

use crate::service::AdminService;
use crate::settings::AdminSettings;

/// An authorized platform admin on this request. Only [`authorize`] (via
/// [`AdminService::authorize`] or the extractor) creates one, so every
/// service operation taking an `AdminCaller` has passed the ADM-01 checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCaller {
    user_id: UserId,
    session_id: SessionId,
    is_break_glass: bool,
}

impl AdminCaller {
    /// The admin's user id.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The admin's own session (inherited by impersonation sessions).
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Whether the admin is a break-glass account (ADM-05).
    #[must_use]
    pub fn is_break_glass(&self) -> bool {
        self.is_break_glass
    }
}

/// Why the guard refused a request (logged and counted; the client sees
/// only the error code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// The request is made under impersonation.
    Impersonated,
    /// API key, service account or no session.
    NotASession,
    /// Not a platform admin, or the account is no longer an active admin.
    NotAdmin,
    /// The client IP is not in the allow-list.
    IpNotAllowed,
    /// The session lacks phishing-resistant MFA.
    PhishingResistantMfaMissing,
    /// The last authentication is too old.
    StepUpRequired,
}

impl Denial {
    /// Stable label (metrics, logs, audit reason).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Impersonated => "impersonated",
            Self::NotASession => "not_a_session",
            Self::NotAdmin => "not_platform_admin",
            Self::IpNotAllowed => "ip_not_allowed",
            Self::PhishingResistantMfaMissing => "phishing_resistant_mfa_missing",
            Self::StepUpRequired => "step_up_required",
        }
    }

    /// The error returned to the client.
    #[must_use]
    pub fn into_error(self) -> AuthError {
        match self {
            Self::Impersonated | Self::NotASession | Self::NotAdmin | Self::IpNotAllowed => {
                AuthError::new(codes::common::FORBIDDEN).with_context(self.as_str())
            }
            Self::PhishingResistantMfaMissing => {
                AuthError::new(codes::admin::PHISHING_RESISTANT_MFA_REQUIRED)
            }
            Self::StepUpRequired => AuthError::new(codes::common::STEP_UP_REQUIRED),
        }
    }
}

/// Whether the session's authentication methods are phishing-resistant
/// MFA: a passkey (`hwk` device-bound or `swk` synced) that counted as
/// multi-factor (`mfa`, i.e. user verification or a second factor).
#[must_use]
pub fn is_phishing_resistant_mfa(amr: &[AuthMethodRef]) -> bool {
    let passkey = amr
        .iter()
        .any(|a| matches!(a, AuthMethodRef::Hwk | AuthMethodRef::Swk));
    passkey && amr.contains(&AuthMethodRef::Mfa)
}

/// The ADM-01 decision. `live` is the caller's `users` row read on this
/// request (`None` if the account no longer exists).
pub fn authorize(
    principal: &Principal,
    live: Option<&UserRecord>,
    client_ip: IpAddr,
    now: OffsetDateTime,
    settings: &AdminSettings,
) -> Result<AdminCaller, Denial> {
    if principal.impersonation.is_some() {
        return Err(Denial::Impersonated);
    }
    let (Some(user_id), Some(session_id)) = (principal.user_id(), principal.session_id()) else {
        return Err(Denial::NotASession);
    };
    let live = live
        .filter(|u| u.id == user_id && u.is_platform_admin && u.status == AccountStatus::Active);
    let Some(live) = live else {
        return Err(Denial::NotAdmin);
    };
    if !principal.is_platform_admin {
        return Err(Denial::NotAdmin);
    }
    if !settings.ip_allow_list.is_empty()
        && !settings
            .ip_allow_list
            .iter()
            .any(|net| net.contains(&client_ip))
    {
        return Err(Denial::IpNotAllowed);
    }
    if !is_phishing_resistant_mfa(&principal.amr) {
        return Err(Denial::PhishingResistantMfaMissing);
    }
    match principal.require_recent_authentication(now, settings.step_up_max_age) {
        Ok(()) => {}
        Err(e) if e.is(codes::common::STEP_UP_REQUIRED) => return Err(Denial::StepUpRequired),
        Err(_) => return Err(Denial::Impersonated),
    }
    Ok(AdminCaller {
        user_id,
        session_id,
        is_break_glass: live.is_break_glass,
    })
}

impl<S> FromRequestParts<S> for AdminCaller
where
    S: Send + Sync,
    AdminService: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx = RequestContext::from_request_parts(parts, state).await?;
        let principal = Principal::from_request_parts(parts, state).await?;
        AdminService::from_ref(state)
            .authorize(&principal, &ctx)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use authn_core::domain::{Impersonation, PrincipalCredential, Subject};
    use authn_core::id::{ApiKeyId, OrgId, ServiceAccountId};

    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn admin_principal(user: UserId) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Hwk, AuthMethodRef::User, AuthMethodRef::Mfa],
            acr: None,
            auth_time: Some(now() - Duration::from_secs(60)),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: true,
            login_method: None,
            mfa_factors: Vec::new(),
        }
    }

    fn record(user: UserId, admin: bool, status: AccountStatus) -> UserRecord {
        UserRecord {
            id: user,
            email: Some("admin@example.com".into()),
            email_normalized: Some("admin@example.com".into()),
            email_verified_at: Some(now()),
            status,
            status_reason: None,
            status_changed_at: now(),
            locked_until: None,
            is_platform_admin: admin,
            is_break_glass: false,
            last_login_at: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn ip() -> IpAddr {
        "198.51.100.7".parse().unwrap()
    }

    #[test]
    fn adm_01_authorization_matrix_on_the_pure_decision() {
        let settings = AdminSettings::default();
        let user = UserId::generate();
        let live = record(user, true, AccountStatus::Active);
        let ok = admin_principal(user);
        let caller = authorize(&ok, Some(&live), ip(), now(), &settings).unwrap();
        assert_eq!(caller.user_id(), user);

        let mut p = ok.clone();
        p.is_platform_admin = false;
        assert_eq!(
            authorize(&p, Some(&live), ip(), now(), &settings),
            Err(Denial::NotAdmin)
        );
        let demoted = record(user, false, AccountStatus::Active);
        assert_eq!(
            authorize(&ok, Some(&demoted), ip(), now(), &settings),
            Err(Denial::NotAdmin)
        );
        let suspended = record(user, true, AccountStatus::Suspended);
        assert_eq!(
            authorize(&ok, Some(&suspended), ip(), now(), &settings),
            Err(Denial::NotAdmin)
        );
        assert_eq!(
            authorize(&ok, None, ip(), now(), &settings),
            Err(Denial::NotAdmin)
        );
        let other = record(UserId::generate(), true, AccountStatus::Active);
        assert_eq!(
            authorize(&ok, Some(&other), ip(), now(), &settings),
            Err(Denial::NotAdmin)
        );

        for amr in [
            vec![AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa],
            vec![AuthMethodRef::Hwk, AuthMethodRef::User],
            vec![AuthMethodRef::Pwd],
        ] {
            let mut p = ok.clone();
            p.amr = amr;
            assert_eq!(
                authorize(&p, Some(&live), ip(), now(), &settings),
                Err(Denial::PhishingResistantMfaMissing)
            );
        }
        let mut synced = ok.clone();
        synced.amr = vec![AuthMethodRef::Swk, AuthMethodRef::Mfa];
        assert!(authorize(&synced, Some(&live), ip(), now(), &settings).is_ok());

        let mut stale = ok.clone();
        stale.auth_time = Some(now() - Duration::from_secs(601));
        assert_eq!(
            authorize(&stale, Some(&live), ip(), now(), &settings),
            Err(Denial::StepUpRequired)
        );
        stale.auth_time = None;
        assert_eq!(
            authorize(&stale, Some(&live), ip(), now(), &settings),
            Err(Denial::StepUpRequired)
        );

        for read_only in [true, false] {
            let mut p = ok.clone();
            p.impersonation = Some(Impersonation {
                admin_user_id: UserId::generate(),
                read_only,
                expires_at: now(),
            });
            assert_eq!(
                authorize(&p, Some(&live), ip(), now(), &settings),
                Err(Denial::Impersonated)
            );
        }

        let mut key = ok.clone();
        key.credential = PrincipalCredential::ApiKey {
            api_key_id: ApiKeyId::generate(),
        };
        assert_eq!(
            authorize(&key, Some(&live), ip(), now(), &settings),
            Err(Denial::NotASession)
        );
        let mut service = ok.clone();
        service.subject = Subject::ServiceAccount {
            service_account_id: ServiceAccountId::generate(),
            org_id: OrgId::generate(),
        };
        assert_eq!(
            authorize(&service, Some(&live), ip(), now(), &settings),
            Err(Denial::NotASession)
        );

        let restricted = AdminSettings {
            ip_allow_list: vec!["10.0.0.0/8".parse().unwrap()],
            ..AdminSettings::default()
        };
        assert_eq!(
            authorize(&ok, Some(&live), ip(), now(), &restricted),
            Err(Denial::IpNotAllowed)
        );
        assert!(
            authorize(
                &ok,
                Some(&live),
                "10.1.2.3".parse().unwrap(),
                now(),
                &restricted
            )
            .is_ok()
        );
    }

    #[test]
    fn adm_01_denials_map_to_stable_codes() {
        for d in [
            Denial::Impersonated,
            Denial::NotASession,
            Denial::NotAdmin,
            Denial::IpNotAllowed,
        ] {
            assert_eq!(d.into_error().code(), codes::common::FORBIDDEN);
        }
        assert_eq!(
            Denial::PhishingResistantMfaMissing.into_error().code(),
            codes::admin::PHISHING_RESISTANT_MFA_REQUIRED
        );
        assert_eq!(
            Denial::StepUpRequired.into_error().code(),
            codes::common::STEP_UP_REQUIRED
        );
    }
}
