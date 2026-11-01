//! Rendering issued credentials and challenges as HTTP responses (SES-03,
//! SES-05). Used by this crate's endpoints and by the login flows.
//!
//! * Web: `Set-Cookie: __Host-authn_session=…` (browser-session cookie
//!   unless "remember me"), the pre-session login-CSRF cookie is deleted,
//!   a device id cookie is set when the browser had none, and the body
//!   carries the new CSRF token. The session token never appears in a body.
//! * Native: access + refresh token in the JSON body.
//! * Every response is `Cache-Control: no-store`.

use authn_core::domain::{AuthMethodRef, ClientKind, FactorKind};
use authn_core::id::{ChallengeId, OrgId, SessionId, UserId};
use authn_core::ports::RequiredAction;
use authn_core::secret::SensitiveString;
use axum::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::cookies;
use crate::model::{IssuedCredentials, SessionRecord};
use crate::service::{IssuedChallenge, remaining_secs};

/// Body of a response that issued or rotated session credentials.
#[derive(Clone, Serialize, ToSchema)]
pub struct CredentialsBody {
    /// `authenticated`.
    pub status: &'static str,
    /// Session id.
    pub session_id: SessionId,
    /// Session owner.
    pub user_id: UserId,
    /// `web` or `native`.
    pub client_kind: ClientKind,
    /// Authentication methods.
    pub amr: Vec<AuthMethodRef>,
    /// Last (re-)authentication.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub auth_time: OffsetDateTime,
    /// Absolute expiry of the session.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// Active organization.
    pub active_org_id: Option<OrgId>,
    /// Web: the CSRF token for `X-CSRF-Token` (SES-04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    /// Native: JWT access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub access_token: Option<SensitiveString>,
    /// Native: `Bearer`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<&'static str>,
    /// Native: seconds until the access token expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Native: opaque refresh token (rotated on every use).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub refresh_token: Option<SensitiveString>,
    /// Native: expiry of the refresh token.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for CredentialsBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialsBody")
            .field("session_id", &self.session_id)
            .field("client_kind", &self.client_kind)
            .finish_non_exhaustive()
    }
}

/// Body of a response that requires more login steps (SES-02, SES-22).
#[derive(Clone, Serialize, ToSchema)]
pub struct ChallengeBody {
    /// `challenge_required`.
    pub status: &'static str,
    /// Challenge id.
    pub challenge_id: ChallengeId,
    /// Native clients: the challenge token to present with each step. Web
    /// clients receive it as the `__Host-authn_challenge` cookie instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub challenge_token: Option<SensitiveString>,
    /// Expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// Second factors that may be used.
    pub allowed_factors: Vec<FactorKind>,
    /// Steps to complete.
    pub required_actions: Vec<RequiredAction>,
}

impl std::fmt::Debug for ChallengeBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeBody")
            .field("challenge_id", &self.challenge_id)
            .finish_non_exhaustive()
    }
}

fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// The body and cookies of issued credentials.
#[must_use]
pub fn credentials_response(
    record: &SessionRecord,
    credentials: IssuedCredentials,
    now: OffsetDateTime,
) -> Response {
    let mut body = CredentialsBody {
        status: "authenticated",
        session_id: record.id,
        user_id: record.user_id,
        client_kind: record.client_kind,
        amr: record.amr.clone(),
        auth_time: record.auth_time,
        expires_at: record.absolute_expires_at,
        active_org_id: record.active_org_id,
        csrf_token: None,
        access_token: None,
        token_type: None,
        expires_in: None,
        refresh_token: None,
        refresh_token_expires_at: None,
    };
    let mut cookies_to_set = Vec::new();
    match credentials {
        IssuedCredentials::Web {
            session_token,
            csrf_token,
            persistent_for,
            new_device_id,
        } => {
            body.csrf_token = Some(csrf_token);
            cookies_to_set.push(cookies::session_cookie(
                session_token.expose(),
                persistent_for,
            ));
            cookies_to_set.push(cookies::clear_pre_session_cookie());
            if let Some(device) = new_device_id {
                cookies_to_set.push(cookies::device_cookie(&device));
            }
        }
        IssuedCredentials::Native {
            access_token,
            access_token_expires_at,
            refresh_token,
            refresh_token_expires_at,
        } => {
            body.access_token = Some(access_token);
            body.token_type = Some("Bearer");
            body.expires_in = Some(remaining_secs(now, access_token_expires_at));
            body.refresh_token = Some(refresh_token);
            body.refresh_token_expires_at = Some(refresh_token_expires_at);
        }
    }
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    for cookie in cookies_to_set {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    no_store(&mut response);
    response
}

/// The session cookie as a `303 See Other` redirect to an already
/// validated `return_to` (PRT-10), for top-level navigations (federated
/// callbacks).
#[must_use]
pub fn redirect_with_session(location: &str, session_cookie: HeaderValue) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(LOCATION, value);
    }
    response.headers_mut().append(SET_COOKIE, session_cookie);
    response
        .headers_mut()
        .append(SET_COOKIE, cookies::clear_pre_session_cookie());
    no_store(&mut response);
    response
}

/// A pending challenge: web clients get the token as a `SameSite=Strict`
/// cookie, native clients in the body.
#[must_use]
pub fn challenge_response(issued: IssuedChallenge, now: OffsetDateTime) -> Response {
    let web = issued.challenge.client_kind == ClientKind::Web;
    let max_age = std::time::Duration::from_secs(remaining_secs(now, issued.challenge.expires_at));
    let cookie = web.then(|| cookies::challenge_cookie(issued.token.expose(), max_age));
    let body = ChallengeBody {
        status: "challenge_required",
        challenge_id: issued.challenge.id,
        challenge_token: (!web).then_some(issued.token),
        expires_at: issued.challenge.expires_at,
        allowed_factors: issued.challenge.allowed_factors,
        required_actions: issued.challenge.required_actions,
    };
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    no_store(&mut response);
    response
}
