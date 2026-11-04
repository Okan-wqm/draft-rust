//! Completing a login and issuing sessions (SES-01, SES-02, SES-21, SES-22,
//! ADM-04). Owner of this file: authn-session.
//!
//! Wave-B crates must not depend on each other, yet social login
//! (authn-oidc-client) and impersonation (authn-admin) need to create
//! sessions through the one login pipeline. They do it through this port:
//! the caller proves a *primary* authentication, the implementation runs the
//! rest of the pipeline (account status, risk, organization policy, MFA
//! requirement, required actions) and either issues a session or returns a
//! challenge.

use std::time::Duration;

use async_trait::async_trait;
use axum::response::Response;
use serde::Serialize;
use sqlx::PgConnection;
use time::OffsetDateTime;

use crate::domain::{AuthMethodRef, ClientKind, FactorKind, LoginMethod};
use crate::error::AuthError;
use crate::http::RequestContext;
use crate::id::{ChallengeId, EventId, OrgId, SessionId, UserId};
use crate::secret::SensitiveString;

/// Runs the post-identification login pipeline.
#[async_trait]
pub trait SessionIssuer: Send + Sync {
    /// Continues the login after a successful primary authentication.
    /// The caller must already have verified the credential (password,
    /// passkey, provider ID token…) for `auth.user_id`.
    async fn complete_primary_authentication(
        &self,
        ctx: &RequestContext,
        auth: PrimaryAuthentication,
    ) -> Result<LoginOutcome, AuthError>;

    /// Renders a login outcome as an HTTP response: sets the session cookie
    /// for web clients (SES-03) or returns tokens as JSON for native clients
    /// (SES-05). For web redirects, `return_to` must already be validated
    /// against the redirect allow-list (PRT-10).
    fn login_response(&self, outcome: LoginOutcome, return_to: Option<&str>) -> Response;

    /// Starts an impersonation session for a platform admin (ADM-04). The
    /// caller (authn-admin) has already checked the admin's authority,
    /// step-up and the target's eligibility.
    async fn start_impersonation(
        &self,
        ctx: &RequestContext,
        request: ImpersonationRequest,
    ) -> Result<IssuedSession, AuthError>;

    /// [`SessionIssuer::start_impersonation`] with the client kind of the
    /// impersonation session (a web cookie session, or native tokens whose
    /// access tokens carry the RFC 8693 `act` claim) and the admin's own
    /// session, whose authentication methods (`amr` / `acr`) the
    /// impersonation session inherits. `admin_session = None` uses the
    /// admin's most recently authenticated active session; an admin without
    /// an active session cannot impersonate.
    ///
    /// The default implementation serves web sessions through
    /// [`SessionIssuer::start_impersonation`] and refuses native ones; the
    /// authn-session implementation overrides it.
    async fn start_impersonation_with(
        &self,
        ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        admin_session: Option<SessionId>,
    ) -> Result<IssuedSession, AuthError> {
        let _ = admin_session;
        match client {
            ClientKind::Web => self.start_impersonation(ctx, request).await,
            ClientKind::Native => Err(AuthError::new(crate::error::codes::common::BAD_REQUEST)
                .with_context("native impersonation is not supported by this issuer")),
        }
    }

    /// [`SessionIssuer::start_impersonation_with`] inside the **caller's
    /// transaction** `conn`, recording the `admin.impersonation_started`
    /// audit event with the caller-chosen id `event_id` (ADM-04, ADM-08).
    ///
    /// The caller (authn-admin) can then store the justification of the
    /// impersonation against `event_id` in the same transaction, so the
    /// session, the user notification, the audit event and the
    /// justification commit — or roll back — together. Nothing is visible
    /// until the caller commits `conn`; dropping it without commit undoes
    /// everything. `event_id` must be fresh (a duplicate fails the insert).
    ///
    /// The default implementation refuses (an issuer without transactional
    /// support must not pretend to be atomic); the authn-session
    /// implementation overrides it.
    async fn start_impersonation_audited(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        admin_session: Option<SessionId>,
        event_id: EventId,
    ) -> Result<IssuedSession, AuthError> {
        let _ = (conn, ctx, request, client, admin_session, event_id);
        Err(AuthError::internal(
            "transactional impersonation is not supported by this issuer",
        ))
    }
}

/// Proof of a successful primary authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryAuthentication {
    /// Authenticated user.
    pub user_id: UserId,
    /// Login method used.
    pub method: LoginMethod,
    /// Methods proven so far (e.g. `[swk, user]` for a synced passkey).
    pub amr: Vec<AuthMethodRef>,
    /// Requesting client.
    pub client: ClientKind,
    /// "Remember me" (SES-06).
    pub remember_me: bool,
    /// "This is not my device" (SES-07).
    pub shared_device: bool,
    /// Organization to activate, if requested.
    pub requested_org: Option<OrgId>,
    /// The external provider asserted MFA (only honoured when configured,
    /// SOC-09).
    pub provider_asserted_mfa: bool,
}

/// What a login produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// A full session was issued.
    Authenticated(IssuedSession),
    /// More steps are needed (MFA, required actions).
    ChallengeRequired(PendingChallenge),
}

/// A newly issued session and its credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSession {
    /// Session id.
    pub session_id: SessionId,
    /// Session owner.
    pub user_id: UserId,
    /// Client kind.
    pub client: ClientKind,
    /// Opaque web session token (cookie value), web clients only.
    pub session_token: Option<SensitiveString>,
    /// JWT access token, native clients only.
    pub access_token: Option<SensitiveString>,
    /// Access token expiry.
    pub access_token_expires_at: Option<OffsetDateTime>,
    /// Opaque refresh token, native clients only.
    pub refresh_token: Option<SensitiveString>,
    /// Idle expiry.
    pub idle_expires_at: OffsetDateTime,
    /// Absolute expiry (never extended, SES-06).
    pub absolute_expires_at: OffsetDateTime,
    /// Whether the cookie must be a browser-session cookie (SES-07).
    pub browser_session_only: bool,
}

/// An outstanding login challenge (SES-02, SES-22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChallenge {
    /// Challenge id.
    pub challenge_id: ChallengeId,
    /// Opaque challenge token returned to the client.
    pub challenge_token: SensitiveString,
    /// Expiry (default 5 minutes).
    pub expires_at: OffsetDateTime,
    /// Factors the user may use now.
    pub allowed_factors: Vec<FactorKind>,
    /// Steps that must be completed before a session is issued.
    pub required_actions: Vec<RequiredAction>,
}

text_enum! {
    /// Mandatory steps before a full session (SES-22).
    pub enum RequiredAction {
        /// Verify a second factor.
        VerifyMfa => "verify_mfa",
        /// Enroll a second factor (policy requires MFA, none enrolled).
        EnrollMfa => "enroll_mfa",
        /// Change the password (`must_change_password`, PWD-12).
        ChangePassword => "change_password",
        /// Accept new terms / privacy policy (ACC-11).
        AcceptTerms => "accept_terms",
        /// Verify the e-mail address (ACC-05 restricted mode).
        VerifyEmail => "verify_email",
    }
}

/// Request to impersonate a user (ADM-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpersonationRequest {
    /// The acting platform admin.
    pub admin_user_id: UserId,
    /// The impersonated user.
    pub target_user_id: UserId,
    /// Read-only mode (default).
    pub read_only: bool,
    /// Duration (default 15 min, max 60 min).
    pub ttl: Duration,
    /// Mandatory justification.
    pub reason: String,
}
