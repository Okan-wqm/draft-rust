//! The `SessionIssuer` port (social login, impersonation) and the
//! post-primary login pipeline (SES-15, ADM-04).
//!
//! [`SessionService::complete_login`] is the single place where a verified
//! primary authentication turns into a session or a challenge:
//!
//! 1. the account must allow a login (`AccountService::assess_login`:
//!    disabled / suspended / locked / unverified-blocked accounts are
//!    refused; `verify_email` / `accept_terms` become required actions);
//! 2. a requested organization must admit the user, the client IP and the
//!    login method ([`SessionService::verify_login_org`]);
//! 3. the MFA requirement (authn-mfa `evaluate_for_user`, organization
//!    policy — the requested organization's, otherwise the strictest of the
//!    user's memberships; platform admins need a phishing-resistant factor)
//!    is satisfied by a passkey with user verification (`amr` contains
//!    `mfa`, SES-21; for any other primary method the caller's `mfa` /
//!    `hwk` / `swk` claims are dropped) or — only with
//!    `oidc_client.trust_provider_mfa` and
//!    never where phishing resistance is required — by the identity
//!    provider; otherwise it becomes `verify_mfa` / `enroll_mfa`;
//! 4. no outstanding step → session ([`SessionService::establish`]) +
//!    `login.succeeded`; otherwise a challenge + `login.challenge_issued`.
//!
//! The pipeline itself lives in [`crate::login::pipeline`]; it adds risk
//! evaluation (RSK-03, RSK-04) and trusted devices (MFA-09).

use async_trait::async_trait;
use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::domain::{AuthMethodRef, ClientKind, LoginMethod};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{EventId, SessionId};
use authn_core::ports::{
    Actor, ImpersonationRequest, IssuedSession, LoginOutcome, Notification, NotificationKind,
    PendingChallenge, PrimaryAuthentication, Recipient, SecurityEvent, SecurityEventKind,
    SessionIssuer,
};
use authn_crypto::token::OpaqueToken;
use authn_mfa::OrgMfaPolicy;
use authn_org::OrgPolicy;
use authn_store::UserRepository;
use axum::http::StatusCode;
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use sqlx::PgConnection;

use super::establish::ClientChannel;
use super::org_switch::has_passkey;
use super::{SessionService, after, remaining};
use crate::cookies;
use crate::csrf::LoginCsrfVerified;
use crate::login::pipeline::{LoginSignals, PipelineOutcome};
use crate::metrics;
use crate::model::{DeviceInfo, EstablishedSession, IssuedCredentials, SessionRecord};
use crate::response::{ChallengeBody, CredentialsBody};
use crate::store::refresh::NewRefreshToken;
use crate::store::sessions::{self, NewSession};

/// Longest impersonation justification (`sessions_impersonation_check`).
const MAX_REASON_CHARS: usize = 1000;

/// The MFA input of an organization policy (authn-mfa, MFA-08).
#[must_use]
pub fn org_mfa_policy(policy: &OrgPolicy) -> OrgMfaPolicy {
    OrgMfaPolicy {
        mfa_required: policy.mfa_required || policy.phishing_resistant_mfa_required,
        phishing_resistant_required: policy.phishing_resistant_mfa_required,
        allowed_factors: policy.allowed_mfa_factors.clone(),
        trusted_devices_allowed: policy.trusted_devices_allowed,
    }
}

/// The `amr` values a primary authentication with `method` may claim.
///
/// `mfa`, `hwk` and `swk` are proofs only a passkey ceremony produces (user
/// verification ⇒ `mfa`, SES-21). Any other primary method — a password, an
/// e-mail link or code, or an external identity provider — never proves
/// them here: a provider's MFA is honoured only through
/// `PrimaryAuthentication::provider_asserted_mfa` and
/// `oidc_client.trust_provider_mfa` (SOC-09). Taking them from the caller's
/// list would let a `SessionIssuer` caller skip the MFA requirement, satisfy
/// a phishing-resistant organization policy and mint a session whose `amr`
/// every later organization check trusts.
pub(crate) fn primary_amr(method: LoginMethod, amr: &[AuthMethodRef]) -> Vec<AuthMethodRef> {
    let passkey = method == LoginMethod::Passkey && has_passkey(amr);
    let kept: Vec<AuthMethodRef> = amr
        .iter()
        .copied()
        .filter(|a| {
            passkey
                || !matches!(
                    a,
                    AuthMethodRef::Mfa | AuthMethodRef::Hwk | AuthMethodRef::Swk
                )
        })
        .collect();
    if kept.len() != amr.len() {
        tracing::warn!(
            method = method.as_str(),
            "primary authentication claimed amr values its method cannot prove; dropped"
        );
    }
    kept
}

/// The strictest MFA policy over every active membership of the user.
pub(crate) async fn strictest_membership_policy(
    conn: &mut PgConnection,
    user: authn_core::id::UserId,
) -> Result<Option<OrgMfaPolicy>, AuthError> {
    let policies = authn_org::policies_for_user(conn, user).await?;
    Ok(policies
        .iter()
        .map(|(_, p)| org_mfa_policy(p))
        .reduce(|a, b| a.strictest(&b)))
}

impl SessionService {
    /// The post-primary login pipeline (see the module docs and
    /// [`crate::login::pipeline`]). `client` must carry the login-CSRF proof
    /// for web logins. Risk evaluation (RSK-03) and the new-device alert
    /// (RSK-04) apply to every caller, including federated logins.
    pub async fn complete_login(
        &self,
        ctx: &RequestContext,
        auth: PrimaryAuthentication,
        client: ClientChannel,
    ) -> Result<LoginOutcome, AuthError> {
        let outcome = self
            .run_login_pipeline(ctx, auth, client, &LoginSignals::default())
            .await?;
        Ok(match outcome {
            PipelineOutcome::Established(established) => {
                LoginOutcome::Authenticated(established.to_issued_session())
            }
            PipelineOutcome::Challenge(issued) => {
                LoginOutcome::ChallengeRequired(PendingChallenge {
                    challenge_id: issued.challenge.id,
                    challenge_token: issued.token,
                    expires_at: issued.challenge.expires_at,
                    allowed_factors: issued.challenge.allowed_factors,
                    required_actions: issued.challenge.required_actions,
                })
            }
        })
    }

    /// The `login.succeeded` event of an established session (record it in
    /// the establishing transaction).
    #[must_use]
    pub fn login_succeeded_event(
        &self,
        ctx: &RequestContext,
        established: &EstablishedSession,
        method: LoginMethod,
    ) -> SecurityEvent {
        let session = &established.session;
        let mut event = SecurityEvent::new(SecurityEventKind::LoginSucceeded, self.now())
            .with_context(ctx)
            .with_actor(Actor::User(session.user_id))
            .with_subject(session.user_id)
            .with_resource("session", session.id)
            .with_meta("method", method.as_str())
            .with_meta("client", session.client_kind.as_str())
            .with_meta(
                "amr",
                session.amr.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
            );
        if let Some(org) = session.active_org_id {
            event = event.with_org(org);
        }
        if !established.evicted.is_empty() {
            event = event.with_meta("evicted_sessions", established.evicted.len());
        }
        event
    }

    /// The high-priority `admin.break_glass_used` event of a login that
    /// established a session for a break-glass account (ADM-05, K-05):
    /// `priority: high`, `surface: login`. Record it in the establishing
    /// transaction, next to `login.succeeded`, so alerting sees every use
    /// of the recovery account — not only its admin API requests.
    #[must_use]
    pub fn break_glass_login_event(
        &self,
        ctx: &RequestContext,
        established: &EstablishedSession,
        method: LoginMethod,
    ) -> SecurityEvent {
        let session = &established.session;
        SecurityEvent::new(SecurityEventKind::BreakGlassUsed, self.now())
            .with_context(ctx)
            .with_actor(Actor::User(session.user_id))
            .with_subject(session.user_id)
            .with_resource("session", session.id)
            .with_meta("priority", "high")
            .with_meta("surface", "login")
            .with_meta("method", method.as_str())
            .with_meta("client", session.client_kind.as_str())
    }

    /// Starts an impersonation session (ADM-04). Defence in depth on top of
    /// authn-admin's checks: the actor must be an active platform admin
    /// with a live session of their own (whose `amr` / `acr` / `auth_time`
    /// are inherited), the target an active account that is neither a
    /// platform admin nor a break-glass account nor the admin; the duration
    /// is at most `admin.impersonation_max_ttl` and never extended; a
    /// justification is mandatory. The user is notified and the start is
    /// audited (`admin.impersonation_started`).
    pub async fn impersonate(
        &self,
        ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        admin_session: Option<SessionId>,
    ) -> Result<EstablishedSession, AuthError> {
        let mut tx = self.begin().await?;
        let established = self
            .impersonate_in_tx(
                &mut tx,
                ctx,
                request,
                client,
                admin_session,
                EventId::generate(),
            )
            .await?;
        authn_store::commit(tx).await?;
        metrics::sessions_created("impersonation");
        Ok(established)
    }

    /// [`SessionService::impersonate`] in the caller's transaction, with
    /// the `admin.impersonation_started` event recorded under `event_id`
    /// (`SessionIssuer::start_impersonation_audited`). The caller commits;
    /// the same checks apply, and the target row stays locked until then.
    pub async fn impersonate_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        admin_session: Option<SessionId>,
        event_id: EventId,
    ) -> Result<EstablishedSession, AuthError> {
        let reason = request.reason.trim();
        let reason_chars = reason.chars().count();
        if reason_chars == 0
            || reason_chars > MAX_REASON_CHARS
            || reason.chars().any(char::is_control)
        {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("impersonation reason must be 1-1000 printable characters"));
        }
        if request.ttl.is_zero() || request.ttl > self.settings().impersonation_max_ttl {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("impersonation ttl out of range"));
        }
        if request.admin_user_id == request.target_user_id {
            return Err(AuthError::new(codes::session::IMPERSONATION_NOT_ALLOWED));
        }
        let now = self.now();
        let admin = UserRepository::find_by_id(&mut *conn, request.admin_user_id)
            .await?
            .filter(|a| a.is_platform_admin && a.status == AccountStatus::Active)
            .ok_or_else(|| AuthError::new(codes::common::FORBIDDEN))?;
        let admin_session = sessions::admin_session(&mut *conn, admin.id, admin_session, now)
            .await?
            .ok_or_else(|| {
                AuthError::new(codes::common::FORBIDDEN)
                    .with_context("the admin has no live session")
            })?;
        let target = UserRepository::lock_for_update(conn, request.target_user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if target.is_platform_admin
            || target.is_break_glass
            || target.status != AccountStatus::Active
        {
            return Err(AuthError::new(codes::session::IMPERSONATION_NOT_ALLOWED));
        }
        let absolute = after(now, request.ttl);
        let id = SessionId::generate();
        let web_token = match client {
            ClientKind::Web => Some(OpaqueToken::generate().map_err(AuthError::from)?),
            ClientKind::Native => None,
        };
        let web_hash = web_token.as_ref().map(OpaqueToken::hash);
        let device = DeviceInfo::from_context(ctx);
        let scopes = self.settings().session.default_scopes.clone();
        let record = sessions::insert(
            conn,
            &NewSession {
                id,
                user_id: target.id,
                client_kind: client,
                token_hash: web_hash.as_ref(),
                remember_me: false,
                shared_device: true,
                amr: &admin_session.amr,
                acr: admin_session.acr.as_deref(),
                auth_time: admin_session.auth_time,
                active_org_id: None,
                impersonator_user_id: Some(admin.id),
                impersonation_read_only: Some(request.read_only),
                impersonation_reason: Some(reason),
                device_id: device.device_id.as_deref(),
                device_name: device.device_name.as_deref(),
                user_agent: device.user_agent.as_deref(),
                ip: device.ip,
                created_at: now,
                idle_expires_at: absolute,
                absolute_expires_at: absolute,
                login_method: None,
                scopes: &scopes,
            },
        )
        .await?;
        let credentials = match web_token {
            Some(token) => self.web_credentials(&record, token, None, now)?,
            None => self.impersonation_tokens(conn, &record, now).await?,
        };
        let mut event = SecurityEvent::new(SecurityEventKind::ImpersonationStarted, now)
            .with_context(ctx)
            .with_actor(Actor::User(admin.id))
            .with_subject(target.id)
            .with_resource("session", record.id)
            .with_meta("read_only", request.read_only)
            .with_meta("ttl_seconds", request.ttl.as_secs())
            .with_meta("client", client.as_str());
        event.id = event_id;
        event.impersonator = Some(admin.id);
        self.deps().audit.record_in_tx(conn, event).await?;
        if let Some(email) = target
            .email
            .as_deref()
            .and_then(|e| EmailAddress::parse(e).ok())
        {
            // Through the transaction's connection (K-58 pool pattern: the
            // target's row is locked; never wait for a second connection).
            let profile = self
                .deps()
                .accounts
                .profile_of_in(&mut *conn, target.id)
                .await?;
            self.deps()
                .notifier
                .notify_in_tx(
                    conn,
                    Notification {
                        recipient: Recipient {
                            email,
                            user_id: Some(target.id),
                            display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
                        },
                        locale: profile.map(|p| p.locale).unwrap_or_default(),
                        kind: NotificationKind::ImpersonationStarted {
                            at: now,
                            expires_at: absolute,
                        },
                    },
                )
                .await?;
        }
        Ok(EstablishedSession {
            session: record,
            credentials,
            evicted: Vec::new(),
        })
    }

    /// Native impersonation credentials: a refresh family that ends with
    /// the impersonation, access tokens with the `act` claim.
    async fn impersonation_tokens(
        &self,
        conn: &mut PgConnection,
        record: &SessionRecord,
        now: time::OffsetDateTime,
    ) -> Result<IssuedCredentials, AuthError> {
        let token = OpaqueToken::generate().map_err(AuthError::from)?;
        let token_id = uuid::Uuid::now_v7();
        crate::store::refresh::insert(
            conn,
            &NewRefreshToken {
                id: authn_core::id::RefreshTokenId::generate(),
                session_id: record.id,
                token_hash: &token.hash(),
                parent_id: None,
                generation: 0,
                created_at: now,
                idle_expires_at: record.absolute_expires_at,
                absolute_expires_at: record.absolute_expires_at,
                access_token_id: token_id,
            },
        )
        .await?;
        let (access_token, access_token_expires_at) =
            self.issue_access_token(conn, record, token_id, now).await?;
        Ok(IssuedCredentials::Native {
            access_token,
            access_token_expires_at,
            refresh_token: token.into_sensitive(),
            refresh_token_expires_at: record.absolute_expires_at,
        })
    }
}

#[async_trait]
impl SessionIssuer for SessionService {
    async fn complete_primary_authentication(
        &self,
        ctx: &RequestContext,
        auth: PrimaryAuthentication,
    ) -> Result<LoginOutcome, AuthError> {
        // Federated callbacks are protected against login CSRF by the
        // server-side OAuth `state` bound to the browser (SOC-02).
        let client = match auth.client {
            ClientKind::Web => ClientChannel::Web(LoginCsrfVerified::federated()),
            ClientKind::Native => ClientChannel::Native,
        };
        self.complete_login(ctx, auth, client).await
    }

    fn login_response(&self, outcome: LoginOutcome, return_to: Option<&str>) -> Response {
        let now = self.now();
        match outcome {
            LoginOutcome::Authenticated(session) => {
                self.issued_session_response(session, return_to)
            }
            LoginOutcome::ChallengeRequired(challenge) => {
                let web = return_to.is_some();
                let max_age = remaining(now, challenge.expires_at);
                let body = ChallengeBody {
                    status: "challenge_required",
                    challenge_id: challenge.challenge_id,
                    challenge_token: (!web).then(|| challenge.challenge_token.clone()),
                    expires_at: challenge.expires_at,
                    allowed_factors: challenge.allowed_factors,
                    required_actions: challenge.required_actions,
                };
                let mut response = match return_to {
                    Some(location) => crate::response::redirect_with_session(
                        location,
                        cookies::challenge_cookie(challenge.challenge_token.expose(), max_age),
                    ),
                    None => (StatusCode::OK, axum::Json(body)).into_response(),
                };
                response.headers_mut().insert(
                    axum::http::header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("no-store"),
                );
                response
            }
        }
    }

    async fn start_impersonation(
        &self,
        ctx: &RequestContext,
        request: ImpersonationRequest,
    ) -> Result<IssuedSession, AuthError> {
        self.start_impersonation_with(ctx, request, ClientKind::Web, None)
            .await
    }

    async fn start_impersonation_with(
        &self,
        ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        admin_session: Option<SessionId>,
    ) -> Result<IssuedSession, AuthError> {
        self.impersonate(ctx, request, client, admin_session)
            .await
            .map(|e| e.to_issued_session())
    }

    async fn start_impersonation_audited(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        admin_session: Option<SessionId>,
        event_id: EventId,
    ) -> Result<IssuedSession, AuthError> {
        let established = self
            .impersonate_in_tx(conn, ctx, request, client, admin_session, event_id)
            .await?;
        // Counted when issued; the caller's commit is not observable here.
        metrics::sessions_created("impersonation");
        Ok(established.to_issued_session())
    }
}

impl SessionService {
    /// Renders an [`IssuedSession`] of the port.
    fn issued_session_response(&self, session: IssuedSession, return_to: Option<&str>) -> Response {
        let now = self.now();
        let persistent_for =
            (!session.browser_session_only).then(|| remaining(now, session.absolute_expires_at));
        let mut body = CredentialsBody {
            status: "authenticated",
            session_id: session.session_id,
            user_id: session.user_id,
            client_kind: session.client,
            amr: Vec::new(),
            auth_time: now,
            expires_at: session.absolute_expires_at,
            active_org_id: None,
            csrf_token: None,
            access_token: None,
            token_type: None,
            expires_in: None,
            refresh_token: None,
            refresh_token_expires_at: None,
        };
        let mut cookie = None;
        match session.client {
            ClientKind::Web => {
                if let Some(token) = &session.session_token {
                    if let Ok(parsed) = OpaqueToken::parse(token.expose()) {
                        body.csrf_token = self
                            .csrf()
                            .session_token(session.session_id, &parsed.hash())
                            .ok();
                    }
                    cookie = Some(cookies::session_cookie(token.expose(), persistent_for));
                }
            }
            ClientKind::Native => {
                body.access_token.clone_from(&session.access_token);
                body.token_type = Some("Bearer");
                body.expires_in = session
                    .access_token_expires_at
                    .map(|exp| remaining(now, exp).as_secs());
                body.refresh_token.clone_from(&session.refresh_token);
                body.refresh_token_expires_at = Some(session.idle_expires_at);
            }
        }
        let mut response = match (return_to, cookie) {
            (Some(location), Some(cookie)) => {
                crate::response::redirect_with_session(location, cookie)
            }
            (_, cookie) => {
                let mut response = (StatusCode::OK, axum::Json(body)).into_response();
                if let Some(cookie) = cookie {
                    response.headers_mut().append(SET_COOKIE, cookie);
                    response
                        .headers_mut()
                        .append(SET_COOKIE, cookies::clear_pre_session_cookie());
                }
                response
            }
        };
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response
    }
}
