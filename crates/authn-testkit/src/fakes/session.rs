use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use authn_core::domain::ClientKind;
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, SessionId, UserId};
use authn_core::ports::{
    Clock, ImpersonationRequest, IssuedSession, LoginOutcome, PrimaryAuthentication,
    RevocationReason, RevokeOptions, SessionIssuer, SessionRevoker,
};
use authn_core::secret::SensitiveString;
use axum::response::{IntoResponse, Response};
use sqlx::PgConnection;

use super::lock;

/// One recorded `SessionRevoker` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationCall {
    /// `revoke_session`.
    Session(SessionId, RevocationReason),
    /// `revoke_all_for_user`.
    AllForUser(UserId, RevocationReason, RevokeOptions),
    /// `revoke_all_except`.
    AllExcept(UserId, SessionId, RevocationReason, RevokeOptions),
    /// `revoke_for_user_in_org`.
    UserInOrg(UserId, OrgId, RevocationReason),
    /// `revoke_all_for_org`.
    AllForOrg(OrgId, RevocationReason),
    /// `revoke_everything`.
    Everything(RevocationReason),
}

/// Records revocation requests; reports `revoked_count` (default 1).
#[derive(Debug)]
pub struct RecordingSessionRevoker {
    calls: Mutex<Vec<RevocationCall>>,
    revoked_count: Mutex<u64>,
}

impl Default for RecordingSessionRevoker {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            revoked_count: Mutex::new(1),
        }
    }
}

impl RecordingSessionRevoker {
    /// Recorded calls.
    #[must_use]
    pub fn calls(&self) -> Vec<RevocationCall> {
        lock(&self.calls).clone()
    }

    /// Sets the count returned by bulk operations.
    pub fn set_revoked_count(&self, n: u64) {
        *lock(&self.revoked_count) = n;
    }

    fn push(&self, call: RevocationCall) -> u64 {
        lock(&self.calls).push(call);
        *lock(&self.revoked_count)
    }
}

#[async_trait]
impl SessionRevoker for RecordingSessionRevoker {
    async fn revoke_session(
        &self,
        _c: &mut PgConnection,
        s: SessionId,
        r: RevocationReason,
    ) -> Result<bool, AuthError> {
        Ok(self.push(RevocationCall::Session(s, r)) > 0)
    }

    async fn revoke_all_for_user(
        &self,
        _c: &mut PgConnection,
        u: UserId,
        r: RevocationReason,
        o: RevokeOptions,
    ) -> Result<u64, AuthError> {
        Ok(self.push(RevocationCall::AllForUser(u, r, o)))
    }

    async fn revoke_all_except(
        &self,
        _c: &mut PgConnection,
        u: UserId,
        keep: SessionId,
        r: RevocationReason,
        o: RevokeOptions,
    ) -> Result<u64, AuthError> {
        Ok(self.push(RevocationCall::AllExcept(u, keep, r, o)))
    }

    async fn revoke_for_user_in_org(
        &self,
        _c: &mut PgConnection,
        u: UserId,
        org: OrgId,
        r: RevocationReason,
    ) -> Result<u64, AuthError> {
        Ok(self.push(RevocationCall::UserInOrg(u, org, r)))
    }

    async fn revoke_all_for_org(
        &self,
        _c: &mut PgConnection,
        org: OrgId,
        r: RevocationReason,
    ) -> Result<u64, AuthError> {
        Ok(self.push(RevocationCall::AllForOrg(org, r)))
    }

    async fn revoke_everything(
        &self,
        _c: &mut PgConnection,
        r: RevocationReason,
    ) -> Result<u64, AuthError> {
        Ok(self.push(RevocationCall::Everything(r)))
    }
}

/// Issues fake sessions immediately (no MFA, no risk) and records requests.
/// `login_response` renders `{"session_id": …, "user_id": …}`.
pub struct FakeSessionIssuer {
    clock: Arc<dyn Clock>,
    logins: Mutex<Vec<PrimaryAuthentication>>,
    impersonations: Mutex<Vec<ImpersonationRequest>>,
    next_outcome: Mutex<Option<LoginOutcome>>,
}

impl std::fmt::Debug for FakeSessionIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeSessionIssuer").finish_non_exhaustive()
    }
}

impl FakeSessionIssuer {
    /// A fake issuer using `clock` for expiry times.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            logins: Mutex::new(Vec::new()),
            impersonations: Mutex::new(Vec::new()),
            next_outcome: Mutex::new(None),
        }
    }

    /// Primary authentications received.
    #[must_use]
    pub fn logins(&self) -> Vec<PrimaryAuthentication> {
        lock(&self.logins).clone()
    }

    /// Impersonation requests received.
    #[must_use]
    pub fn impersonations(&self) -> Vec<ImpersonationRequest> {
        lock(&self.impersonations).clone()
    }

    /// Makes the next `complete_primary_authentication` return `outcome`.
    pub fn set_next_outcome(&self, outcome: LoginOutcome) {
        *lock(&self.next_outcome) = Some(outcome);
    }

    fn issue(&self, user_id: UserId, client: ClientKind) -> IssuedSession {
        let now = self.clock.now();
        let session_id = SessionId::generate();
        IssuedSession {
            session_id,
            user_id,
            client,
            session_token: (client == ClientKind::Web)
                .then(|| SensitiveString::new(format!("fake-session-{session_id}"))),
            access_token: (client == ClientKind::Native)
                .then(|| SensitiveString::new(format!("fake-access-{session_id}"))),
            access_token_expires_at: (client == ClientKind::Native)
                .then(|| now + time::Duration::minutes(10)),
            refresh_token: (client == ClientKind::Native)
                .then(|| SensitiveString::new(format!("fake-refresh-{session_id}"))),
            idle_expires_at: now + time::Duration::hours(2),
            absolute_expires_at: now + time::Duration::hours(12),
            browser_session_only: false,
        }
    }
}

#[async_trait]
impl SessionIssuer for FakeSessionIssuer {
    async fn complete_primary_authentication(
        &self,
        _ctx: &RequestContext,
        auth: PrimaryAuthentication,
    ) -> Result<LoginOutcome, AuthError> {
        let (user, client) = (auth.user_id, auth.client);
        lock(&self.logins).push(auth);
        if let Some(outcome) = lock(&self.next_outcome).take() {
            return Ok(outcome);
        }
        Ok(LoginOutcome::Authenticated(self.issue(user, client)))
    }

    fn login_response(&self, outcome: LoginOutcome, _return_to: Option<&str>) -> Response {
        let body = match outcome {
            LoginOutcome::Authenticated(s) => serde_json::json!({
                "status": "authenticated",
                "session_id": s.session_id,
                "user_id": s.user_id,
            }),
            LoginOutcome::ChallengeRequired(c) => serde_json::json!({
                "status": "challenge_required",
                "challenge_id": c.challenge_id,
                "allowed_factors": c.allowed_factors,
                "required_actions": c.required_actions,
            }),
        };
        axum::Json(body).into_response()
    }

    async fn start_impersonation(
        &self,
        _ctx: &RequestContext,
        request: ImpersonationRequest,
    ) -> Result<IssuedSession, AuthError> {
        let user = request.target_user_id;
        lock(&self.impersonations).push(request);
        Ok(self.issue(user, ClientKind::Web))
    }

    /// Records the request like [`SessionIssuer::start_impersonation`]
    /// (nothing is written to `conn`: the fake keeps no database state).
    async fn start_impersonation_audited(
        &self,
        _conn: &mut sqlx::PgConnection,
        _ctx: &RequestContext,
        request: ImpersonationRequest,
        client: ClientKind,
        _admin_session: Option<authn_core::id::SessionId>,
        _event_id: authn_core::id::EventId,
    ) -> Result<IssuedSession, AuthError> {
        let user = request.target_user_id;
        lock(&self.impersonations).push(request);
        Ok(self.issue(user, client))
    }
}
