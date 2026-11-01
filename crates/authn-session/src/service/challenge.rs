//! Pending login state (SES-02, SES-22): the `auth_challenges` API used by
//! the login flows.
//!
//! A challenge is created after a successful primary authentication when
//! more steps are needed (second factor, required actions). The client
//! receives an opaque 256-bit token (only its SHA-256 is stored) and
//! presents it with each step:
//!
//! * [`SessionService::open_challenge`] row-locks the challenge in the
//!   caller's transaction and checks it is unconsumed, unexpired, has
//!   attempts left and is presented by the same kind of client (and the
//!   same device, when it was created with a device id). Every failure is
//!   the uniform `challenge_invalid`.
//! * Wrong factor proofs are counted with
//!   [`SessionService::record_challenge_failure`] in its **own**
//!   transaction (so the count survives the caller's rollback); the attempt
//!   that reaches `max_attempts` burns the challenge.
//! * [`SessionService::update_challenge`] records progress (verified
//!   factor, completed action) and [`SessionService::consume_challenge`]
//!   ends it exactly once, in the transaction that establishes the session.

use authn_core::domain::{AuthMethodRef, ClientKind, FactorKind, LoginMethod};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{ChallengeId, OrgId, SessionId, UserId};
use authn_core::ports::{RequiredAction, RiskLevel};
use authn_core::secret::SensitiveString;
use authn_crypto::token::OpaqueToken;
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::{SessionService, after};
use crate::store::challenges::{self, ChallengeRow, NewChallengeRow};

/// What a challenge is for (`auth_challenges.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeKind {
    /// A pending login (second factor, required actions).
    Login,
    /// A step-up bound to an existing session.
    StepUp,
    /// A passwordless login in progress (e-mail code, SES-19).
    Passwordless,
}

impl ChallengeKind {
    /// The stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::StepUp => "step_up",
            Self::Passwordless => "passwordless",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "login" => Some(Self::Login),
            "step_up" => Some(Self::StepUp),
            "passwordless" => Some(Self::Passwordless),
            _ => None,
        }
    }
}

/// Input of [`SessionService::create_challenge`].
#[derive(Debug, Clone, PartialEq)]
pub struct NewChallenge {
    /// Purpose.
    pub kind: ChallengeKind,
    /// The user who passed the primary authentication.
    pub user_id: UserId,
    /// Client the challenge is bound to.
    pub client_kind: ClientKind,
    /// Primary login method.
    pub primary_method: Option<LoginMethod>,
    /// Methods proven so far.
    pub amr: Vec<AuthMethodRef>,
    /// Time of the primary authentication.
    pub first_factor_at: Option<OffsetDateTime>,
    /// Second factors the user may use now (already filtered by policy;
    /// `verify_factor` must only be called for these, contracts §15.7).
    pub allowed_factors: Vec<FactorKind>,
    /// Steps to complete before a session is issued.
    pub required_actions: Vec<RequiredAction>,
    /// "Remember me".
    pub remember_me: bool,
    /// "Not my device".
    pub shared_device: bool,
    /// Organization requested for the session.
    pub requested_org: Option<OrgId>,
    /// Risk level of the login (RSK-03).
    pub risk_level: Option<RiskLevel>,
    /// Step-up challenges: the session they elevate.
    pub session_id: Option<SessionId>,
    /// Extra non-secret state (JSON object).
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

/// A created challenge and its token (returned to the client once).
#[derive(Clone, PartialEq)]
pub struct IssuedChallenge {
    /// The challenge.
    pub challenge: ChallengeState,
    /// Opaque token; only its hash is stored.
    pub token: SensitiveString,
}

impl std::fmt::Debug for IssuedChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedChallenge")
            .field("challenge", &self.challenge)
            .finish_non_exhaustive()
    }
}

/// An open challenge.
#[derive(Debug, Clone, PartialEq)]
pub struct ChallengeState {
    /// Id.
    pub id: ChallengeId,
    /// Purpose.
    pub kind: ChallengeKind,
    /// User.
    pub user_id: UserId,
    /// Step-up: the session.
    pub session_id: Option<SessionId>,
    /// Client kind it is bound to.
    pub client_kind: ClientKind,
    /// Primary login method.
    pub primary_method: Option<LoginMethod>,
    /// Methods proven so far.
    pub amr: Vec<AuthMethodRef>,
    /// Time of the primary authentication.
    pub first_factor_at: Option<OffsetDateTime>,
    /// Usable second factors.
    pub allowed_factors: Vec<FactorKind>,
    /// Outstanding steps.
    pub required_actions: Vec<RequiredAction>,
    /// "Remember me".
    pub remember_me: bool,
    /// "Not my device".
    pub shared_device: bool,
    /// Requested organization.
    pub requested_org: Option<OrgId>,
    /// Risk level.
    pub risk_level: Option<RiskLevel>,
    /// Failed attempts so far.
    pub attempts: u32,
    /// Attempt limit.
    pub max_attempts: u32,
    /// Extra state.
    pub metadata: serde_json::Map<String, serde_json::Value>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

impl ChallengeState {
    fn from_row(row: ChallengeRow) -> Result<Self, AuthError> {
        let kind = ChallengeKind::parse(&row.kind)
            .ok_or_else(|| AuthError::internal("unknown challenge kind"))?;
        let metadata = match row.metadata {
            serde_json::Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };
        Ok(Self {
            id: row.id,
            kind,
            user_id: row.user_id,
            session_id: row.session_id,
            client_kind: row.client_kind,
            primary_method: row.primary_method,
            amr: row.amr,
            first_factor_at: row.first_factor_at,
            allowed_factors: row.allowed_factors,
            required_actions: row.required_actions,
            remember_me: row.remember_me,
            shared_device: row.shared_device,
            requested_org: row.requested_org_id,
            risk_level: row.risk_level,
            attempts: u32::try_from(row.attempts).unwrap_or(0),
            max_attempts: u32::try_from(row.max_attempts).unwrap_or(0),
            metadata,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }

    /// Whether `factor` may be verified for this challenge.
    #[must_use]
    pub fn allows_factor(&self, factor: FactorKind) -> bool {
        self.allowed_factors.contains(&factor)
    }
}

/// Progress written by [`SessionService::update_challenge`].
#[derive(Debug, Clone, PartialEq)]
pub struct ChallengeProgress {
    /// Methods proven so far.
    pub amr: Vec<AuthMethodRef>,
    /// Usable second factors.
    pub allowed_factors: Vec<FactorKind>,
    /// Outstanding steps.
    pub required_actions: Vec<RequiredAction>,
    /// Extra state.
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

/// Longest wait for a challenge row lock in
/// [`SessionService::record_challenge_failure`].
pub const CHALLENGE_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const CHALLENGE_LOCK_TIMEOUT_SQL: &str = "SET LOCAL lock_timeout = '5s'";

fn invalid(context: &'static str) -> AuthError {
    AuthError::new(codes::session::CHALLENGE_INVALID).with_context(context)
}

impl SessionService {
    /// Creates a challenge in the caller's transaction (lifetime
    /// `session.mfa_challenge_ttl`, `session.challenge_max_attempts`
    /// attempts), bound to the client kind and the device of `ctx`.
    pub async fn create_challenge(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        new: NewChallenge,
    ) -> Result<IssuedChallenge, AuthError> {
        if new.kind == ChallengeKind::StepUp && new.session_id.is_none() {
            return Err(AuthError::internal("a step-up challenge needs a session"));
        }
        let now = self.now();
        let settings = &self.settings().session;
        let token = OpaqueToken::generate().map_err(AuthError::from)?;
        let id = ChallengeId::generate();
        let expires_at = after(now, settings.mfa_challenge_ttl);
        let max_attempts = i32::try_from(settings.challenge_max_attempts).unwrap_or(5);
        let metadata = serde_json::Value::Object(new.metadata.clone());
        challenges::insert(
            conn,
            &NewChallengeRow {
                id,
                kind: new.kind.as_str(),
                user_id: new.user_id,
                token_hash: &token.hash(),
                session_id: new.session_id,
                client_kind: new.client_kind,
                amr: &new.amr,
                first_factor_at: new.first_factor_at,
                allowed_factors: &new.allowed_factors,
                required_actions: &new.required_actions,
                remember_me: new.remember_me,
                shared_device: new.shared_device,
                requested_org_id: new.requested_org,
                risk_level: new.risk_level,
                max_attempts,
                ip: Some(ctx.client_ip),
                user_agent: ctx.user_agent.as_deref(),
                device_id: ctx.device_id.as_deref(),
                metadata: &metadata,
                created_at: now,
                expires_at,
                primary_method: new.primary_method,
            },
        )
        .await?;
        Ok(IssuedChallenge {
            challenge: ChallengeState {
                id,
                kind: new.kind,
                user_id: new.user_id,
                session_id: new.session_id,
                client_kind: new.client_kind,
                primary_method: new.primary_method,
                amr: new.amr,
                first_factor_at: new.first_factor_at,
                allowed_factors: new.allowed_factors,
                required_actions: new.required_actions,
                remember_me: new.remember_me,
                shared_device: new.shared_device,
                requested_org: new.requested_org,
                risk_level: new.risk_level,
                attempts: 0,
                max_attempts: u32::try_from(max_attempts).unwrap_or(0),
                metadata: new.metadata,
                created_at: now,
                expires_at,
            },
            token: token.into_sensitive(),
        })
    }

    /// Row-locks the open challenge of `token` in the caller's transaction.
    /// Fails with `challenge_invalid` unless it is unconsumed, unexpired,
    /// has attempts left, is of `kind`, and is presented by the same client
    /// kind and device it was created for.
    pub async fn open_challenge(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        token: &str,
        kind: ChallengeKind,
        client_kind: ClientKind,
    ) -> Result<ChallengeState, AuthError> {
        let token = OpaqueToken::parse(token).map_err(|_| invalid("malformed token"))?;
        let row = challenges::lock_open(conn, &token.hash(), self.now())
            .await?
            .ok_or_else(|| invalid("unknown, used, expired or exhausted"))?;
        if let Some(bound) = &row.device_id
            && ctx.device_id.as_deref() != Some(bound.as_str())
        {
            return Err(invalid("other device"));
        }
        let state = ChallengeState::from_row(row)?;
        if state.kind != kind || state.client_kind != client_kind {
            return Err(invalid("other kind or client"));
        }
        Ok(state)
    }

    /// Counts a failed attempt in its own transaction; the attempt that
    /// reaches the limit burns the challenge. Returns the attempts left
    /// (`0` = burnt).
    ///
    /// Call it only **after** the transaction of
    /// [`Self::open_challenge`] ended (roll it back first): that
    /// transaction holds the challenge's row lock, which this update needs.
    /// A caller that still holds it gets an error after
    /// [`CHALLENGE_LOCK_TIMEOUT`] instead of blocking a pool connection
    /// forever — and must then treat the attempt as failed.
    pub async fn record_challenge_failure(&self, id: ChallengeId) -> Result<u32, AuthError> {
        let mut tx = self.begin().await?;
        sqlx::query(CHALLENGE_LOCK_TIMEOUT_SQL)
            .execute(&mut *tx)
            .await?;
        let counted = challenges::register_failure(&mut tx, id, self.now()).await?;
        authn_store::commit(tx).await?;
        Ok(counted.map_or(0, |(attempts, max)| {
            u32::try_from(max.saturating_sub(attempts)).unwrap_or(0)
        }))
    }

    /// Records progress of an open challenge (caller's transaction).
    pub async fn update_challenge(
        &self,
        conn: &mut PgConnection,
        id: ChallengeId,
        progress: &ChallengeProgress,
    ) -> Result<(), AuthError> {
        let metadata = serde_json::Value::Object(progress.metadata.clone());
        if challenges::update_progress(
            conn,
            id,
            &progress.amr,
            &progress.allowed_factors,
            &progress.required_actions,
            &metadata,
        )
        .await?
        {
            Ok(())
        } else {
            Err(invalid("challenge closed"))
        }
    }

    /// Consumes an open challenge exactly once (caller's transaction).
    pub async fn consume_challenge(
        &self,
        conn: &mut PgConnection,
        id: ChallengeId,
    ) -> Result<(), AuthError> {
        if challenges::consume(conn, id, self.now()).await? {
            Ok(())
        } else {
            Err(invalid("already consumed"))
        }
    }
}
