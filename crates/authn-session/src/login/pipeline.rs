//! The post-primary login pipeline shared by every login method (SES-01,
//! SES-02, SES-21, SES-22, RSK-03, RSK-04, MFA-09).
//!
//! After a primary authentication (password, passkey, magic link, e-mail
//! code, identity provider) the pipeline decides between a full session
//! and a challenge, in this order:
//!
//! 1. the account must allow a login (`AccountService::assess_login`);
//!    status is revealed only now, after a correct primary credential;
//! 2. a requested organization must admit the user, the client IP and the
//!    login method;
//! 3. MFA requirement (MFA-08, organization policy, platform admin);
//! 4. risk (RSK-03): `high` blocks the login and notifies the user,
//!    `medium` forces the second factor (or an e-mail confirmation when no
//!    factor is enrolled);
//! 5. a valid trusted-device token (MFA-09) satisfies a *policy* MFA
//!    requirement — never one forced by risk, never an enrollment;
//! 6. no outstanding step → session; otherwise a challenge.
//!
//! After a session was established the device and network are recorded
//! and a new-device notification with a "this wasn't me" link is queued
//! (RSK-04, [`SessionService::after_login`]).

use authn_core::domain::{
    AccountStatus, AuthMethodRef, ClientKind, EmailAddress, FactorKind, LoginMethod,
};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, PrimaryAuthentication, Recipient, RequiredAction, RiskAssessment, RiskInput, RiskLevel,
    SecurityEvent, SecurityEventKind,
};
use authn_core::secret::SensitiveString;
use authn_mfa::MfaRequirement;
use authn_protect::RiskResponse;
use authn_store::{UserRecord, UserRepository};

use crate::model::{DeviceInfo, EstablishedSession};
use crate::service::{
    ChallengeKind, ClientChannel, EstablishSession, IssuedChallenge, NewChallenge, SessionService,
    has_passkey, normalize_amr, org_mfa_policy, primary_amr, strictest_membership_policy,
};

/// Challenge metadata key: the outstanding `verify_mfa` step is an e-mail
/// confirmation demanded by risk (RSK-03), not an enrolled factor.
pub(crate) const EMAIL_CONFIRMATION: &str = "email_confirmation";
/// Challenge metadata key: the factors the `enroll_mfa` step may enroll,
/// while a `verify_mfa` step that must come first (an existing factor
/// outside the policy, or an e-mail confirmation) uses `allowed_factors`.
pub(crate) const ENROLL_FACTORS: &str = "enroll_factors";

/// Request facts besides the primary authentication.
#[derive(Clone, Default)]
pub struct LoginSignals {
    /// The trusted-device token presented with the request (MFA-09:
    /// `__Host-authn_trusted_device` cookie or `x-trusted-device` header).
    pub trusted_device_token: Option<SensitiveString>,
    /// Steps the primary method itself demands, done after the second
    /// factor (e.g. `change_password` for `must_change_password`, PWD-12).
    pub extra_required_actions: Vec<RequiredAction>,
    /// The primary credential alone must not complete the login: unless a
    /// second factor is verified, the mailbox owner confirms it with an
    /// e-mailed code first (a password whose change is forced — PWD-12,
    /// RSK-04 "this wasn't me" — may be known to someone else).
    pub require_mailbox_proof: bool,
}

impl std::fmt::Debug for LoginSignals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginSignals")
            .field("trusted_device_token", &self.trusted_device_token.is_some())
            .field("extra_required_actions", &self.extra_required_actions)
            .field("require_mailbox_proof", &self.require_mailbox_proof)
            .finish()
    }
}

/// The decision of [`SessionService::plan_login`], applied by
/// [`SessionService::finish_login_in`].
#[derive(Debug)]
pub(crate) struct LoginPlan {
    /// The account as the decision saw it.
    user: UserRecord,
    org: Option<crate::service::VerifiedOrg>,
    amr: Vec<AuthMethodRef>,
    required_actions: Vec<RequiredAction>,
    allowed_factors: Vec<FactorKind>,
    metadata: serde_json::Map<String, serde_json::Value>,
    risk_level: RiskLevel,
}

impl LoginPlan {
    /// Whether the locked account is still what the decision was based on
    /// (a suspension, lock, verification or admin change in between
    /// invalidates it).
    fn still_matches(&self, locked: &UserRecord) -> bool {
        locked.status == self.user.status
            && locked.is_platform_admin == self.user.is_platform_admin
            && locked.locked_until == self.user.locked_until
            && locked.email_verified_at.is_some() == self.user.email_verified_at.is_some()
    }
}

/// What the pipeline produced.
#[derive(Debug)]
pub enum PipelineOutcome {
    /// A session (every step done).
    Established(Box<EstablishedSession>),
    /// More steps are needed.
    Challenge(Box<IssuedChallenge>),
}

/// The notification recipient of a user (`None` without a usable address).
pub(crate) async fn recipient_of(
    service: &SessionService,
    user: &UserRecord,
) -> Result<Option<(Recipient, authn_core::domain::Locale)>, AuthError> {
    let Some(email) = user
        .email
        .as_deref()
        .and_then(|e| EmailAddress::parse(e).ok())
    else {
        return Ok(None);
    };
    let profile = service.deps().accounts.profile_of(user.id).await?;
    Ok(Some((
        Recipient {
            email,
            user_id: Some(user.id),
            display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
        },
        profile.map(|p| p.locale).unwrap_or_default(),
    )))
}

impl SessionService {
    /// Evaluates the login risk (RSK-01, RSK-02); `low` when disabled.
    pub(crate) async fn assess_risk(
        &self,
        ctx: &RequestContext,
        user: UserId,
        method: LoginMethod,
    ) -> Result<(RiskInput, RiskAssessment), AuthError> {
        let input = RiskInput::from_context(ctx, Some(user), method, self.now());
        if !self.settings().risk.enabled {
            return Ok((input, RiskAssessment::low()));
        }
        let assessment = self.deps().risk.evaluate(&input).await?;
        Ok((input, assessment))
    }

    /// Runs the pipeline (see the module docs). `client` must carry the
    /// login-CSRF proof for web logins.
    pub async fn run_login_pipeline(
        &self,
        ctx: &RequestContext,
        auth: PrimaryAuthentication,
        client: ClientChannel,
        signals: &LoginSignals,
    ) -> Result<PipelineOutcome, AuthError> {
        let plan = self.plan_login(ctx, &auth, client, signals, false).await?;
        self.warm_credentials(client.kind()).await?;
        let tx = self.begin().await?;
        self.finish_login_in(tx, ctx, auth, client, plan).await
    }

    /// Loads the signing key before a transaction issues native tokens, so
    /// the transaction never waits for a second pool connection.
    pub(crate) async fn warm_credentials(&self, client: ClientKind) -> Result<(), AuthError> {
        if client == ClientKind::Native {
            self.key_cache().signer().await?;
        }
        Ok(())
    }

    /// The decision part of the pipeline. Runs **without** holding a
    /// connection across the calls into other services (account, MFA,
    /// risk): a login never holds one pooled connection while waiting for
    /// another, so concurrent logins cannot exhaust the pool and stall each
    /// other (OPS, DoS). `mailbox_proven`: the primary authentication is a
    /// mailbox proof that verifies an unverified address in the finishing
    /// transaction (magic link, e-mail code).
    pub(crate) async fn plan_login(
        &self,
        ctx: &RequestContext,
        auth: &PrimaryAuthentication,
        client: ClientChannel,
        signals: &LoginSignals,
        mailbox_proven: bool,
    ) -> Result<LoginPlan, AuthError> {
        if client.kind() != auth.client {
            return Err(AuthError::internal(
                "client channel does not match the login",
            ));
        }
        let now = self.now();
        let mut user = UserRepository::find_by_id(self.pool(), auth.user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::session::INVALID_CREDENTIALS))?;
        if mailbox_proven && user.email_verified_at.is_none() {
            // As the account will be once the proof commits (ADR 0002).
            user.email_verified_at = Some(now);
            if user.status == AccountStatus::PendingVerification {
                user.status = AccountStatus::Active;
            }
        }
        let mut required_actions = match self.deps().accounts.assess_login(&user).await? {
            authn_account::LoginAssessment::Allowed {
                required_actions, ..
            } => required_actions,
            authn_account::LoginAssessment::Denied(reason) => return Err(reason.into_error(now)),
        };
        let (org, mfa_policy) = {
            let mut conn = self.pool().acquire().await?;
            let org = match auth.requested_org {
                Some(org) => Some(
                    self.verify_login_org(&mut conn, ctx, user.id, org, auth.method)
                        .await?,
                ),
                None => None,
            };
            let mfa_policy = match &org {
                Some(org) => Some(org_mfa_policy(org.policy())),
                None => strictest_membership_policy(&mut conn, user.id).await?,
            };
            (org, mfa_policy)
        };
        let trusted_devices_allowed = mfa_policy
            .as_ref()
            .is_none_or(|p| p.trusted_devices_allowed);
        let phishing_resistant = user.is_platform_admin
            || mfa_policy
                .as_ref()
                .is_some_and(|p| p.phishing_resistant_required);
        let mut amr = normalize_amr(&primary_amr(auth.method, &auth.amr))?;
        let primary_is_mfa =
            amr.contains(&AuthMethodRef::Mfa) && (!phishing_resistant || has_passkey(&amr));
        let provider_mfa =
            auth.provider_asserted_mfa && self.settings().trust_provider_mfa && !phishing_resistant;
        let requirement = self
            .deps()
            .mfa
            .evaluate_for_user(user.id, mfa_policy.clone(), false)
            .await?;

        // Factors the user already has although the policy does not
        // permit them: an enrollment demanded by the policy must first be
        // authorized by one of them, so a password alone never adds a
        // factor to an account protected by another one (SES-22).
        let existing_factors = match &requirement {
            MfaRequirement::EnrollmentRequired { .. } => {
                let input = self.deps().mfa.policy_input(user.id, None, false).await?;
                let usable: Vec<FactorKind> = input
                    .enrolled_factors
                    .iter()
                    .copied()
                    .filter(|k| {
                        input
                            .available_factors
                            .as_ref()
                            .is_none_or(|list| list.contains(k))
                    })
                    .collect();
                if usable.iter().any(|k| *k != FactorKind::RecoveryCode) {
                    usable
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        };

        // RSK-03. A passkey with user verification already proves
        // possession + inherence; novelty does not make it weaker.
        let (risk_input, assessment) = self.assess_risk(ctx, user.id, auth.method).await?;
        let mfa_enrolled =
            matches!(requirement, MfaRequirement::Required { .. }) || !existing_factors.is_empty();
        let mut reaction =
            authn_protect::risk::decide(&self.settings().risk, &assessment, mfa_enrolled);
        if primary_is_mfa && reaction != RiskResponse::Block {
            reaction = RiskResponse::Allow;
        }
        if reaction == RiskResponse::RequireEmailConfirmation
            && matches!(auth.method, LoginMethod::MagicLink | LoginMethod::EmailCode)
        {
            // The login itself was a mailbox proof.
            reaction = RiskResponse::Allow;
        }
        if reaction == RiskResponse::Block {
            crate::metrics::login("blocked");
            return Err(self
                .block_risky_login(ctx, &user, &risk_input, &assessment)
                .await);
        }

        let mut allowed_factors: Vec<FactorKind> = Vec::new();
        let mut metadata = serde_json::Map::new();
        let risk_forces_mfa = reaction == RiskResponse::RequireMfa;
        let needs_mailbox =
            reaction == RiskResponse::RequireEmailConfirmation || signals.require_mailbox_proof;
        match requirement {
            MfaRequirement::NotRequired if !risk_forces_mfa => {}
            _ if primary_is_mfa => {}
            _ if provider_mfa && !risk_forces_mfa => amr.push(AuthMethodRef::Mfa),
            MfaRequirement::Required { allowed_factors: f } => {
                let trusted = !risk_forces_mfa
                    && match &signals.trusted_device_token {
                        Some(token) => {
                            self.deps()
                                .mfa
                                .is_trusted_device(user.id, token.expose(), trusted_devices_allowed)
                                .await?
                        }
                        None => false,
                    };
                if !trusted {
                    allowed_factors = f;
                    required_actions.insert(0, RequiredAction::VerifyMfa);
                }
            }
            MfaRequirement::EnrollmentRequired { allowed_factors: f } => {
                if f.is_empty() {
                    return Err(AuthError::new(codes::org::ORG_POLICY_MFA_REQUIRED)
                        .with_context("no permitted factor can be enrolled"));
                }
                required_actions.insert(0, RequiredAction::EnrollMfa);
                // RSK-03 / existing factors: a proof before the enrollment.
                let proof_first = if !existing_factors.is_empty() {
                    Some(existing_factors)
                } else if needs_mailbox {
                    metadata.insert(EMAIL_CONFIRMATION.into(), serde_json::Value::Bool(true));
                    Some(vec![FactorKind::Email])
                } else {
                    None
                };
                match proof_first {
                    Some(verify) => {
                        metadata.insert(
                            ENROLL_FACTORS.into(),
                            serde_json::to_value(&f)
                                .map_err(|_| AuthError::internal("enrollable factors"))?,
                        );
                        allowed_factors = verify;
                        required_actions.insert(0, RequiredAction::VerifyMfa);
                    }
                    None => allowed_factors = f,
                }
            }
            MfaRequirement::NotRequired => {
                // Risk demands a second factor although none is enrolled:
                // `decide` answers RequireEmailConfirmation in that case, so
                // this arm is unreachable in practice; fail safe anyway.
                allowed_factors = vec![FactorKind::Email];
                metadata.insert(EMAIL_CONFIRMATION.into(), serde_json::Value::Bool(true));
                required_actions.insert(0, RequiredAction::VerifyMfa);
            }
        }
        if needs_mailbox
            && !required_actions.contains(&RequiredAction::VerifyMfa)
            && !required_actions.contains(&RequiredAction::EnrollMfa)
        {
            allowed_factors = vec![FactorKind::Email];
            metadata.insert(EMAIL_CONFIRMATION.into(), serde_json::Value::Bool(true));
            required_actions.insert(0, RequiredAction::VerifyMfa);
        }
        for action in &signals.extra_required_actions {
            if !required_actions.contains(action) {
                required_actions.push(*action);
            }
        }
        Ok(LoginPlan {
            user,
            org,
            amr,
            required_actions,
            allowed_factors,
            metadata,
            risk_level: assessment.level,
        })
    }

    /// The writing part of the pipeline, in `tx` only (which may already
    /// hold the proof of the primary authentication: a consumed magic link
    /// or login challenge, a mailbox confirmation — they commit together
    /// with the session or challenge). The user row is locked and must
    /// still be in the state the plan was made for.
    pub(crate) async fn finish_login_in(
        &self,
        mut tx: authn_store::PgTx,
        ctx: &RequestContext,
        auth: PrimaryAuthentication,
        client: ClientChannel,
        plan: LoginPlan,
    ) -> Result<PipelineOutcome, AuthError> {
        let now = self.now();
        let user = UserRepository::lock_for_update(&mut tx, auth.user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::session::INVALID_CREDENTIALS))?;
        if !plan.still_matches(&user) {
            return Err(AuthError::new(codes::common::CONFLICT)
                .with_context("the account changed during the sign-in"));
        }
        let LoginPlan {
            org,
            amr,
            required_actions,
            allowed_factors,
            metadata,
            risk_level,
            ..
        } = plan;

        if required_actions.is_empty() {
            let established = self
                .establish(
                    &mut tx,
                    ctx,
                    EstablishSession {
                        user_id: user.id,
                        method: auth.method,
                        amr,
                        acr: None,
                        auth_time: now,
                        client,
                        remember_me: auth.remember_me,
                        shared_device: auth.shared_device,
                        org,
                        device: DeviceInfo::from_context(ctx),
                    },
                )
                .await?;
            UserRepository::record_login(&mut tx, user.id, now).await?;
            let event = self.login_succeeded_event(ctx, &established, auth.method);
            self.deps().audit.record_in_tx(&mut tx, event).await?;
            if user.is_break_glass {
                self.record_break_glass_login(&mut tx, ctx, &established, auth.method)
                    .await?;
            }
            authn_store::commit(tx).await?;
            self.after_login(
                ctx,
                &user,
                auth.method,
                established.session.device_id.as_deref(),
            )
            .await;
            return Ok(PipelineOutcome::Established(Box::new(established)));
        }

        let issued = self
            .create_challenge(
                &mut tx,
                ctx,
                NewChallenge {
                    kind: ChallengeKind::Login,
                    user_id: user.id,
                    client_kind: auth.client,
                    primary_method: Some(auth.method),
                    amr,
                    first_factor_at: Some(now),
                    allowed_factors,
                    required_actions,
                    remember_me: auth.remember_me,
                    shared_device: auth.shared_device,
                    requested_org: auth.requested_org,
                    risk_level: Some(risk_level),
                    session_id: None,
                    metadata,
                },
            )
            .await?;
        let event = SecurityEvent::new(SecurityEventKind::LoginChallengeIssued, now)
            .with_context(ctx)
            .with_actor(Actor::User(user.id))
            .with_subject(user.id)
            .with_resource("auth_challenge", issued.challenge.id)
            .with_meta("method", auth.method.as_str())
            .with_meta("risk", risk_level.as_str())
            .with_meta(
                "required_actions",
                issued
                    .challenge
                    .required_actions
                    .iter()
                    .map(|a| a.as_str())
                    .collect::<Vec<_>>(),
            );
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        crate::metrics::login("challenge");
        Ok(PipelineOutcome::Challenge(Box::new(issued)))
    }

    /// Records `admin.break_glass_used` (high priority, `surface: login`)
    /// in the establishing transaction (ADM-05, K-05).
    pub(crate) async fn record_break_glass_login(
        &self,
        conn: &mut sqlx::PgConnection,
        ctx: &RequestContext,
        established: &EstablishedSession,
        method: LoginMethod,
    ) -> Result<(), AuthError> {
        crate::metrics::break_glass_login();
        tracing::warn!(
            user = %established.session.user_id,
            session = %established.session.id,
            "break-glass account signed in (high priority)"
        );
        let event = self.break_glass_login_event(ctx, established, method);
        self.deps().audit.record_in_tx(conn, event).await
    }

    /// RSK-03 `high`: audit, notify the user (throttled) and answer
    /// `suspicious_login_blocked`.
    async fn block_risky_login(
        &self,
        ctx: &RequestContext,
        user: &UserRecord,
        input: &RiskInput,
        assessment: &RiskAssessment,
    ) -> AuthError {
        match recipient_of(self, user).await {
            Ok(Some((recipient, locale))) => {
                self.deps()
                    .risk_alerts
                    .on_blocked_login(input, assessment, recipient, locale, ctx)
                    .await
            }
            Ok(None) | Err(_) => AuthError::new(codes::protect::SUSPICIOUS_LOGIN_BLOCKED),
        }
    }

    /// After a session was established: records the device and network
    /// and, for a new device of a user with a login history, queues the
    /// new-device notification with a "this wasn't me" link (RSK-04). Never
    /// fails the login (errors are logged).
    pub(crate) async fn after_login(
        &self,
        ctx: &RequestContext,
        user: &UserRecord,
        method: LoginMethod,
        device_id: Option<&str>,
    ) {
        crate::metrics::login("succeeded");
        // contracts §15.7: verified-domain auto-join after every login.
        if let Err(err) = self.deps().orgs.auto_join_verified_domains(user.id).await {
            tracing::warn!(error = %err, "domain auto-join after login failed");
        }
        if !self.settings().risk.enabled {
            return;
        }
        let mut input = RiskInput::from_context(ctx, Some(user.id), method, self.now());
        // The session's device: a browser without a device cookie got a
        // fresh id from `establish` (a new device, RSK-04).
        if let Some(device) = device_id {
            input.device_id = Some(device.to_owned());
        }
        let recipient = match recipient_of(self, user).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                if let Err(err) = self.deps().risk.record_successful_login(&input).await {
                    tracing::warn!(error = %err, "recording the login device failed");
                }
                return;
            }
            Err(err) => {
                tracing::warn!(error = %err, "loading the login recipient failed");
                return;
            }
        };
        if let Err(err) = self
            .deps()
            .risk_alerts
            .on_successful_login(&input, recipient.0, recipient.1, self, ctx)
            .await
        {
            tracing::warn!(error = %err, "new-device alert failed");
        }
    }
}
