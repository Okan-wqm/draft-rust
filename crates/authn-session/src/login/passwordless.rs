//! Passwordless login: magic link (SES-18) and e-mail code (SES-19).
//!
//! Both start requests answer the same way for every address (body,
//! status, timing): the answer — a binding token for the magic link, a
//! challenge token for the e-mail code — is generated before the address
//! is looked up, and the lookup, the token and the e-mail happen in a
//! background job ([`SessionService::drain_background_jobs`]).
//!
//! * **Magic link** (`one_time_tokens` purpose `magic_link`, 15 min): the
//!   link points to the frontend, which **POSTs** the token (link-preview
//!   bots never consume it). The request binds the link to the requesting
//!   browser (`__Host-authn_magic` cookie) or app (body); opened anywhere
//!   else, the user must confirm explicitly (`confirm_other_device`).
//! * **E-mail code** (purpose `login_code`, 6 digits, 10 min, 5 attempts):
//!   bound to a `passwordless` challenge and to the requesting device;
//!   every failure is the uniform `invalid_code`.
//!
//! Consuming the proof, the mailbox confirmation of an unverified account
//! (`MailboxProof::Passwordless`, ADR 0002) and the session or MFA
//! challenge commit in one transaction.

use authn_core::domain::{AccountStatus, AuthMethodRef, ClientKind, EmailAddress, LoginMethod};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{ChallengeId, OneTimeTokenId, OrgId, UserId};
use authn_core::ports::{
    Notification, NotificationKind, PrimaryAuthentication, RateLimitKey, RateLimitPolicy,
};
use authn_core::secret::{SecretString, SensitiveString};
use authn_crypto::token::{OpaqueToken, TokenHash};
use authn_protect::LoginAttempt;
use authn_store::{
    NewOneTimeToken, OneTimeTokenRepository, TokenPurpose, TokenSubject, UserRecord, UserRepository,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;

use super::pipeline::{LoginSignals, PipelineOutcome, recipient_of};
use crate::service::{
    ChallengeKind, ClientChannel, IssuedChallenge, NewChallenge, SessionService, after,
};

/// Rate-limit action: passwordless requests per address.
const PASSWORDLESS_ACTION: &str = "login_passwordless";
/// Passwordless e-mails per address and hour.
const PASSWORDLESS_PER_ADDRESS: RateLimitPolicy =
    RateLimitPolicy::new(5, std::time::Duration::from_secs(3600));

/// Body of `POST /v1/login/magic-link` and `POST /v1/login/email-code`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MagicLinkRequest {
    /// E-mail address.
    pub email: String,
    /// "Remember me" for the session (web).
    #[serde(default)]
    pub remember_me: bool,
    /// "This is not my device" (SES-07).
    #[serde(default)]
    pub shared_device: bool,
    /// Organization to sign in to.
    #[serde(default)]
    pub org_id: Option<OrgId>,
}

impl std::fmt::Debug for MagicLinkRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkRequest")
            .field("email", &authn_core::redact::mask_email(&self.email))
            .finish_non_exhaustive()
    }
}

/// The answer of a magic-link request: the binding secret of the
/// requesting client (web: cookie, native: body).
#[derive(Clone)]
pub struct MagicLinkStart {
    /// Binding secret.
    pub binding_token: SensitiveString,
    /// Link lifetime.
    pub expires_in: std::time::Duration,
}

impl std::fmt::Debug for MagicLinkStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkStart").finish_non_exhaustive()
    }
}

/// Body of `POST /v1/login/magic-link/verify`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MagicLinkVerify {
    /// The token from the link.
    #[schema(value_type = String)]
    pub token: SecretString,
    /// Native clients: the binding token of the request.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub binding_token: Option<SecretString>,
    /// The user confirmed signing in on this device although the link was
    /// requested elsewhere.
    #[serde(default)]
    pub confirm_other_device: bool,
}

impl std::fmt::Debug for MagicLinkVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkVerify")
            .field("confirm_other_device", &self.confirm_other_device)
            .finish_non_exhaustive()
    }
}

/// The answer of an e-mail-code request: the challenge token (web: cookie,
/// native: body).
#[derive(Clone)]
pub struct EmailCodeStart {
    /// Challenge token to present with the code.
    pub challenge_token: SensitiveString,
    /// Code lifetime.
    pub expires_in: std::time::Duration,
}

impl std::fmt::Debug for EmailCodeStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailCodeStart").finish_non_exhaustive()
    }
}

/// Body of `POST /v1/login/email-code/verify`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailCodeVerify {
    /// Six-digit code.
    #[schema(value_type = String)]
    pub code: SecretString,
}

impl std::fmt::Debug for EmailCodeVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailCodeVerify").finish_non_exhaustive()
    }
}

/// Accounts a passwordless login may be offered to. Placeholders of
/// unverified registrations are included: the mailbox owner proves
/// control (ADR 0002). Status is assessed again by the pipeline.
fn passwordless_allowed(user: &UserRecord) -> bool {
    !matches!(
        user.status,
        AccountStatus::Deleted | AccountStatus::Disabled | AccountStatus::Suspended
    ) && user.email.is_some()
}

/// Shortest answer time of a failed e-mail-code verification (SES-19:
/// existing and unknown accounts answer alike; also slows guessing).
const LOGIN_CODE_FAILURE_FLOOR: std::time::Duration = std::time::Duration::from_millis(50);

fn hex(hash: &TokenHash) -> String {
    data_encoding::HEXLOWER.encode(hash.as_bytes())
}

fn invalid_code() -> AuthError {
    AuthError::new(codes::common::INVALID_CODE)
}

impl SessionService {
    /// Limits shared by both passwordless requests: per IP (the login
    /// limit, PRT-02) and per address.
    async fn passwordless_limits(
        &self,
        ctx: &RequestContext,
        identifier: &str,
        method: LoginMethod,
    ) -> Result<(), AuthError> {
        self.deps()
            .protection
            .check_attempt(
                &LoginAttempt {
                    identifier,
                    user_id: None,
                    method,
                    trusted_device: false,
                    captcha_response: None,
                },
                ctx,
            )
            .await?;
        self.deps()
            .rate_limiter
            .check(
                &RateLimitKey::account(PASSWORDLESS_ACTION, identifier),
                PASSWORDLESS_PER_ADDRESS,
                1,
            )
            .await?
            .into_result()?;
        Ok(())
    }

    /// SES-18: requests a magic link. Answers the same for every address.
    pub async fn request_magic_link(
        &self,
        ctx: &RequestContext,
        request: MagicLinkRequest,
        client: ClientKind,
    ) -> Result<MagicLinkStart, AuthError> {
        let email = EmailAddress::parse(&request.email)
            .map_err(|_| AuthError::new(codes::common::VALIDATION_FAILED).with_context("email"))?;
        self.passwordless_limits(ctx, email.normalized(), LoginMethod::MagicLink)
            .await?;
        let binding = OpaqueToken::generate().map_err(AuthError::from)?;
        let binding_hash = hex(&binding.hash());
        let link = OpaqueToken::generate().map_err(AuthError::from)?;
        let service = self.clone();
        let ctx_job = ctx.clone();
        let queued = self
            .spawn_job(async move {
                if let Err(err) = service
                    .process_magic_link(&ctx_job, &email, &request, client, link, binding_hash)
                    .await
                {
                    tracing::error!(error = %err, request_id = %ctx_job.request_id, "magic link request failed");
                }
            })
            .await;
        if !queued {
            tracing::warn!("passwordless backlog full; magic link request dropped");
        }
        Ok(MagicLinkStart {
            binding_token: binding.into_sensitive(),
            expires_in: self.settings().session.magic_link_ttl,
        })
    }

    async fn process_magic_link(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
        request: &MagicLinkRequest,
        client: ClientKind,
        link: OpaqueToken,
        binding_hash: String,
    ) -> Result<(), AuthError> {
        let Some(user) = UserRepository::find_by_email(self.pool(), email)
            .await?
            .filter(passwordless_allowed)
        else {
            return Ok(());
        };
        // Read before the transaction: never wait for a second connection
        // while holding one.
        let Some((recipient, locale)) = recipient_of(self, &user).await? else {
            return Ok(());
        };
        let now = self.now();
        let expires_at = after(now, self.settings().session.magic_link_ttl);
        let mut tx = self.begin().await?;
        OneTimeTokenRepository::create(
            &mut tx,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: TokenPurpose::MagicLink,
                token_hash: link.hash(),
                subject: TokenSubject::user(user.id),
                group_id: None,
                target: None,
                max_attempts: 1,
                metadata: serde_json::json!({
                    "binding": binding_hash,
                    "client": client.as_str(),
                    "remember_me": request.remember_me,
                    "shared_device": request.shared_device,
                    "org_id": request.org_id,
                }),
                created_ip: Some(ctx.client_ip),
                created_at: now,
                expires_at,
            },
            true,
        )
        .await?;
        self.deps()
            .notifier
            .notify_in_tx(
                &mut tx,
                Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::MagicLink {
                        token: link.into_sensitive(),
                        expires_at,
                    },
                },
            )
            .await?;
        authn_store::commit(tx).await
    }

    /// SES-18: signs in with a magic link (POST only). A link opened on
    /// another device than the requesting one needs
    /// `confirm_other_device` (`magic_link_confirmation_required`).
    pub async fn verify_magic_link(
        &self,
        ctx: &RequestContext,
        verify: MagicLinkVerify,
        client: ClientChannel,
        binding_cookie: Option<SensitiveString>,
    ) -> Result<PipelineOutcome, AuthError> {
        let token = OpaqueToken::parse(verify.token.expose_secret())
            .map_err(|_| AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN))?;
        let now = self.now();
        // Read the link without a transaction; it is consumed below, in
        // the transaction that creates the session.
        let record = OneTimeTokenRepository::find_active_link(
            self.pool(),
            TokenPurpose::MagicLink,
            &token.hash(),
            now,
        )
        .await?
        .ok_or_else(|| AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN))?;
        let presented = binding_cookie
            .map(|c| c.expose().to_owned())
            .or_else(|| verify.binding_token.map(|b| b.expose_secret().to_owned()));
        let stored = record
            .metadata
            .get("binding")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let same_device = presented
            .and_then(|p| OpaqueToken::parse(&p).ok())
            .is_some_and(|p| bool::from(hex(&p.hash()).as_bytes().ct_eq(stored.as_bytes())));
        if !same_device && !verify.confirm_other_device {
            return Err(AuthError::new(
                codes::session::MAGIC_LINK_CONFIRMATION_REQUIRED,
            ));
        }
        let user = record
            .user_id
            .ok_or_else(|| AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN))?;
        let flag = |name: &str| {
            same_device
                && record
                    .metadata
                    .get(name)
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
        };
        let requested_org = record
            .metadata
            .get("org_id")
            .and_then(|v| serde_json::from_value::<OrgId>(v.clone()).ok());
        let kind = client.kind();
        let auth = PrimaryAuthentication {
            user_id: user,
            method: LoginMethod::MagicLink,
            amr: vec![AuthMethodRef::Email],
            client: kind,
            remember_me: flag("remember_me") && kind == ClientKind::Web,
            // On a confirmed other device the session is short-lived.
            shared_device: flag("shared_device") || !same_device,
            requested_org,
            provider_asserted_mfa: false,
        };
        let plan = self
            .plan_login(ctx, &auth, client, &LoginSignals::default(), true)
            .await?;
        self.warm_credentials(kind).await?;
        let mut tx = self.begin().await?;
        let consumed = OneTimeTokenRepository::consume_link(
            &mut tx,
            TokenPurpose::MagicLink,
            &token.hash(),
            self.now(),
        )
        .await?
        .ok_or_else(|| AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN))?;
        if consumed.user_id != Some(user) {
            return Err(AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN));
        }
        // ADR 0002: the mailbox owner proved control; an unverified
        // account is verified and its unproven credentials dropped.
        self.deps()
            .accounts
            .confirm_mailbox_control_in_tx(
                &mut tx,
                Some(ctx),
                user,
                authn_account::MailboxProof::Passwordless,
            )
            .await?;
        self.finish_login_in(tx, ctx, auth, client, plan).await
    }

    /// SES-19: requests an e-mail login code. Answers the same for every
    /// address: the challenge token is generated first, the challenge and
    /// the code exist only for an eligible account.
    pub async fn request_email_code(
        &self,
        ctx: &RequestContext,
        request: MagicLinkRequest,
        client: ClientKind,
    ) -> Result<EmailCodeStart, AuthError> {
        let email = EmailAddress::parse(&request.email)
            .map_err(|_| AuthError::new(codes::common::VALIDATION_FAILED).with_context("email"))?;
        self.passwordless_limits(ctx, email.normalized(), LoginMethod::EmailCode)
            .await?;
        let token = OpaqueToken::generate().map_err(AuthError::from)?;
        let challenge_token = SensitiveString::new(token.expose().to_owned());
        let service = self.clone();
        let ctx_job = ctx.clone();
        let queued = self
            .spawn_job(async move {
                if let Err(err) = service
                    .process_email_code(&ctx_job, &email, &request, client, token)
                    .await
                {
                    tracing::error!(error = %err, request_id = %ctx_job.request_id, "e-mail code request failed");
                }
            })
            .await;
        if !queued {
            tracing::warn!("passwordless backlog full; e-mail code request dropped");
        }
        Ok(EmailCodeStart {
            challenge_token,
            expires_in: self.settings().session.email_code_ttl,
        })
    }

    async fn process_email_code(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
        request: &MagicLinkRequest,
        client: ClientKind,
        token: OpaqueToken,
    ) -> Result<(), AuthError> {
        let Some(user) = UserRepository::find_by_email(self.pool(), email)
            .await?
            .filter(passwordless_allowed)
        else {
            return Ok(());
        };
        let Some((recipient, locale)) = recipient_of(self, &user).await? else {
            return Ok(());
        };
        let mut tx = self.begin().await?;
        let IssuedChallenge { challenge, .. } = self
            .create_challenge_with(
                &mut tx,
                ctx,
                NewChallenge {
                    kind: ChallengeKind::Passwordless,
                    user_id: user.id,
                    client_kind: client,
                    primary_method: Some(LoginMethod::EmailCode),
                    amr: Vec::new(),
                    first_factor_at: None,
                    allowed_factors: Vec::new(),
                    required_actions: Vec::new(),
                    remember_me: request.remember_me,
                    shared_device: request.shared_device,
                    requested_org: request.org_id,
                    risk_level: None,
                    session_id: None,
                    metadata: serde_json::Map::new(),
                },
                token,
                self.settings().session.email_code_ttl,
            )
            .await?;
        self.issue_challenge_code(
            &mut tx,
            user.id,
            (recipient, locale),
            challenge.id,
            challenge.expires_at,
            Some(ctx.client_ip),
        )
        .await?;
        authn_store::commit(tx).await
    }

    /// SES-19: signs in with the e-mailed code. Every failure (unknown,
    /// expired or burnt challenge, other device, wrong code) is the
    /// uniform `invalid_code`.
    pub async fn verify_email_code(
        &self,
        ctx: &RequestContext,
        challenge_token: &str,
        code: &SecretString,
        client: ClientChannel,
    ) -> Result<PipelineOutcome, AuthError> {
        let started = tokio::time::Instant::now();
        // Read (and immediately release) the challenge: the code check and
        // the failure count must not run while a connection is held.
        let state = {
            let mut tx = self.begin().await?;
            let opened = self
                .open_challenge(
                    &mut tx,
                    ctx,
                    challenge_token,
                    ChallengeKind::Passwordless,
                    client.kind(),
                )
                .await;
            if let Err(err) = tx.rollback().await {
                tracing::warn!(error = %err, "releasing a login-code challenge failed");
            }
            match opened {
                Ok(state) => Some(state),
                Err(err) if err.status().is_server_error() => return Err(err),
                Err(_) => None,
            }
        };
        // Unknown, burnt or foreign challenges (including the tokens handed
        // out for addresses without an account) do the same work as a wrong
        // code — code check and failure count against ids that never
        // exist — so the answer time does not reveal the account (SES-19).
        let (user, challenge) = state.as_ref().map_or_else(
            || {
                (
                    UserId::from_uuid(uuid::Uuid::nil()),
                    ChallengeId::from_uuid(uuid::Uuid::nil()),
                )
            },
            |s| (s.user_id, s.id),
        );
        let checked = self.check_login_code(user, challenge, code).await;
        let state = match (state, checked) {
            (Some(state), Ok(())) => state,
            (_, checked) => {
                if let Err(count_err) = self.record_challenge_failure(challenge).await {
                    tracing::warn!(error = %count_err, "counting a login-code failure failed");
                }
                // The writes of a real attempt (attempt counters) still
                // cost a commit more than an unknown challenge: every
                // failure answers no earlier than the floor.
                tokio::time::sleep_until(started + LOGIN_CODE_FAILURE_FLOOR).await;
                return Err(match checked {
                    Err(err) if err.status().is_server_error() => err,
                    _ => invalid_code(),
                });
            }
        };
        let kind = client.kind();
        let auth = PrimaryAuthentication {
            user_id: state.user_id,
            method: LoginMethod::EmailCode,
            amr: vec![AuthMethodRef::Email, AuthMethodRef::Otp],
            client: kind,
            remember_me: state.remember_me && kind == ClientKind::Web,
            shared_device: state.shared_device,
            requested_org: state.requested_org,
            provider_asserted_mfa: false,
        };
        let plan = self
            .plan_login(ctx, &auth, client, &LoginSignals::default(), true)
            .await?;
        self.warm_credentials(kind).await?;
        let mut tx = self.begin().await?;
        // The code is consumed; the challenge must still be open (a
        // concurrent revocation closes it).
        let reopened = self
            .open_challenge(
                &mut tx,
                ctx,
                challenge_token,
                ChallengeKind::Passwordless,
                kind,
            )
            .await
            .map_err(|e| {
                if e.status().is_server_error() {
                    e
                } else {
                    invalid_code()
                }
            })?;
        self.consume_challenge(&mut tx, reopened.id).await?;
        self.deps()
            .accounts
            .confirm_mailbox_control_in_tx(
                &mut tx,
                Some(ctx),
                reopened.user_id,
                authn_account::MailboxProof::Passwordless,
            )
            .await?;
        self.finish_login_in(tx, ctx, auth, client, plan).await
    }
}
