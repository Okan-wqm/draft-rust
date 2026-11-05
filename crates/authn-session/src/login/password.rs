//! Password login (SES-01).
//!
//! Order (contracts §15.7):
//!
//! 1. login CSRF (web) — done by the endpoint;
//! 2. account lookup by the normalized address (none → dummy
//!    verification below, CRY-05);
//! 3. [`authn_protect::LoginProtection::check_attempt`] **exactly once**
//!    per attempt: per-IP limit, CAPTCHA escalation, soft lock (the
//!    per-identifier budgets are consumed atomically, so concurrent guesses
//!    cannot outrun them);
//! 4. password verification (`PasswordService::verify_login_password`,
//!    rehash / legacy upgrade, dummy hash for unknown accounts);
//!    the outcome is matched as an enum: `MustChangePassword` ⇒ the
//!    `change_password` required action, never a full session;
//! 5. success → `record_success` (refunds the budgets); failure →
//!    `record_failure` (risk velocity) + the uniform `invalid_credentials`;
//! 6. the shared pipeline (account status — revealed only now —,
//!    organization, MFA, risk, trusted device).

use authn_core::domain::{AuthMethodRef, ClientKind, EmailAddress, LoginMethod};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::OrgId;
use authn_core::ports::{
    Actor, PrimaryAuthentication, RequiredAction, SecurityEvent, SecurityEventKind,
};
use authn_core::secret::{SecretString, SensitiveString};
use authn_password::LoginPasswordOutcome;
use authn_protect::LoginAttempt;
use authn_store::UserRepository;
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use super::pipeline::{LoginSignals, PipelineOutcome};
use crate::metrics;
use crate::service::{ClientChannel, SessionService};

/// Longest accepted identifier (RFC 5321 path limit).
const MAX_IDENTIFIER_BYTES: usize = 320;

/// Body of `POST /v1/login/password`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordLogin {
    /// E-mail address.
    pub email: String,
    /// Password.
    #[schema(value_type = String)]
    pub password: SecretString,
    /// CAPTCHA response, when the previous answer was `captcha_required`.
    #[serde(default)]
    pub captcha: Option<String>,
    /// "Remember me" (SES-06, web).
    #[serde(default)]
    pub remember_me: bool,
    /// "This is not my device" (SES-07).
    #[serde(default)]
    pub shared_device: bool,
    /// Organization to sign in to (SES-17, ORG-07).
    #[serde(default)]
    pub org_id: Option<OrgId>,
}

impl std::fmt::Debug for PasswordLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordLogin")
            .field("email", &authn_core::redact::mask_email(&self.email))
            .field("remember_me", &self.remember_me)
            .field("shared_device", &self.shared_device)
            .field("org_id", &self.org_id)
            .finish_non_exhaustive()
    }
}

/// The counter key of a submitted identifier: the normalized address, or
/// the trimmed lower-cased input when it is not a valid address (so
/// malformed identifiers are throttled like any other).
fn identifier_key(input: &str) -> (Option<EmailAddress>, String) {
    match EmailAddress::parse(input) {
        Ok(email) => {
            let key = email.normalized().to_owned();
            (Some(email), key)
        }
        Err(_) => {
            let mut key: String = input.trim().to_lowercase();
            key.truncate(MAX_IDENTIFIER_BYTES);
            (None, key)
        }
    }
}

impl SessionService {
    /// SES-01: signs in with e-mail and password. Every credential failure
    /// is the uniform `invalid_credentials` (same body, status and — the
    /// unknown-account path verifies a dummy hash — timing).
    pub async fn login_with_password(
        &self,
        ctx: &RequestContext,
        login: PasswordLogin,
        client: ClientChannel,
        trusted_device_token: Option<SensitiveString>,
    ) -> Result<PipelineOutcome, AuthError> {
        if login.email.len() > MAX_IDENTIFIER_BYTES || login.password.expose_secret().len() > 4096 {
            return Err(AuthError::new(codes::session::INVALID_CREDENTIALS));
        }
        let (email, identifier) = identifier_key(&login.email);
        let account = match &email {
            Some(email) => UserRepository::find_by_email(self.pool(), email).await?,
            None => None,
        };
        let user_id = account.as_ref().map(|u| u.id);
        let trusted_device = match (user_id, &trusted_device_token) {
            (Some(user), Some(token)) => {
                self.deps()
                    .mfa
                    .is_trusted_device(user, token.expose(), true)
                    .await?
            }
            _ => false,
        };
        let attempt = LoginAttempt {
            identifier: &identifier,
            user_id,
            method: LoginMethod::Password,
            trusted_device,
            captcha_response: login.captcha.as_deref(),
        };
        self.deps()
            .protection
            .check_attempt(&attempt, ctx)
            .await
            .inspect_err(|e| metrics::login_failed("password", e.code().code()))?;

        let (outcome, verified_password) = self
            .deps()
            .passwords
            .verify_login_password_checked(ctx, user_id, &login.password)
            .await?;
        let must_change = match outcome {
            LoginPasswordOutcome::Valid => false,
            LoginPasswordOutcome::MustChangePassword => true,
            LoginPasswordOutcome::Invalid => {
                if let Err(err) = self.deps().protection.record_failure(&attempt, ctx).await {
                    tracing::warn!(error = %err, "recording a login failure failed");
                }
                let mut event = SecurityEvent::new(SecurityEventKind::LoginFailed, self.now())
                    .with_context(ctx)
                    .with_actor(Actor::Anonymous)
                    .failed(codes::session::INVALID_CREDENTIALS.code())
                    .with_meta("method", LoginMethod::Password.as_str());
                if let Some(user) = user_id {
                    event = event.with_subject(user);
                }
                if let Err(err) = self.deps().audit.record(event).await {
                    tracing::warn!(error = %err, "login failure audit failed");
                }
                metrics::login_failed("password", "invalid_credentials");
                return Err(AuthError::new(codes::session::INVALID_CREDENTIALS));
            }
        };
        let Some(user) = user_id else {
            // A correct password needs an account; unreachable.
            return Err(AuthError::new(codes::session::INVALID_CREDENTIALS));
        };
        self.deps().protection.record_success(&attempt, ctx).await?;

        let signals = LoginSignals {
            trusted_device_token,
            extra_required_actions: if must_change {
                vec![RequiredAction::ChangePassword]
            } else {
                Vec::new()
            },
            // RSK-04 / PWD-12: whoever knows the old password may be the
            // reason it must change; it alone never sets the new one.
            require_mailbox_proof: must_change,
            verified_password,
        };
        let client_kind = client.kind();
        // The row read above is passed on (K-128): the pipeline re-checks it
        // under the row lock before acting on it.
        self.run_login_pipeline_for(
            ctx,
            PrimaryAuthentication {
                user_id: user,
                method: LoginMethod::Password,
                amr: vec![AuthMethodRef::Pwd],
                client: client_kind,
                remember_me: login.remember_me && client_kind == ClientKind::Web,
                shared_device: login.shared_device,
                requested_org: login.org_id,
                provider_asserted_mfa: false,
            },
            client,
            &signals,
            account,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ses_01_identifier_key_normalizes_addresses_and_keeps_garbage_bounded() {
        let (email, key) = identifier_key("  Alice@Example.COM ");
        assert!(email.is_some());
        assert_eq!(key, "alice@example.com");
        let long = "x".repeat(1000);
        let (email, key) = identifier_key(&long);
        assert!(email.is_none());
        assert_eq!(key.len(), MAX_IDENTIFIER_BYTES);
    }
}
