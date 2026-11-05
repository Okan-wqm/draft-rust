//! Passkey login (SES-20, SES-21): username-less (discoverable credential)
//! with optional conditional UI (autofill).
//!
//! `POST /v1/login/passkey/options` starts the ceremony (the binding token
//! goes to a `__Host-authn_passkey` cookie, `SameSite=Strict`, for web
//! clients and into the body for native ones); `POST /v1/login/passkey`
//! finishes it. The user is whoever the authenticator asserts; user
//! verification is required, so the passkey alone satisfies MFA
//! (`amr: [hwk|swk, user, mfa]`) unless the organization demands otherwise.

#[cfg(feature = "passkey")]
use authn_core::domain::{ClientKind, LoginMethod};
use authn_core::error::AuthError;
#[cfg(not(feature = "passkey"))]
use authn_core::error::codes;
use authn_core::http::RequestContext;
use authn_core::id::{CeremonyId, OrgId};
#[cfg(feature = "passkey")]
use authn_core::ports::PrimaryAuthentication;
use authn_core::secret::SensitiveString;
#[cfg(feature = "passkey")]
use authn_protect::LoginAttempt;
use serde::Deserialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

#[cfg(feature = "passkey")]
use super::pipeline::LoginSignals;
use super::pipeline::PipelineOutcome;
use crate::service::{ClientChannel, SessionService};

/// A started passkey ceremony (login or second factor).
#[derive(Clone)]
pub struct PasskeyLoginStart {
    /// Ceremony id.
    pub ceremony_id: CeremonyId,
    /// Binding token (web: cookie, native: body).
    pub binding_token: SensitiveString,
    /// `CredentialRequestOptions` for `navigator.credentials.get()`.
    pub options: serde_json::Value,
    /// Ceremony expiry.
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for PasskeyLoginStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyLoginStart")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

/// Body of `POST /v1/login/passkey/options`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLoginOptions {
    /// Request conditional mediation (passkey autofill).
    #[serde(default)]
    pub conditional_ui: bool,
}

/// Body of `POST /v1/login/passkey`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLogin {
    /// Ceremony id.
    pub ceremony_id: CeremonyId,
    /// Native clients: the binding token (web sends the cookie).
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub binding_token: Option<SensitiveString>,
    /// `PublicKeyCredential` from `navigator.credentials.get()`.
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
    /// "Remember me" (web).
    #[serde(default)]
    pub remember_me: bool,
    /// "This is not my device" (SES-07).
    #[serde(default)]
    pub shared_device: bool,
    /// Organization to sign in to.
    #[serde(default)]
    pub org_id: Option<OrgId>,
}

impl std::fmt::Debug for PasskeyLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyLogin")
            .field("ceremony_id", &self.ceremony_id)
            .finish_non_exhaustive()
    }
}

impl SessionService {
    /// SES-20: starts a username-less passkey login.
    #[cfg(feature = "passkey")]
    pub async fn start_passkey_login(
        &self,
        ctx: &RequestContext,
        options: PasskeyLoginOptions,
    ) -> Result<PasskeyLoginStart, AuthError> {
        let start = self
            .deps()
            .webauthn
            .start_authentication(
                ctx,
                authn_webauthn::AuthenticationTarget::Discoverable {
                    conditional_ui: options.conditional_ui,
                },
                &authn_webauthn::PasskeyPolicy::unrestricted(),
            )
            .await?;
        Ok(PasskeyLoginStart {
            ceremony_id: start.ceremony_id,
            binding_token: start.binding_token,
            options: start.options,
            expires_at: start.expires_at,
        })
    }

    /// Without the `passkey` feature.
    #[cfg(not(feature = "passkey"))]
    pub async fn start_passkey_login(
        &self,
        _ctx: &RequestContext,
        _options: PasskeyLoginOptions,
    ) -> Result<PasskeyLoginStart, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }

    /// SES-20, SES-21: finishes a passkey login and runs the pipeline.
    #[cfg(feature = "passkey")]
    pub async fn login_with_passkey(
        &self,
        ctx: &RequestContext,
        login: PasskeyLogin,
        client: ClientChannel,
        binding_cookie: Option<SensitiveString>,
        trusted_device_token: Option<SensitiveString>,
    ) -> Result<PipelineOutcome, AuthError> {
        // Per-IP login limit (PRT-02); passkeys are never soft-locked.
        self.deps()
            .protection
            .check_attempt(
                &LoginAttempt {
                    identifier: "",
                    user_id: None,
                    method: LoginMethod::Passkey,
                    trusted_device: false,
                    captcha_response: None,
                },
                ctx,
            )
            .await?;
        let binding_token = binding_cookie.or(login.binding_token).ok_or_else(|| {
            AuthError::new(authn_core::error::codes::webauthn::PASSKEY_CEREMONY_INVALID)
                .with_context("missing binding token")
        })?;
        let verified = self
            .deps()
            .webauthn
            .finish_authentication(
                ctx,
                authn_webauthn::AuthenticationFinish {
                    ceremony_id: login.ceremony_id,
                    binding_token,
                    target: authn_webauthn::AuthenticationTarget::Discoverable {
                        conditional_ui: false,
                    },
                    credential: login.credential,
                },
            )
            .await
            .inspect_err(|e| crate::metrics::login_failed("passkey", e.code().code()))?;
        let kind = client.kind();
        self.run_login_pipeline(
            ctx,
            PrimaryAuthentication {
                user_id: verified.user_id,
                method: LoginMethod::Passkey,
                amr: verified.amr,
                client: kind,
                remember_me: login.remember_me && kind == ClientKind::Web,
                shared_device: login.shared_device,
                requested_org: login.org_id,
                provider_asserted_mfa: false,
            },
            client,
            &LoginSignals {
                trusted_device_token,
                extra_required_actions: Vec::new(),
                require_mailbox_proof: false,
                verified_password: None,
            },
        )
        .await
    }

    /// Without the `passkey` feature.
    #[cfg(not(feature = "passkey"))]
    pub async fn login_with_passkey(
        &self,
        _ctx: &RequestContext,
        _login: PasskeyLogin,
        _client: ClientChannel,
        _binding_cookie: Option<SensitiveString>,
        _trusted_device_token: Option<SensitiveString>,
    ) -> Result<PipelineOutcome, AuthError> {
        Err(AuthError::new(codes::webauthn::PASSKEY_NOT_AVAILABLE))
    }
}
