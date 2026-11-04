//! Native (mobile SDK) flow (SOC-04).
//!
//! 1. `POST /v1/oauth/nonce` returns a fresh 256-bit nonce (stored as
//!    `SHA-256(nonce)`, `oidc_client.native_nonce_ttl`, single use).
//! 2. The app passes it verbatim to the platform SDK (Sign in with Apple
//!    `request.nonce`, Google `setNonce` / Credential Manager), which puts it
//!    into the ID token.
//! 3. `POST /v1/oauth/{provider}/native` with the ID token: signature, `iss`,
//!    `aud` / `azp` ∈ the configured **native client ids**, `exp`, `iat` are
//!    verified first; then the nonce row is consumed atomically by the
//!    hash of the token's `nonce` — a token without our nonce, with an
//!    expired or reused nonce, or replayed is refused.

use authn_core::domain::{ClientKind, Principal};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::OAuthStateId;
use authn_core::ports::LoginOutcome;
use authn_crypto::token::TokenHash;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::{IdentitySummary, OidcClientService, actions};
use crate::codes;
use crate::identity::{self, ExternalIdentity, clean_display_name};
use crate::provider::{Provider, ProviderKind};
use crate::store::{self, FLOW_NATIVE_NONCE, NewState};

/// A native nonce.
#[derive(Debug, Serialize, ToSchema)]
pub struct NativeNonce {
    /// Pass verbatim to the platform SDK as the ID-token nonce.
    pub nonce: String,
    /// Expiry.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// Body of `POST /v1/oauth/{provider}/native`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeLoginRequest {
    /// The ID token returned by the platform SDK.
    pub id_token: String,
    /// "Remember me" (SES-06).
    #[serde(default)]
    pub remember_me: bool,
    /// "This is not my device" (SES-07).
    #[serde(default)]
    pub shared_device: bool,
    /// Apple first sign-in only: the name the SDK returned
    /// (`fullName.givenName`); used as display name of the identity.
    /// Ignored for every other provider (their signed `name` claim is used).
    #[serde(default)]
    pub given_name: Option<String>,
    /// Apple first sign-in only: `fullName.familyName`.
    #[serde(default)]
    pub family_name: Option<String>,
}

impl std::fmt::Debug for NativeLoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeLoginRequest")
            .field("remember_me", &self.remember_me)
            .field("shared_device", &self.shared_device)
            .finish_non_exhaustive()
    }
}

impl OidcClientService {
    fn native_provider(&self, slug: &str) -> Result<Provider, AuthError> {
        let provider = self.provider(slug)?;
        if !provider.supports_native() {
            return Err(AuthError::new(codes::OAUTH_NATIVE_NOT_SUPPORTED));
        }
        Ok(provider.clone())
    }

    /// Issues a native nonce for `provider` (`POST /v1/oauth/nonce`).
    pub async fn issue_native_nonce(
        &self,
        ctx: &RequestContext,
        provider: &str,
    ) -> Result<NativeNonce, AuthError> {
        let provider = self.native_provider(provider)?;
        self.rate_limit(actions::NATIVE, ctx, self.settings().native_per_ip)
            .await?;
        let nonce = Self::token()?;
        // `state_hash` is NOT NULL and unique: an unrelated random value.
        let filler = Self::token()?;
        let now = self.now();
        let expires_at = now + self.settings().config.native_nonce_ttl;
        store::insert_state(
            &self.deps().pool,
            &NewState {
                id: OAuthStateId::generate(),
                provider: &provider.storage_id,
                flow: FLOW_NATIVE_NONCE,
                state_hash: filler.hash().as_bytes(),
                nonce_hash: nonce.hash().as_bytes(),
                pkce_verifier_ciphertext: None,
                user_id: None,
                return_to: None,
                client_kind: ClientKind::Native,
                binding_hash: None,
                created_at: now,
                expires_at,
            },
        )
        .await?;
        Ok(NativeNonce {
            nonce: nonce.expose().to_owned(),
            expires_at,
        })
    }

    /// Verifies a native ID token and consumes its nonce.
    async fn verify_native(
        &self,
        provider: &Provider,
        id_token: &str,
        first_login_name: Option<String>,
    ) -> Result<ExternalIdentity, AuthError> {
        let endpoints = self.endpoints(provider).await?;
        let claims = self
            .verify_id_token(provider, &endpoints, id_token, &provider.native_client_ids)
            .await?;
        let nonce_invalid = || AuthError::new(codes::OAUTH_NONCE_INVALID);
        let nonce = claims
            .nonce
            .as_deref()
            .filter(|n| !n.is_empty() && n.len() <= 256)
            .ok_or_else(nonce_invalid)?;
        store::consume_native_nonce(
            &self.deps().pool,
            TokenHash::digest(nonce.as_bytes()).as_bytes(),
            &provider.storage_id,
            self.now(),
        )
        .await?
        .ok_or_else(nonce_invalid)?;
        identity::from_id_claims(provider, claims, first_login_name)
    }

    /// Native login (`POST /v1/oauth/{provider}/native`). Failures are
    /// audited.
    pub async fn native_login(
        &self,
        ctx: &RequestContext,
        provider: &str,
        request: &NativeLoginRequest,
    ) -> Result<LoginOutcome, AuthError> {
        let result = async {
            let provider = self.native_provider(provider)?;
            self.rate_limit(actions::NATIVE, ctx, self.settings().native_per_ip)
                .await?;
            // The SDK-reported name is unsigned client input: it is taken
            // only for Apple, whose ID token never carries a name; every
            // other provider's signed `name` claim wins.
            let name = if provider.kind == ProviderKind::Apple {
                match (
                    request.given_name.as_deref(),
                    request.family_name.as_deref(),
                ) {
                    (Some(g), Some(f)) => clean_display_name(&format!("{g} {f}")),
                    (Some(one), None) | (None, Some(one)) => clean_display_name(one),
                    (None, None) => None,
                }
            } else {
                None
            };
            let external = self
                .verify_native(&provider, &request.id_token, name)
                .await?;
            self.login_with_identity(
                ctx,
                &external,
                ClientKind::Native,
                request.remember_me,
                request.shared_device,
            )
            .await
        }
        .await;
        match &result {
            Ok(_) => crate::metrics::login(provider, "ok"),
            Err(err) => {
                self.record_failure(ctx, provider, ClientKind::Native, err)
                    .await;
            }
        }
        result
    }

    /// Links a provider to the signed-in account with a native ID token
    /// (SOC-06; requires a recent authentication).
    pub async fn native_link(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        provider: &str,
        id_token: &str,
    ) -> Result<IdentitySummary, AuthError> {
        let user = self.require_step_up(principal)?;
        let provider = self.native_provider(provider)?;
        self.rate_limit(actions::NATIVE, ctx, self.settings().native_per_ip)
            .await?;
        self.ensure_linkable(user).await?;
        let external = self.verify_native(&provider, id_token, None).await?;
        self.link_identity(ctx, user, &external).await
    }
}
