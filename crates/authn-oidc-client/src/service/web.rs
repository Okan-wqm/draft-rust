//! Browser flow: authorization code + PKCE (S256) + `state` + `nonce`,
//! server-side state, browser binding (SOC-02).
//!
//! Start: a fresh `state`, `nonce` and PKCE verifier (256-bit CSPRNG
//! tokens) are created; only `SHA-256(state)`, `SHA-256(nonce)`,
//! `SHA-256(binding)` and the envelope-encrypted verifier (AAD = row) are
//! stored, with the validated `return_to` and a `state_ttl` (10 min)
//! expiry.
//!
//! Callback: the row is consumed atomically (`UPDATE … WHERE consumed_at IS
//! NULL AND expires_at > now RETURNING`) — single use even under concurrent
//! replays — *before* any other check; then the provider must match the
//! path, the browser must present the binding cookie (constant-time hash
//! comparison), the code is exchanged with the verifier, and the ID
//! token's `nonce` must hash to the stored one.

use std::time::Duration;

use authn_core::domain::{ClientKind, Principal};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{OAuthStateId, SessionId, UserId};
use authn_core::ports::LoginOutcome;
use authn_crypto::token::{OpaqueToken, TokenHash};
use secrecy::zeroize::Zeroizing;
use serde::Deserialize;
use url::Url;
use utoipa::{IntoParams, ToSchema};

use super::{OidcClientService, actions, pkce_challenge};
use crate::codes;
use crate::id_token::invalid;
use crate::identity::{self, ExternalIdentity};
use crate::provider::{Provider, ProviderKind};
use crate::store::{self, FLOW_LINK, FLOW_LOGIN, NewState};

/// Longest accepted `code` / `state` / `error` parameter.
const MAX_PARAM_BYTES: usize = 2048;

/// What `start` produced.
#[derive(Debug)]
pub struct WebStart {
    /// Where to send the browser.
    pub authorization_url: Url,
    /// Binding cookie value (`__Host-authn_oauth`).
    pub binding: OpaqueToken,
    /// Cookie lifetime (`oidc_client.state_ttl`).
    pub binding_max_age: Duration,
}

/// Query (`GET`) or form (`POST`, Apple `form_post`) parameters of the
/// callback. Unknown parameters (`scope`, `session_state`, Apple's
/// `id_token`…) are ignored: only the code-exchange result is trusted.
#[derive(Default, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct CallbackParams {
    /// Authorization code.
    pub code: Option<String>,
    /// The `state` issued at start.
    pub state: Option<String>,
    /// Provider error (`access_denied`…).
    pub error: Option<String>,
    /// Apple, first authorization only: JSON with the user's name (unsigned;
    /// only the name is used).
    pub user: Option<String>,
}

impl std::fmt::Debug for CallbackParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The code and the state are credentials of the flow; the `user`
        // field holds personal data.
        f.debug_struct("CallbackParams")
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field("state", &self.state.as_ref().map(|_| "[REDACTED]"))
            .field("error", &self.error)
            .field("user", &self.user.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Session options of a browser **login** (SES-06, SES-07, K-32): chosen
/// on the login page, stored with the authorization state and handed to
/// the session pipeline by the callback.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WebLoginOptions {
    /// "Remember me" (long-lived session).
    pub remember_me: bool,
    /// "This is not my device" (browser-session cookie, short lifetime).
    pub shared_device: bool,
}

/// What a callback produced.
#[derive(Debug)]
pub enum CallbackResult {
    /// A login: render with `SessionIssuer::login_response` (session cookie
    /// or challenge cookie + redirect to `return_to`).
    Login {
        /// Session or challenge.
        outcome: LoginOutcome,
        /// Validated absolute redirect target.
        return_to: String,
    },
    /// An identity was linked to the signed-in account.
    Linked {
        /// Validated absolute redirect target.
        return_to: String,
    },
}

/// Which browser flow is started.
enum Flow {
    /// Login, with the session options of the login page.
    Login(WebLoginOptions),
    /// Linking to `user`'s account, from `session`.
    Link { user: UserId, session: SessionId },
}

fn bounded(value: Option<&str>) -> Option<&str> {
    value.filter(|v| {
        !v.is_empty() && v.len() <= MAX_PARAM_BYTES && v.bytes().all(|b| b.is_ascii_graphic())
    })
}

impl OidcClientService {
    /// Starts a browser login with `provider` (`GET
    /// /v1/oauth/{provider}/start`). `binding_cookie` is the request's
    /// existing binding cookie, reused when well-formed.
    pub async fn start_web_login(
        &self,
        ctx: &RequestContext,
        provider: &str,
        return_to: Option<&str>,
        binding_cookie: Option<&str>,
        options: WebLoginOptions,
    ) -> Result<WebStart, AuthError> {
        let provider = self.provider(provider)?.clone();
        self.start(
            ctx,
            &provider,
            Flow::Login(options),
            return_to,
            binding_cookie,
        )
        .await
    }

    /// Starts linking `provider` to the signed-in account (SOC-06; requires
    /// a recent authentication, SES-13). The callback links instead of
    /// logging in — only while the session that started the flow is still
    /// active (K-03).
    pub async fn start_web_link(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        provider: &str,
        return_to: Option<&str>,
        binding_cookie: Option<&str>,
    ) -> Result<WebStart, AuthError> {
        let user = self.require_step_up(principal)?;
        let session = principal
            .session_id()
            .ok_or_else(|| AuthError::new(authn_core::error::codes::common::FORBIDDEN))?;
        let provider = self.provider(provider)?.clone();
        self.ensure_linkable(user).await?;
        self.start(
            ctx,
            &provider,
            Flow::Link { user, session },
            return_to,
            binding_cookie,
        )
        .await
    }

    async fn start(
        &self,
        ctx: &RequestContext,
        provider: &Provider,
        flow: Flow,
        return_to: Option<&str>,
        binding_cookie: Option<&str>,
    ) -> Result<WebStart, AuthError> {
        let (flow_name, user, session, options) = match flow {
            Flow::Login(options) => (FLOW_LOGIN, None, None, options),
            Flow::Link { user, session } => (
                FLOW_LINK,
                Some(user),
                Some(session),
                WebLoginOptions::default(),
            ),
        };
        self.rate_limit(actions::START, ctx, self.settings().start_per_ip)
            .await?;
        let return_to = self.validate_return_to(return_to)?;
        let endpoints = self.endpoints(provider).await?;

        let state = Self::token()?;
        let nonce = Self::token()?;
        let verifier = Self::token()?;
        let binding = match binding_cookie.and_then(|c| OpaqueToken::parse(c).ok()) {
            Some(existing) => existing,
            None => Self::token()?,
        };
        let id = OAuthStateId::generate();
        let now = self.now();
        let ttl = self.settings().config.state_ttl;
        let sealed = self
            .seal(
                "oauth_states",
                "pkce_verifier_ciphertext",
                id,
                verifier.expose().as_bytes(),
            )
            .await?;
        store::insert_state(
            &self.deps().pool,
            &NewState {
                id,
                provider: &provider.storage_id,
                flow: flow_name,
                state_hash: state.hash().as_bytes(),
                nonce_hash: nonce.hash().as_bytes(),
                pkce_verifier_ciphertext: Some(&sealed),
                user_id: user,
                return_to: Some(&return_to),
                client_kind: ClientKind::Web,
                binding_hash: Some(binding.hash().as_bytes()),
                created_at: now,
                expires_at: now + ttl,
                remember_me: options.remember_me,
                shared_device: options.shared_device,
                session_id: session,
            },
        )
        .await?;

        let mut url = endpoints.authorization.clone();
        {
            let redirect_uri = self.redirect_uri(provider)?;
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &provider.client_id)
                .append_pair("redirect_uri", redirect_uri.as_str())
                .append_pair("scope", &provider.scopes.join(" "))
                .append_pair("state", state.expose())
                .append_pair("code_challenge", &pkce_challenge(verifier.expose()))
                .append_pair("code_challenge_method", "S256");
            if provider.kind.is_oidc() {
                query.append_pair("nonce", nonce.expose());
            }
            if provider.kind == ProviderKind::Apple {
                query.append_pair("response_mode", "form_post");
            }
        }
        Ok(WebStart {
            authorization_url: url,
            binding,
            binding_max_age: ttl,
        })
    }

    /// Completes a browser flow (`GET`/`POST /v1/oauth/{provider}/callback`).
    /// Failures are audited (`login.failed`, no user).
    pub async fn web_callback(
        &self,
        ctx: &RequestContext,
        provider: &str,
        params: &CallbackParams,
        binding_cookie: Option<&str>,
    ) -> Result<CallbackResult, AuthError> {
        let result = self.callback(ctx, provider, params, binding_cookie).await;
        match &result {
            Ok(CallbackResult::Login { .. }) => crate::metrics::login(provider, "ok"),
            Ok(CallbackResult::Linked { .. }) => {}
            Err(err) => {
                self.record_failure(ctx, provider, ClientKind::Web, err)
                    .await;
            }
        }
        result
    }

    async fn callback(
        &self,
        ctx: &RequestContext,
        provider_slug: &str,
        params: &CallbackParams,
        binding_cookie: Option<&str>,
    ) -> Result<CallbackResult, AuthError> {
        let provider = self.provider(provider_slug)?.clone();
        // Before any database work or audit record: an anonymous caller
        // must not be able to run unlimited state lookups or grow the audit
        // chain with made-up `state` values (throttled requests are not
        // audited).
        self.rate_limit(actions::CALLBACK, ctx, self.settings().callback_per_ip)
            .await?;
        let state_invalid = || AuthError::new(codes::OAUTH_STATE_INVALID);
        let state = bounded(params.state.as_deref())
            .and_then(|s| OpaqueToken::parse(s).ok())
            .ok_or_else(state_invalid)?;
        let now = self.now();
        // Single use: consumed before anything else is checked.
        let row = store::consume_web_state(&self.deps().pool, state.hash().as_bytes(), now)
            .await?
            .ok_or_else(state_invalid)?;
        if row.provider != provider.storage_id {
            return Err(state_invalid());
        }
        let binding_ok = match (
            binding_cookie.and_then(|c| OpaqueToken::parse(c).ok()),
            row.binding_hash.as_deref().map(TokenHash::from_slice),
        ) {
            (Some(cookie), Some(Ok(stored))) => cookie.matches(&stored),
            _ => false,
        };
        if !binding_ok {
            tracing::info!("oauth callback without the browser binding");
            return Err(state_invalid());
        }
        if params.error.is_some() {
            return Err(AuthError::new(codes::OAUTH_AUTHORIZATION_DENIED));
        }
        let code = bounded(params.code.as_deref()).ok_or_else(|| invalid("missing code"))?;
        let sealed = row
            .pkce_verifier_ciphertext
            .as_deref()
            .ok_or_else(|| AuthError::internal("web state without PKCE verifier"))?;
        let verifier = self
            .open("oauth_states", "pkce_verifier_ciphertext", row.id, sealed)
            .await?;
        let verifier = Zeroizing::new(
            std::str::from_utf8(verifier.expose())
                .map_err(|_| AuthError::internal("corrupt PKCE verifier"))?
                .to_owned(),
        );

        let endpoints = self.endpoints(&provider).await?;
        let (id_token, tokens) = self
            .exchange_code(&provider, &endpoints, code, &verifier)
            .await?;
        let mut external: ExternalIdentity = if provider.kind.is_oidc() {
            let id_token = id_token.ok_or_else(|| invalid("token response without id_token"))?;
            let claims = self
                .verify_id_token(
                    &provider,
                    &endpoints,
                    &id_token,
                    std::slice::from_ref(&provider.client_id),
                )
                .await?;
            let stored = TokenHash::from_slice(&row.nonce_hash)
                .map_err(|_| AuthError::internal("corrupt nonce hash"))?;
            let nonce_ok = claims
                .nonce
                .as_deref()
                .is_some_and(|n| TokenHash::digest(n.as_bytes()) == stored);
            if !nonce_ok {
                return Err(invalid("nonce mismatch"));
            }
            let first_login_name = if provider.kind == ProviderKind::Apple {
                crate::apple::display_name_from_user_field(params.user.as_deref())
            } else {
                None
            };
            identity::from_id_claims(&provider, claims, first_login_name)?
        } else {
            let access = tokens
                .as_ref()
                .map(|t| t.access_token.clone())
                .ok_or_else(|| invalid("token response without access_token"))?;
            identity::github_identity(
                self.deps().http.as_ref(),
                &provider,
                &endpoints,
                access.expose(),
            )
            .await?
        };
        external.tokens = tokens;

        let return_to = row.return_to.clone().unwrap_or_else(|| "/".to_owned());
        if row.flow == FLOW_LINK {
            let user = row
                .user_id
                .ok_or_else(|| AuthError::internal("link state without user"))?;
            // K-03: rows written before migration 2101 were removed by it;
            // a link row always names its session (CHECK constraint).
            let session = row
                .session_id
                .ok_or_else(|| AuthError::new(codes::OAUTH_STATE_INVALID))?;
            self.link_identity(ctx, user, Some(session), &external)
                .await?;
            return Ok(CallbackResult::Linked { return_to });
        }
        let outcome = self
            .login_with_identity(
                ctx,
                &external,
                ClientKind::Web,
                row.remember_me,
                row.shared_device,
            )
            .await?;
        Ok(CallbackResult::Login { outcome, return_to })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_02_callback_params_debug_redacts_code_and_state() {
        let params = CallbackParams {
            code: Some("secret-authorization-code".to_owned()),
            state: Some("secret-state-value".to_owned()),
            error: Some("access_denied".to_owned()),
            user: Some(r#"{"name":{"firstName":"Ada"}}"#.to_owned()),
        };
        let debug = format!("{params:?}");
        assert!(!debug.contains("secret-authorization-code"), "{debug}");
        assert!(!debug.contains("secret-state-value"), "{debug}");
        assert!(!debug.contains("Ada"), "{debug}");
    }
}
