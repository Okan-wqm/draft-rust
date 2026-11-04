//! [`OidcClientService`]: every social-login use case.
//!
//! | Method | Requirement | Caller |
//! |--------|-------------|--------|
//! | [`OidcClientService::providers`] | SOC-01 | `GET /v1/oauth/providers` |
//! | [`OidcClientService::start_web_login`] | SOC-02 | `GET /v1/oauth/{provider}/start` |
//! | [`OidcClientService::web_callback`] | SOC-02, SOC-03, SOC-05, SOC-07, SOC-08, SOC-09 | `GET`/`POST /v1/oauth/{provider}/callback` |
//! | [`OidcClientService::issue_native_nonce`] | SOC-04 | `POST /v1/oauth/nonce` |
//! | [`OidcClientService::native_login`] | SOC-03, SOC-04, SOC-05, SOC-09 | `POST /v1/oauth/{provider}/native` |
//! | [`OidcClientService::list_identities`] | SOC-06 | `GET /v1/me/identities` |
//! | [`OidcClientService::start_web_link`] / [`OidcClientService::native_link`] | SOC-06 | `POST /v1/me/identities/link[/native]` |
//! | [`OidcClientService::unlink`] | SOC-06, PWD-11 | `DELETE /v1/me/identities/{identity_id}` |
//! | [`OidcClientService::stored_provider_tokens`] | SOC-08 | server / applications |
//! | [`OidcClientService::linked_identity_count_in`] | PWD-11, PKY-04 | authn-server (`LoginMethodInventory` / `AccountMethodsSource` adapters of other modules) |
//! | [`OidcClientService::purge_expired_states`] | OPS-06 | authn-server background job |
//! | [`OidcClientService::process_token_revocations`] | SOC-07, ACC-09 (K-35) | authn-server background job |
//! | [`OidcClientService::erasure_hook`] | ACC-09 (K-35) | authn-server: `AccountService::register_erasure_hook` |
//!
//! Sessions are never created here: a verified identity becomes a
//! `PrimaryAuthentication { method: Social, amr: [fed] }` for the
//! `SessionIssuer` port (authn-session), which runs account status, risk,
//! organization and MFA policy and returns a session **or a challenge**
//! (SOC-09). The provider's MFA claim is forwarded only when
//! `oidc_client.trust_provider_mfa` is on.

mod accounts;
mod native;
mod revocation;
mod web;

use std::sync::Arc;

use authn_account::AccountService;
use authn_core::domain::{ClientKind, Principal};
use authn_core::error::{AuthError, codes as common_codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, AuditSink, Clock, EventPublisher, HttpClient, Notifier, RateLimitKey, RateLimitPolicy,
    RateLimiter, SecurityEvent, SecurityEventKind, SessionIssuer,
};
use authn_core::secret::ExposeSecret as _;
use authn_crypto::envelope::{EnvelopeCipher, EnvelopeContext};
use authn_crypto::token::OpaqueToken;
use authn_protect::web::{RedirectTarget, RedirectValidator};
use serde::Deserialize;
use sqlx::PgPool;
use time::OffsetDateTime;
use url::Url;

pub use self::accounts::{IdentitySummary, StoredProviderTokens};
pub use self::native::{NativeLoginRequest, NativeNonce};
pub use self::revocation::{
    MAX_REVOCATION_ATTEMPTS, ProviderTokenErasureHook, RevocationReport, revocation_backoff,
};
pub use self::web::{CallbackParams, CallbackResult, WebLoginOptions, WebStart};
use crate::codes;
use crate::discovery::DiscoveryCache;
use crate::hooks::{LoginMethodInventory, SessionLiveness};
use crate::id_token::{self, Expectations, IdClaims, invalid};
use crate::identity::ProviderTokens;
use crate::jwks::JwksCache;
use crate::outbound;
use crate::provider::{
    ClientCredential, EndpointSource, Endpoints, Provider, ProviderRegistry, TokenAuthMethod,
};
use crate::settings::OidcClientSettings;

/// Rate-limit action names (`RateLimitKey::action`).
pub mod actions {
    /// Web flow starts (login and link), per client IP.
    pub const START: &str = "oauth_start";
    /// Native nonces and native logins / links, per client IP.
    pub const NATIVE: &str = "oauth_native";
    /// Web callbacks (`GET`/`POST /v1/oauth/{provider}/callback`), per
    /// client IP — checked before the state lookup.
    pub const CALLBACK: &str = "oauth_callback";
}

/// Ports and services the social-login service needs.
#[derive(Clone)]
pub struct OidcClientServiceDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Outbound HTTP — authn-protect's `SsrfSafeHttpClient` in production.
    pub http: Arc<dyn HttpClient>,
    /// Envelope encryption (PKCE verifiers, stored provider tokens).
    pub envelopes: EnvelopeCipher,
    /// Rate limiter.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Security audit.
    pub audit: Arc<dyn AuditSink>,
    /// Domain events (outbox) — `user.created` for accounts created here.
    pub events: Arc<dyn EventPublisher>,
    /// The login pipeline (authn-session's `SessionService`).
    pub sessions: Arc<dyn SessionIssuer>,
    /// authn-account: account provisioning with the ACC-07 reservation
    /// check (K-02, K-33), mailbox proofs for provider-verified addresses
    /// (`confirm_mailbox_control_in_tx`, ADR 0002), notice recipients.
    pub accounts: AccountService,
    /// Other login methods (SOC-06 last-method rule).
    pub login_methods: Arc<dyn LoginMethodInventory>,
    /// Whether the session that started a link flow is still valid (K-03;
    /// authn-session through authn-server).
    pub session_liveness: Arc<dyn SessionLiveness>,
    /// Security notices (identity linked / unlinked, K-18) — authn-notify's
    /// outbox notifier, used in the link / unlink transactions.
    pub notifier: Arc<dyn Notifier>,
}

struct Inner {
    deps: OidcClientServiceDeps,
    settings: OidcClientSettings,
    registry: ProviderRegistry,
    redirects: RedirectValidator,
    jwks: JwksCache,
    discovery: DiscoveryCache,
    /// Validated absolute target for failed web callbacks (K-36).
    error_redirect: Option<Url>,
}

/// The social-login service. Cheap to clone; handlers obtain it through
/// `FromRef` (see [`crate::router`]).
#[derive(Clone)]
pub struct OidcClientService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for OidcClientService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClientService")
            .field(
                "providers",
                &self
                    .inner
                    .registry
                    .iter()
                    .map(|p| p.slug.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// A provider as listed for login buttons.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ProviderInfo {
    /// Route segment (`/v1/oauth/{provider}/…`).
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Whether `POST /v1/oauth/{provider}/native` is available.
    pub native: bool,
}

/// Token-endpoint answer.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    error: Option<String>,
}

impl OidcClientService {
    /// Builds the service at start-up: decrypts an envelope-encrypted
    /// Apple key (`oidc_client.apple.private_key_ciphertext`, K-34) with
    /// the deps' envelope cipher, then [`OidcClientService::new`]. The
    /// server uses this constructor.
    pub async fn build(
        deps: OidcClientServiceDeps,
        mut settings: OidcClientSettings,
    ) -> Result<Self, AuthError> {
        if let Some(apple) = settings.config.apple.as_mut() {
            crate::apple::resolve_private_key(apple, &deps.envelopes).await?;
        }
        Self::new(deps, settings)
    }

    /// Builds the service and its provider registry from the settings
    /// (an envelope-encrypted Apple key must have been decrypted: use
    /// [`OidcClientService::build`]).
    pub fn new(
        deps: OidcClientServiceDeps,
        settings: OidcClientSettings,
    ) -> Result<Self, AuthError> {
        let registry = ProviderRegistry::from_settings(&settings)?;
        Self::with_registry(deps, settings, registry)
    }

    /// Builds the service with an explicit registry (tests against fake
    /// providers: [`ProviderRegistry::override_endpoints`]). Fails fast
    /// when `oidc_client.error_redirect` is not an allowed redirect target
    /// (K-36).
    pub fn with_registry(
        deps: OidcClientServiceDeps,
        settings: OidcClientSettings,
        registry: ProviderRegistry,
    ) -> Result<Self, AuthError> {
        authn_core::tls::install_crypto_provider();
        let redirects = RedirectValidator::new(
            settings.redirect_allow_list.clone(),
            settings.public_base_url.clone(),
        );
        let error_redirect =
            match settings.config.error_redirect.as_deref() {
                None => None,
                Some(target) => {
                    let absolute = absolute_redirect(&redirects, &settings.public_base_url, target)
                        .map_err(|_| {
                            AuthError::internal(
                                "oidc_client.error_redirect is not an allowed redirect target \
                             (same-origin path or protect.redirect_allow_list / \
                             oidc_client.allowed_return_to entry)",
                            )
                        })?;
                    Some(Url::parse(&absolute).map_err(|_| {
                        AuthError::internal("oidc_client.error_redirect is not a URL")
                    })?)
                }
            };
        let jwks = JwksCache::new(
            settings.config.jwks_cache_ttl,
            settings.jwks_refresh_min_interval,
        );
        let discovery = DiscoveryCache::new(settings.config.jwks_cache_ttl);
        Ok(Self {
            inner: Arc::new(Inner {
                deps,
                settings,
                registry,
                redirects,
                jwks,
                discovery,
                error_redirect,
            }),
        })
    }

    /// Where to send the browser after a failed web callback (K-36):
    /// the configured, start-up-validated target with `error=<code>`
    /// appended (only the stable error code, never details). `None` when
    /// not configured — the error is answered as JSON.
    #[must_use]
    pub fn error_redirect_location(&self, err: &AuthError) -> Option<String> {
        let mut url = self.inner.error_redirect.clone()?;
        url.query_pairs_mut()
            .append_pair("error", err.code().code());
        Some(url.into())
    }

    pub(crate) fn deps(&self) -> &OidcClientServiceDeps {
        &self.inner.deps
    }

    pub(crate) fn settings(&self) -> &OidcClientSettings {
        &self.inner.settings
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    /// Every enabled provider (SOC-01).
    #[must_use]
    pub fn providers(&self) -> Vec<ProviderInfo> {
        self.inner
            .registry
            .iter()
            .map(|p| ProviderInfo {
                id: p.slug.clone(),
                display_name: p.display_name.clone(),
                native: p.supports_native(),
            })
            .collect()
    }

    /// The provider whose storage id (`identities.provider`) is `id`.
    pub(crate) fn provider_by_storage_id(&self, id: &str) -> Option<&Provider> {
        self.inner.registry.by_storage_id(id)
    }

    pub(crate) fn provider(&self, slug: &str) -> Result<&Provider, AuthError> {
        self.inner
            .registry
            .get(slug)
            .ok_or_else(|| AuthError::new(codes::OAUTH_PROVIDER_UNKNOWN))
    }

    pub(crate) async fn rate_limit(
        &self,
        action: &'static str,
        ctx: &RequestContext,
        policy: RateLimitPolicy,
    ) -> Result<(), AuthError> {
        self.inner
            .deps
            .rate_limiter
            .check(&RateLimitKey::ip(action, ctx.client_ip), policy, 1)
            .await?
            .into_result()
            .map(|_| ())
    }

    /// The step-up guard of linking and unlinking (SES-13, SOC-06).
    pub(crate) fn require_step_up(&self, principal: &Principal) -> Result<UserId, AuthError> {
        principal.require_writable()?;
        if principal.session_id().is_none() {
            return Err(AuthError::new(common_codes::common::FORBIDDEN));
        }
        let user = principal.require_user()?;
        principal.require_recent_authentication(self.now(), self.inner.settings.step_up_max_age)?;
        Ok(user)
    }

    /// Validates a `return_to` (PRT-10) and returns the absolute target.
    pub(crate) fn validate_return_to(&self, value: Option<&str>) -> Result<String, AuthError> {
        match value {
            None | Some("") => absolute_redirect(
                &self.inner.redirects,
                &self.inner.settings.public_base_url,
                "/",
            ),
            Some(v) => absolute_redirect(
                &self.inner.redirects,
                &self.inner.settings.public_base_url,
                v,
            ),
        }
    }

    /// `redirect_uri` of `provider`, built from `server.public_base_url`.
    pub(crate) fn redirect_uri(&self, provider: &Provider) -> Result<Url, AuthError> {
        let base = self
            .inner
            .settings
            .public_base_url
            .as_str()
            .trim_end_matches('/');
        Url::parse(&format!("{base}/v1/oauth/{}/callback", provider.slug))
            .map_err(|_| AuthError::internal("cannot build redirect_uri"))
    }

    /// The provider's endpoints (discovery for generic providers).
    pub(crate) async fn endpoints(&self, provider: &Provider) -> Result<Endpoints, AuthError> {
        match &provider.endpoints {
            EndpointSource::Static(endpoints) => Ok(endpoints.as_ref().clone()),
            EndpointSource::Discovery { issuer } => {
                self.inner
                    .discovery
                    .endpoints(self.inner.deps.http.as_ref(), issuer, self.now())
                    .await
            }
        }
    }

    /// Verifies an ID token of `provider` for one of `audiences` (SOC-03).
    /// The nonce is compared by the caller.
    pub(crate) async fn verify_id_token(
        &self,
        provider: &Provider,
        endpoints: &Endpoints,
        token: &str,
        audiences: &[String],
    ) -> Result<IdClaims, AuthError> {
        let parsed = id_token::parse(token)?;
        let jwks_url = endpoints
            .jwks
            .as_ref()
            .ok_or_else(|| AuthError::internal("OIDC provider without JWKS"))?;
        let now = self.now();
        let key = self
            .inner
            .jwks
            .key(
                self.inner.deps.http.as_ref(),
                jwks_url,
                endpoints.target,
                &parsed.kid,
                now,
            )
            .await?
            .ok_or_else(|| invalid("unknown kid"))?;
        let claims = parsed.verify(&key)?;
        id_token::validate(
            &claims,
            &Expectations {
                issuer: &provider.issuer,
                audiences,
                now,
                leeway: self.inner.settings.jwt_leeway,
            },
        )
    }

    /// Authorization-code exchange with PKCE (SOC-02).
    async fn exchange_code(
        &self,
        provider: &Provider,
        endpoints: &Endpoints,
        code: &str,
        verifier: &str,
    ) -> Result<(Option<String>, Option<ProviderTokens>), AuthError> {
        let redirect_uri = self.redirect_uri(provider)?;
        let form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier),
        ];
        self.token_request(provider, endpoints, &provider.client_id, form)
            .await
    }

    /// The client secret of `provider` for `client_id` (Apple: an ES256 JWT
    /// whose `sub` is that client id, K-35).
    pub(crate) fn client_secret(
        &self,
        provider: &Provider,
        client_id: &str,
    ) -> Result<authn_core::secret::SensitiveString, AuthError> {
        match &provider.credential {
            ClientCredential::Secret(s) => {
                Ok(authn_core::secret::SensitiveString::new(s.expose_secret()))
            }
            ClientCredential::Apple(apple) => apple.current_for(client_id, self.now()),
        }
    }

    /// A token-endpoint request authenticated as `client_id`; returns the
    /// ID token and the provider tokens of the answer.
    pub(crate) async fn token_request(
        &self,
        provider: &Provider,
        endpoints: &Endpoints,
        client_id: &str,
        mut form: Vec<(&str, &str)>,
    ) -> Result<(Option<String>, Option<ProviderTokens>), AuthError> {
        let secret = self.client_secret(provider, client_id)?;
        let basic = match endpoints.token_auth {
            TokenAuthMethod::ClientSecretPost => {
                form.push(("client_id", client_id));
                form.push(("client_secret", secret.expose()));
                None
            }
            TokenAuthMethod::ClientSecretBasic => Some((client_id, secret.expose())),
        };
        let response = outbound::post_form(
            self.inner.deps.http.as_ref(),
            endpoints.token.clone(),
            endpoints.target,
            &form,
            basic,
        )
        .await?;
        if response.status.is_client_error() {
            return Err(invalid("code exchange refused"));
        }
        let body: TokenResponse = response.json("token response")?;
        if body.error.is_some() {
            // GitHub answers 200 with an `error` member.
            return Err(invalid("code exchange refused"));
        }
        let now = self.now();
        let tokens = body.access_token.map(|access| ProviderTokens {
            access_token: authn_core::secret::SensitiveString::new(access),
            refresh_token: body
                .refresh_token
                .map(authn_core::secret::SensitiveString::new),
            expires_at: body
                .expires_in
                .filter(|s| *s > 0 && *s < 10 * 365 * 86_400)
                .map(|s| now + time::Duration::seconds(s)),
        });
        Ok((body.id_token, tokens))
    }

    /// Seals a secret for `table.column` of row `row` (CRY-08, AAD).
    pub(crate) async fn seal(
        &self,
        table: &'static str,
        column: &'static str,
        row: impl std::fmt::Display,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        let context = EnvelopeContext::new(table, column, row)?;
        Ok(self.inner.deps.envelopes.seal(plaintext, &context).await?)
    }

    /// Opens a secret sealed by [`OidcClientService::seal`].
    pub(crate) async fn open(
        &self,
        table: &'static str,
        column: &'static str,
        row: impl std::fmt::Display,
        envelope: &[u8],
    ) -> Result<authn_crypto::secret::SecretBytes, AuthError> {
        let context = EnvelopeContext::new(table, column, row)?;
        Ok(self.inner.deps.envelopes.open(envelope, &context).await?)
    }

    /// Records a failed social login (own transaction; no user, no
    /// secrets).
    pub(crate) async fn record_failure(
        &self,
        ctx: &RequestContext,
        provider: &str,
        client: ClientKind,
        err: &AuthError,
    ) {
        // Requests that never reached a provider flow (throttled, unknown
        // provider) are not audited: anonymous callers must not be able to
        // grow the audit chain at will.
        if err.is(common_codes::common::RATE_LIMITED)
            || err.is(codes::OAUTH_PROVIDER_UNKNOWN)
            || err.is(codes::OAUTH_NATIVE_NOT_SUPPORTED)
        {
            return;
        }
        let event = SecurityEvent::new(SecurityEventKind::LoginFailed, self.now())
            .with_context(ctx)
            .with_actor(Actor::Anonymous)
            .failed(err.code().code())
            .with_meta("method", "social")
            .with_meta("provider", provider.to_owned())
            .with_meta("client", client.as_str());
        if let Err(audit_err) = self.inner.deps.audit.record(event).await {
            tracing::warn!(
                code = audit_err.code().code(),
                "failed to audit social login failure"
            );
        }
        crate::metrics::login(provider, err.code().code());
    }

    /// A fresh 256-bit token (state, nonce, binding, PKCE verifier).
    pub(crate) fn token() -> Result<OpaqueToken, AuthError> {
        Ok(OpaqueToken::generate()?)
    }
}

/// Validates a redirect target with authn-protect's validator (PRT-10:
/// same-origin path or an exact allow-list entry) and returns it absolute
/// (relative paths are joined to `server.public_base_url`).
fn absolute_redirect(
    redirects: &RedirectValidator,
    base: &Url,
    value: &str,
) -> Result<String, AuthError> {
    let absolute = match redirects.validate(value)? {
        RedirectTarget::Absolute(url) => url,
        RedirectTarget::Relative(path) => base
            .join(&path)
            .map(|u| u.to_string())
            .map_err(|_| AuthError::internal("cannot resolve return_to"))?,
    };
    // `oauth_states.return_to` holds at most 2048 characters.
    if absolute.len() > authn_protect::web::MAX_REDIRECT_LEN {
        return Err(AuthError::new(common_codes::protect::INVALID_REDIRECT));
    }
    Ok(absolute)
}

/// `BASE64URL(SHA-256(verifier))` (RFC 7636 S256).
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(authn_crypto::sha256(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_02_pkce_s256_known_answer() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
