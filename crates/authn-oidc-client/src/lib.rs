//! # authn-oidc-client
//!
//! Social login as an OIDC / OAuth 2.0 relying party: Google, Apple,
//! Microsoft (multi-tenant), GitHub and generic OIDC providers; browser and
//! native (mobile SDK) flows; account matching, linking and unlinking.
//!
//! Owned requirements: SOC-01 … SOC-09.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`service`] | SOC-02 … SOC-09 | [`OidcClientService`] — every use case |
//! | [`routes`] | ARC-03, ARC-09 | [`router`], [`OidcClientApi`] |
//! | [`provider`] | SOC-01, SOC-03 | [`ProviderRegistry`] — built-in endpoints, issuer rules (Microsoft tenant rule) |
//! | [`discovery`] | SOC-01 | generic-provider discovery (exact issuer match, cached) |
//! | [`jwks`] | SOC-03 | provider JWKS cache with rate-limited refresh on unknown `kid` |
//! | [`id_token`] | SOC-03, SOC-04 | JWS parsing (algorithm allow-list) and claim validation |
//! | [`identity`] | SOC-01, SOC-05 | provider identity normalization, GitHub `/user` + `/user/emails` |
//! | [`apple`] | SOC-07 | ES256 `client_secret` (`p256` 0.14 only), first-login name |
//! | [`cookies`] | SOC-02 | the browser-binding cookie |
//! | [`hooks`] | SOC-06 | [`LoginMethodInventory`], [`SessionLiveness`] — implemented by authn-server |
//! | [`export`] | ACC-10 | [`IdentityDataExporter`] — the `identities` export section |
//! | [`codes`] | ARC-08 | this crate's error codes |
//! | [`settings`] | ARC-07 | [`OidcClientSettings`] |
//! | [`metrics`] | OPS-04 | metric names |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`OidcClientService`] via `FromRef<S>`.
//! * Sessions are opened only through the `SessionIssuer` port (this crate
//!   must not depend on authn-session); every outbound request goes through
//!   the `HttpClient` port (SSRF-safe client).
//! * Signatures are verified by audited code (`openidconnect`'s JWK
//!   implementation for provider public keys, `p256` 0.14 for the Apple
//!   client secret); `openidconnect` / `oauth2` run without default
//!   features and without their HTTP clients.
//! * Errors are `authn_core::AuthError` with codes from [`codes`] and
//!   `authn_core::error::codes::common`.

#![forbid(unsafe_code)]

pub mod apple;
pub mod codes;
pub mod cookies;
pub mod discovery;
pub mod export;
pub mod hooks;
pub mod id_token;
pub mod identity;
pub mod jwks;
pub mod metrics;
pub mod provider;
pub mod routes;
pub mod service;
pub mod settings;

mod outbound;
mod store;

pub use export::IdentityDataExporter;
pub use hooks::{LoginMethodInventory, PasswordOnlyInventory, SessionLiveness};
pub use provider::{
    Endpoints, IssuerRule, ProviderKind, ProviderRegistry, TenantPolicy, TokenAuthMethod,
};
pub use routes::{OidcClientApi, router};
pub use service::{
    CallbackParams, CallbackResult, IdentitySummary, NativeLoginRequest, NativeNonce,
    OidcClientService, OidcClientServiceDeps, ProviderInfo, ProviderTokenErasureHook,
    RevocationReport, StoredProviderTokens, WebLoginOptions, WebStart,
};
pub use settings::OidcClientSettings;
