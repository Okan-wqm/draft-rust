//! OAuth 2.1 / OpenID Connect provider core (K-80; OIDP-01 … OIDP-13).
//!
//! The server acts as an authorization server and OpenID Provider for
//! registered third-party (and first-party) applications:
//!
//! * **Client registry** (staff-managed): confidential and public clients,
//!   secrets stored as SHA-256, exact redirect URIs (RFC 8252 loopback and
//!   private-use schemes for native apps), allowed scopes / grant types /
//!   resources, first-party consent skip ([`service`], [`redirect`]).
//! * **Authorization code + PKCE `S256` only** (no implicit, no ROPC, no
//!   `plain`), `state`, `nonce`, `prompt`, `max_age`, `acr_values`, RFC
//!   9207 `iss`; errors are redirected only to a validated redirect URI
//!   ([`request`]). Login and consent are *headless*: the provider hands
//!   the browser to the operator's page (`oidc_provider.interaction_url`),
//!   which uses the existing login API and then the interaction API.
//! * **Tokens**: single-use codes (replay revokes the grant), rotating
//!   refresh tokens with replay detection, RFC 9068 JWT access tokens
//!   (RFC 8707 audiences), ID tokens with `at_hash` / `nonce` / `auth_time`
//!   / `amr` / `acr` / `sid`, signed with the server's key set (CRY-09/10).
//! * **Discovery** (OIDC + RFC 8414), the shared JWKS, **UserInfo**, **RFC
//!   7009** revocation, **RFC 7662** introspection.
//! * **Revocation coupling** (OIDP-12): every grant is bound to the user
//!   session it was authorized in, so sign-out, "sign out everywhere",
//!   password reset, suspension, deletion and admin revocation end it.
//!
//! Wiring (authn-server): [`OidcProviderService::new`] with the
//! [`hooks::SessionLiveness`] and [`hooks::ClientAdminAuthorizer`]
//! adapters; [`routes::router`] behind the session middleware,
//! [`routes::protocol_router`] outside it; [`OidcProviderService::purge_expired`]
//! as a background job. Off by default (`oidc_provider.enabled`).

#![forbid(unsafe_code)]

pub mod claims;
pub mod cookies;
pub mod discovery;
pub mod error;
pub mod export;
pub mod hooks;
mod keys;
pub mod pkce;
pub mod redirect;
pub mod request;
pub mod routes;
pub mod service;
pub mod settings;
pub mod store;

pub use export::ProviderDataExporter;
pub use hooks::{
    ClientAdminAccess, ClientAdminAuthorizer, DenyClientAdmin, NoLiveSessions, SessionLiveness,
};
pub use routes::{OidcProviderApi, protocol_router, router};
pub use service::{OidcProviderDeps, OidcProviderService};
pub use settings::OidcProviderSettings;
