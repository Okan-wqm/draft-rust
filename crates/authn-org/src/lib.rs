//! # authn-org
//!
//! Organizations (B2B tenants), memberships, RBAC, invitations, DNS domain
//! verification, organization security policies, API keys and service
//! accounts of `rust-authentication` (ORG-01 … ORG-12, ARC-10).
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`authz`] | ORG-03, ORG-04, ORG-07, ORG-10, ARC-10 | the single default-deny decision behind [`OrgService::authorize`] |
//! | [`permission`] | ORG-03, ORG-04 | the closed permission catalog, built-in roles |
//! | [`service`] | ORG-01 … ORG-12 | [`OrgService`]: every use case |
//! | [`api_key`] | ORG-08 | `ak_<env>_<base62>_<crc32>` generation and parsing |
//! | [`middleware`] | ORG-08 | [`api_key_middleware`]: API key → `Principal` |
//! | [`policy`] | ORG-07 | [`OrgPolicy`] model, validation, enforcement helpers |
//! | [`dns`] | ORG-06 | [`HickoryDnsTxtResolver`] (`DnsTxtResolver` port) |
//! | [`routes`] | ARC-03, ARC-09 | [`router`], [`OrgApi`] |
//! | [`export`] | ACC-10 | [`OrgDataExporter`] (`organizations` section) |
//! | [`validate`] | ORG-01, ORG-06 | slugs, display text (bidi / invisible characters), domains |
//! | [`model`] | — | response types |
//! | [`metrics`] | OPS-04 | metric names |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`OrgService`] via `FromRef<S>`.
//! * Side effects go through the ports of `authn_core::ports` (audit,
//!   events, notifier, rate limiter, session revoker, DNS); tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::org` and `codes::common`; resources of other
//!   organizations are always `404 not_found`.
#![forbid(unsafe_code)]

#[macro_use]
mod macros;

pub mod api_key;
pub mod authz;
pub mod dns;
pub mod export;
pub mod extract;
pub mod metrics;
pub mod middleware;
pub mod model;
pub mod permission;
pub mod policy;
pub mod routes;
pub mod service;
pub mod validate;

pub use api_key::{GeneratedApiKey, ParsedApiKey, parse_api_key};
pub use authz::{Authorization, AuthzSubject};
pub use dns::HickoryDnsTxtResolver;
pub use export::OrgDataExporter;
pub use middleware::{API_KEY_HEADER, api_key_middleware};
pub use permission::{BuiltinRole, Permission, PermissionSet};
pub use policy::{OrgPolicy, OrgPolicyInput};
pub use routes::{OrgApi, router};
pub use service::members::sole_owner_organizations;
pub use service::policies::{policies_for_user, policy_of};
pub use service::{OrgService, OrgServiceDeps, OrgServiceSettings, actor_of};
