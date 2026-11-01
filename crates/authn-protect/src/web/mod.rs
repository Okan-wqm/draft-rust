//! HTTP hardening for `authn-server` (PRT-07 … PRT-10).
//!
//! Middleware functions for `axum::middleware::from_fn_with_state`, in the
//! OPS-02 order (outermost first, all *inside* the authn-core request
//! context middleware):
//!
//! 1. [`validate_host`] with [`HostValidation`] (PRT-09)
//! 2. [`security_headers`] with [`SecurityHeaders`] (PRT-07)
//! 3. [`cors`] with [`CorsPolicy`] (PRT-08)
//! 4. [`crate::rate_limit::http_rate_limit`] (PRT-02 / PRT-04)
//!
//! [`RedirectValidator`] (PRT-10) is a plain service used by the flows that
//! accept `return_to` / `redirect_uri` (authn-session, authn-oidc-client).

mod cors;
mod headers;
mod host;
mod redirect;

pub use cors::{ALLOWED_HEADERS, ALLOWED_METHODS, CorsPolicy, EXPOSED_HEADERS, cors};
pub use headers::{CSP, SecurityHeaders, security_headers};
pub use host::{HostValidation, validate_host};
pub use redirect::{MAX_REDIRECT_LEN, RedirectTarget, RedirectValidator};
