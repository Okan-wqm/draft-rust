//! The authentication middleware (OPS-02 slot 8: authentication → CSRF).
//!
//! Install it inside the request-context middleware and the protect layers:
//!
//! ```ignore
//! router.layer(axum::middleware::from_fn_with_state(session_service, authn_session::authenticate))
//! ```
//!
//! It **replaces** `authn_org::api_key_middleware` (do not install both:
//! the org middleware refuses a request that already carries a principal).
//!
//! Resolution, in order — exactly one credential decides who the caller is:
//!
//! 1. **API key** (`Authorization: Bearer ak_…` or `X-API-Key`): turned into
//!    a [`Principal`] only on organization routes
//!    (`authn_org::middleware::is_api_key_path`, `/v1/orgs/{org_id}[/…]`);
//!    elsewhere the request continues without a principal (endpoints such
//!    as introspection authenticate the key themselves). Ambiguous
//!    credential headers are `401`.
//! 2. **Bearer access token** (any other `Authorization: Bearer`): verified
//!    (CRY-09) and, by default, checked against its live session; a bad
//!    token is `401` with `WWW-Authenticate: Bearer error="invalid_token"`.
//!    The session cookie is ignored when an `Authorization` header is
//!    present (no CSRF exposure: browsers never attach it cross-site).
//! 3. **Session cookie** `__Host-authn_session`: for state-changing methods
//!    the CSRF checks run here (SES-04: `Origin` / `Sec-Fetch-Site` +
//!    `X-CSRF-Token`); a failure is `403 csrf_failed` and the handler never
//!    runs. An unknown / expired cookie simply yields no principal (the
//!    cookie is not cleared: a concurrent rotation may have replaced it).
//!
//! Finally, a **read-only impersonation** principal (ADM-04) may not use
//! any state-changing method except `POST /v1/logout` — enforced here for
//! every route of every module, on top of `Principal::require_writable`.
//!
//! The middleware never authenticates in handlers' place: it only inserts
//! the [`Principal`] (and [`CurrentSession`]) into the request extensions.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_org::middleware::{ApiKeyCredential, extract_api_key, is_api_key_path};
use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::cookies::{CookieValue, SESSION_COOKIE, read_cookie};
use crate::csrf::is_state_changing;
use crate::metrics;
use crate::model::CurrentSession;
use crate::service::{Authenticated, SessionService};

/// Path that a read-only impersonation may still `POST` to.
pub const LOGOUT_PATH: &str = "/v1/logout";

fn bearer_challenge(err: AuthError) -> Response {
    let mut response = err.into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

fn insert(request: &mut Request, authenticated: Authenticated) {
    request.extensions_mut().insert(authenticated.principal);
    request.extensions_mut().insert(authenticated.session);
}

/// The authentication middleware (see the module docs).
pub async fn authenticate(
    State(service): State<SessionService>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(ctx) = request.extensions().get::<RequestContext>().cloned() else {
        return AuthError::internal("request context middleware is not installed").into_response();
    };
    // Principals are produced here only: never trust one set earlier.
    request.extensions_mut().remove::<Principal>();
    request.extensions_mut().remove::<CurrentSession>();
    let state_changing = is_state_changing(request.method());

    if request.headers().get_all(AUTHORIZATION).iter().count() > 1 {
        return AuthError::new(codes::common::UNAUTHENTICATED)
            .with_context("several Authorization headers")
            .into_response();
    }
    match extract_api_key(request.headers()) {
        ApiKeyCredential::Ambiguous => {
            return AuthError::new(codes::common::UNAUTHENTICATED)
                .with_context("ambiguous credentials")
                .into_response();
        }
        ApiKeyCredential::Present(key) => {
            if is_api_key_path(request.uri().path()) {
                match service
                    .deps()
                    .orgs
                    .authenticate_api_key(&ctx, key.expose())
                    .await
                {
                    Ok(principal) => {
                        request.extensions_mut().insert(principal);
                    }
                    Err(err) => return err.into_response(),
                }
            }
            return next.run(request).await;
        }
        ApiKeyCredential::None => {}
    }

    if let Some(value) = request.headers().get(AUTHORIZATION) {
        let Ok(text) = value.to_str() else {
            return bearer_challenge(AuthError::new(codes::common::UNAUTHENTICATED));
        };
        if let Some(token) = bearer_token(text) {
            let token = token.to_owned();
            match service.authenticate_bearer(&token).await {
                Ok(authenticated) => insert(&mut request, authenticated),
                Err(err) if err.status().is_server_error() => return err.into_response(),
                Err(err) => return bearer_challenge(err),
            }
        }
        // Other schemes: no principal; the cookie is not consulted.
        return enforce_read_only(request, next, state_changing).await;
    }

    if let CookieValue::One(cookie) = read_cookie(request.headers(), SESSION_COOKIE) {
        match service.authenticate_cookie(&ctx, &cookie).await {
            Ok(Some(mut authenticated)) => {
                if state_changing {
                    let hash = authenticated
                        .session
                        .token_hash
                        .map(authn_crypto::token::TokenHash::from_bytes);
                    let verdict = match hash {
                        Some(hash) => service.csrf().verify_session_request(
                            request.headers(),
                            authenticated.session.record.id,
                            &hash,
                        ),
                        None => Err(AuthError::new(codes::session::CSRF_FAILED)),
                    };
                    if let Err(err) = verdict {
                        metrics::csrf_rejected();
                        tracing::info!(
                            session_id = %authenticated.session.record.id,
                            reason = err.context().unwrap_or_default(),
                            "csrf check failed"
                        );
                        return err.into_response();
                    }
                    authenticated.session.csrf_verified = true;
                }
                insert(&mut request, authenticated);
            }
            Ok(None) => {}
            Err(err) => return err.into_response(),
        }
    }
    enforce_read_only(request, next, state_changing).await
}

async fn enforce_read_only(request: Request, next: Next, state_changing: bool) -> Response {
    let read_only = request
        .extensions()
        .get::<Principal>()
        .and_then(|p| p.impersonation)
        .is_some_and(|i| i.read_only);
    if read_only && state_changing && request.uri().path() != LOGOUT_PATH {
        return AuthError::new(codes::common::FORBIDDEN)
            .with_context("read-only impersonation")
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ses_05_bearer_scheme_parsing() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer  abc "), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer "), None);
    }
}
