//! API key authentication middleware (ORG-08).
//!
//! Install after the request-context middleware and before the handlers:
//!
//! ```ignore
//! router.layer(axum::middleware::from_fn_with_state(org_service.clone(), authn_org::api_key_middleware))
//! ```
//!
//! * Credentials: `Authorization: Bearer ak_…` or `X-API-Key: ak_…`.
//!   Anything else passes through untouched (cookie sessions, JWTs are
//!   authn-session's).
//! * Ambiguity is refused: more than one `Authorization` / `X-API-Key`
//!   header, or both headers at once, is `401` — a proxy and the
//!   application must never disagree about who the caller is.
//! * A request that already carries a [`Principal`] (set by an earlier
//!   layer) but also presents an API key is refused as ambiguous.
//! * **Organization endpoints only:** an API key becomes a [`Principal`]
//!   only on `/v1/orgs/{org_id}[/…]` ([`is_api_key_path`]). On every other
//!   path the request passes through untouched (no principal from the key):
//!   a personal key acts as its user *inside its organization and within
//!   its scopes*, never on account-level endpoints such as `/v1/me/…` of
//!   other modules, which do not check scopes. Endpoints that authenticate
//!   API-key clients themselves (SES-10) call
//!   [`OrgService::authenticate_api_key`] directly.
//! * On success the [`Principal`] of the key is inserted into the request
//!   extensions; on failure the standard `401 unauthenticated` (or `429`)
//!   envelope is returned and the handler never runs.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::secret::SensitiveString;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName};

use crate::api_key::looks_like_api_key;
use crate::service::OrgService;

/// Header for API keys as an alternative to `Authorization: Bearer`.
pub const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");

/// Longest credential header value inspected (bytes).
const MAX_CREDENTIAL_BYTES: usize = 256;

/// Path prefix of the organization-scoped endpoints.
const ORG_PATH_PREFIX: &str = "/v1/orgs/";

/// Whether `path` is an organization-scoped endpoint
/// (`/v1/orgs/{org_id}` or `/v1/orgs/{org_id}/…`) — the only routes on which
/// [`api_key_middleware`] turns an API key into a [`Principal`]. Paths with
/// dot segments (also percent-encoded) are never accepted, so a proxy that
/// normalizes them cannot route an API key to another endpoint.
#[must_use]
pub fn is_api_key_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(ORG_PATH_PREFIX) else {
        return false;
    };
    let org_segment = rest.split('/').next().unwrap_or_default();
    !org_segment.is_empty() && rest.split('/').all(|segment| !is_dot_segment(segment))
}

/// `.` / `..`, also percent-encoded (`%2e`, `.%2E`, …).
fn is_dot_segment(segment: &str) -> bool {
    let decoded = segment.replace("%2e", ".").replace("%2E", ".");
    decoded == "." || decoded == ".."
}

/// Where a request presents an API key.
#[derive(Debug, PartialEq, Eq)]
pub enum ApiKeyCredential {
    /// No API key presented.
    None,
    /// One API key.
    Present(SensitiveString),
    /// Malformed / ambiguous credential headers.
    Ambiguous,
}

/// Extracts the API key of a request (see the module docs for the rules).
#[must_use]
pub fn extract_api_key(headers: &HeaderMap) -> ApiKeyCredential {
    let authorization: Vec<_> = headers.get_all(AUTHORIZATION).iter().collect();
    let api_key: Vec<_> = headers.get_all(API_KEY_HEADER).iter().collect();
    if authorization.len() > 1 || api_key.len() > 1 {
        return ApiKeyCredential::Ambiguous;
    }
    let from_authorization = authorization.first().and_then(|value| {
        let value = value.to_str().ok()?;
        let (scheme, token) = value.split_once(' ')?;
        (scheme.eq_ignore_ascii_case("bearer") && looks_like_api_key(token.trim()))
            .then(|| token.trim().to_owned())
    });
    let from_header = match api_key.first() {
        None => None,
        Some(value) => match value.to_str() {
            Ok(v) if v.len() <= MAX_CREDENTIAL_BYTES => Some(v.trim().to_owned()),
            _ => return ApiKeyCredential::Ambiguous,
        },
    };
    match (from_authorization, from_header) {
        (None, None) => {
            if authorization.is_empty() || api_key.is_empty() {
                ApiKeyCredential::None
            } else {
                ApiKeyCredential::Ambiguous
            }
        }
        (Some(key), None) => {
            if api_key.is_empty() {
                ApiKeyCredential::Present(SensitiveString::new(key))
            } else {
                ApiKeyCredential::Ambiguous
            }
        }
        (None, Some(key)) => {
            if authorization.is_empty() {
                ApiKeyCredential::Present(SensitiveString::new(key))
            } else {
                ApiKeyCredential::Ambiguous
            }
        }
        (Some(_), Some(_)) => ApiKeyCredential::Ambiguous,
    }
}

/// The middleware (`from_fn_with_state(OrgService, api_key_middleware)`).
pub async fn api_key_middleware(
    State(service): State<OrgService>,
    mut request: Request,
    next: Next,
) -> Response {
    let key = match extract_api_key(request.headers()) {
        ApiKeyCredential::None => return next.run(request).await,
        ApiKeyCredential::Ambiguous => {
            return AuthError::new(codes::common::UNAUTHENTICATED)
                .with_context("ambiguous credentials")
                .into_response();
        }
        ApiKeyCredential::Present(key) => key,
    };
    if !is_api_key_path(request.uri().path()) {
        // Not an organization endpoint: the key grants nothing here.
        return next.run(request).await;
    }
    if request.extensions().get::<Principal>().is_some() {
        return AuthError::new(codes::common::UNAUTHENTICATED)
            .with_context("api key presented on an already authenticated request")
            .into_response();
    }
    let Some(ctx) = request.extensions().get::<RequestContext>().cloned() else {
        return AuthError::internal("request context middleware is not installed").into_response();
    };
    match service.authenticate_api_key(&ctx, key.expose()).await {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(err) => err.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn org_08_credentials_are_extracted_unambiguously() {
        assert_eq!(extract_api_key(&headers(&[])), ApiKeyCredential::None);
        assert_eq!(
            extract_api_key(&headers(&[("authorization", "Bearer eyJhbGciOi.jwt")])),
            ApiKeyCredential::None
        );
        assert_eq!(
            extract_api_key(&headers(&[("authorization", "Bearer ak_live_x")])),
            ApiKeyCredential::Present(SensitiveString::new("ak_live_x"))
        );
        assert_eq!(
            extract_api_key(&headers(&[("x-api-key", "ak_live_x")])),
            ApiKeyCredential::Present(SensitiveString::new("ak_live_x"))
        );
        for ambiguous in [
            headers(&[
                ("authorization", "Bearer ak_a"),
                ("authorization", "Bearer ak_b"),
            ]),
            headers(&[("x-api-key", "ak_a"), ("x-api-key", "ak_b")]),
            headers(&[("authorization", "Bearer ak_a"), ("x-api-key", "ak_b")]),
            headers(&[("authorization", "Bearer jwt"), ("x-api-key", "ak_b")]),
            headers(&[("x-api-key", &"a".repeat(300))]),
        ] {
            assert_eq!(extract_api_key(&ambiguous), ApiKeyCredential::Ambiguous);
        }
    }

    #[test]
    fn org_08_api_keys_only_authenticate_organization_paths() {
        for ok in [
            "/v1/orgs/0190a1b2-0000-7000-8000-000000000001",
            "/v1/orgs/0190a1b2-0000-7000-8000-000000000001/members",
            "/v1/orgs/x/api-keys/y/rotate",
            "/v1/orgs/x/audit-events",
        ] {
            assert!(is_api_key_path(ok), "{ok}");
        }
        for refused in [
            "/v1/orgs",
            "/v1/orgs/",
            "/v1/orgs//members",
            "/v1/me",
            "/v1/me/profile",
            "/v1/me/security-events",
            "/v1/me/passkeys",
            "/v1/invitations/accept",
            "/v1/ownership-transfers/accept",
            "/v1/org-permissions",
            "/V1/orgs/x/members",
            "/v1/orgs/../me/profile",
            "/v1/orgs/x/../../me/profile",
            "/v1/orgs/%2e%2e/me/profile",
            "/v1/orgs/x/.%2E/.%2e/me",
            "/v1/orgs/./members",
            "/v1/orgsx/members",
            "",
        ] {
            assert!(!is_api_key_path(refused), "{refused}");
        }
    }
}
