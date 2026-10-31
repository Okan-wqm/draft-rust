//! Outbound HTTP with SSRF protection (PRT-12). Owner of this file:
//! authn-protect.
//!
//! Every outbound call (HIBP, OIDC providers, CAPTCHA, webhooks, SMS
//! providers) goes through this port so that timeouts, response-size limits
//! and — for user-supplied URLs — SSRF rules are enforced in one place:
//! * [`OutboundTarget::UserSupplied`] URLs must be `https` and must not
//!   resolve to private, loopback, link-local, CGNAT, multicast or cloud
//!   metadata ranges; the connection is pinned to the vetted IP (DNS
//!   rebinding), redirects are not followed.
//! * [`OutboundTarget::Trusted`] is for operator-configured endpoints.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

use crate::error::AuthError;

/// Performs outbound HTTP requests.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Executes a request; the body is read up to the size limit.
    async fn execute(&self, request: OutboundRequest) -> Result<OutboundResponse, AuthError>;
}

/// Trust level of the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundTarget {
    /// Operator-configured endpoint (still subject to timeouts / limits).
    Trusted,
    /// URL supplied by a tenant or user: full SSRF protection.
    UserSupplied,
}

/// An outbound request.
#[derive(Clone)]
pub struct OutboundRequest {
    /// Method.
    pub method: Method,
    /// Absolute URL.
    pub url: Url,
    /// Headers.
    pub headers: HeaderMap,
    /// Body bytes.
    pub body: Option<Vec<u8>>,
    /// Destination trust level.
    pub target: OutboundTarget,
    /// Per-request timeout override.
    pub timeout: Option<Duration>,
    /// Response-size limit override in bytes.
    pub max_response_bytes: Option<usize>,
}

impl OutboundRequest {
    /// A `GET` without body.
    #[must_use]
    pub fn get(url: Url, target: OutboundTarget) -> Self {
        Self {
            method: Method::GET,
            url,
            headers: HeaderMap::new(),
            body: None,
            target,
            timeout: None,
            max_response_bytes: None,
        }
    }

    /// A `POST` with a body.
    #[must_use]
    pub fn post(url: Url, body: Vec<u8>, target: OutboundTarget) -> Self {
        Self {
            method: Method::POST,
            url,
            headers: HeaderMap::new(),
            body: Some(body),
            target,
            timeout: None,
            max_response_bytes: None,
        }
    }
}

impl fmt::Debug for OutboundRequest {
    /// Header values and bodies may carry credentials: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut url = self.url.clone();
        url.set_query(None);
        url.set_fragment(None);
        let _ = url.set_password(None);
        let _ = url.set_username("");
        f.debug_struct("OutboundRequest")
            .field("method", &self.method)
            .field("url", &url.as_str())
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// A buffered outbound response.
#[derive(Clone)]
pub struct OutboundResponse {
    /// Status.
    pub status: StatusCode,
    /// Headers.
    pub headers: HeaderMap,
    /// Body (bounded).
    pub body: Vec<u8>,
}

impl fmt::Debug for OutboundResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prt_12_debug_never_prints_credentials() {
        let url = Url::parse("https://user:pw@example.com/hook?token=abc#frag").unwrap();
        let mut req =
            OutboundRequest::post(url, b"secret-body".to_vec(), OutboundTarget::UserSupplied);
        req.headers
            .insert("authorization", "Bearer s3cr3t".parse().unwrap());
        let debug = format!("{req:?}");
        for leaked in ["pw", "abc", "s3cr3t", "secret-body", "frag"] {
            assert!(!debug.contains(leaked), "{leaked} leaked in {debug}");
        }
        assert!(debug.contains("example.com/hook"));
    }
}
