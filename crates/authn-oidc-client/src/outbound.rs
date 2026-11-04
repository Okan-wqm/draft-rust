//! Outbound calls to providers, always through the `HttpClient` port
//! (authn-protect's SSRF-safe client in production, PRT-12).
//!
//! Responses are size-limited; provider error bodies are never logged or
//! echoed (they may contain codes or tokens); transport failures become
//! `service_unavailable`.

use std::time::Duration;

use authn_core::error::{AuthError, codes};
use authn_core::ports::{HttpClient, OutboundRequest, OutboundTarget};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::de::DeserializeOwned;
use url::Url;

/// Largest provider response read (discovery, JWKS, tokens, API).
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Per-request timeout of provider calls.
pub const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);

fn unavailable(context: &'static str) -> AuthError {
    AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_context(context)
}

/// A buffered provider answer. `Debug` shows the status and the body size
/// only (token responses carry provider tokens).
pub struct ProviderResponse {
    /// Status.
    pub status: StatusCode,
    /// Body (≤ [`MAX_RESPONSE_BYTES`]).
    pub body: Vec<u8>,
}

impl std::fmt::Debug for ProviderResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl ProviderResponse {
    /// Parses a 2xx JSON body; anything else is `service_unavailable`.
    pub fn json<T: DeserializeOwned>(&self, what: &'static str) -> Result<T, AuthError> {
        if !self.status.is_success() {
            tracing::warn!(
                status = self.status.as_u16(),
                what,
                "provider answered an error"
            );
            return Err(unavailable(what));
        }
        serde_json::from_slice(&self.body).map_err(|_| {
            tracing::warn!(what, "provider answered malformed JSON");
            unavailable(what)
        })
    }
}

fn prepare(mut request: OutboundRequest) -> OutboundRequest {
    request.timeout = Some(PROVIDER_TIMEOUT);
    request.max_response_bytes = Some(MAX_RESPONSE_BYTES);
    request
        .headers
        .insert(ACCEPT, HeaderValue::from_static("application/json"));
    request
}

/// `GET url` with optional bearer token.
pub async fn get(
    http: &dyn HttpClient,
    url: Url,
    target: OutboundTarget,
    bearer: Option<&str>,
    accept: Option<&'static str>,
) -> Result<ProviderResponse, AuthError> {
    let host = url.host_str().unwrap_or_default().to_owned();
    let mut request = prepare(OutboundRequest::get(url, target));
    if let Some(accept) = accept {
        request
            .headers
            .insert(ACCEPT, HeaderValue::from_static(accept));
    }
    if let Some(token) = bearer {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| unavailable("provider token is not a header value"))?;
        request.headers.insert(AUTHORIZATION, value);
    }
    send(http, request, &host).await
}

/// `POST url` with an `application/x-www-form-urlencoded` body and optional
/// HTTP Basic client authentication (RFC 6749 §2.3.1: both parts are
/// form-urlencoded before base64).
pub async fn post_form(
    http: &dyn HttpClient,
    url: Url,
    target: OutboundTarget,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> Result<ProviderResponse, AuthError> {
    let host = url.host_str().unwrap_or_default().to_owned();
    // The serializer is not `Send`: finish it before any `.await`.
    let body = {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in form {
            serializer.append_pair(key, value);
        }
        secrecy::zeroize::Zeroizing::new(serializer.finish())
    };
    let mut request = prepare(OutboundRequest::post(url, body.as_bytes().to_vec(), target));
    request.headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    if let Some((id, secret)) = basic {
        let encode =
            |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
        let credentials =
            secrecy::zeroize::Zeroizing::new(format!("{}:{}", encode(id), encode(secret)));
        let value = HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(credentials.as_bytes())
        ))
        .map_err(|_| unavailable("client credentials are not a header value"))?;
        request.headers.insert(AUTHORIZATION, value);
    }
    send(http, request, &host).await
}

async fn send(
    http: &dyn HttpClient,
    request: OutboundRequest,
    host: &str,
) -> Result<ProviderResponse, AuthError> {
    match http.execute(request).await {
        Ok(response) => Ok(ProviderResponse {
            status: response.status,
            body: response.body,
        }),
        Err(err) => {
            tracing::warn!(host, code = err.code().code(), "provider request failed");
            Err(unavailable("provider request failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_08_provider_response_debug_redacts_the_body() {
        let response = ProviderResponse {
            status: StatusCode::OK,
            body: br#"{"access_token":"provider-secret-token"}"#.to_vec(),
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains("provider-secret-token"), "{debug}");
        // The body bytes must not be dumped either.
        assert!(!debug.contains("123, 34"), "{debug}");
    }
}
