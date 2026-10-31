use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{HttpClient, OutboundRequest, OutboundResponse};
use http::{HeaderMap, StatusCode};

use super::lock;

/// Outbound HTTP fake: canned responses keyed by `METHOD url` (query
/// included, fragment excluded); unknown requests fail with
/// `service_unavailable`. Every request is recorded.
#[derive(Debug, Default)]
pub struct FakeHttpClient {
    responses: Mutex<HashMap<String, (StatusCode, Vec<u8>)>>,
    requests: Mutex<Vec<OutboundRequest>>,
}

fn route_key(method: &http::Method, url: &url::Url) -> String {
    let mut url = url.clone();
    url.set_fragment(None);
    format!("{method} {url}")
}

impl FakeHttpClient {
    /// Registers a canned response.
    pub fn respond(
        &self,
        method: http::Method,
        url: &str,
        status: StatusCode,
        body: impl Into<Vec<u8>>,
    ) {
        let url = url::Url::parse(url).expect("valid URL in test setup");
        lock(&self.responses).insert(route_key(&method, &url), (status, body.into()));
    }

    /// Registers a canned JSON response.
    pub fn respond_json(
        &self,
        method: http::Method,
        url: &str,
        status: StatusCode,
        body: &serde_json::Value,
    ) {
        self.respond(method, url, status, body.to_string().into_bytes());
    }

    /// Requests sent so far.
    #[must_use]
    pub fn requests(&self) -> Vec<OutboundRequest> {
        lock(&self.requests).clone()
    }
}

#[async_trait]
impl HttpClient for FakeHttpClient {
    async fn execute(&self, request: OutboundRequest) -> Result<OutboundResponse, AuthError> {
        let key = route_key(&request.method, &request.url);
        lock(&self.requests).push(request);
        let canned = lock(&self.responses).get(&key).cloned();
        match canned {
            Some((status, body)) => Ok(OutboundResponse {
                status,
                headers: HeaderMap::new(),
                body,
            }),
            None => Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("no canned response")),
        }
    }
}
