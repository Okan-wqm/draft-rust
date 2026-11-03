//! A browser and native-app client for the login endpoints.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use authn_crypto::token::OpaqueToken;
use authn_session::cookies::{PRE_SESSION_COOKIE, SESSION_COOKIE};
use authn_testkit::http::{TestRequest, TestResponse};
use serde_json::Value;

use super::{Harness, ORIGIN};

/// A browser: keeps its cookies and the login-CSRF token.
pub struct Browser {
    pub cookies: BTreeMap<String, String>,
    pub csrf: String,
    pub device: String,
}

impl Browser {
    pub fn new(h: &Harness) -> Self {
        Self::with_device(h, &format!("device-{}", uuid::Uuid::now_v7().simple()))
    }

    pub fn with_device(h: &Harness, device: &str) -> Self {
        let secret = OpaqueToken::generate().unwrap();
        let csrf = h.service.csrf().pre_session_token(&secret).unwrap();
        let mut cookies = BTreeMap::new();
        cookies.insert(PRE_SESSION_COOKIE.to_owned(), secret.expose().to_owned());
        cookies.insert(
            authn_core::http::DEVICE_ID_COOKIE.to_owned(),
            device.to_owned(),
        );
        Self {
            cookies,
            csrf,
            device: device.to_owned(),
        }
    }

    /// A fresh browser that has never received a device cookie.
    pub fn without_device(h: &Harness) -> Self {
        let mut browser = Self::new(h);
        browser.cookies.remove(authn_core::http::DEVICE_ID_COOKIE);
        browser.device = String::new();
        browser
    }

    pub fn post(&self, path: &str, body: &Value) -> TestRequest {
        let mut request = TestRequest::post(path)
            .json(body)
            .header("origin", ORIGIN)
            .header("x-csrf-token", &self.csrf);
        for (name, value) in &self.cookies {
            request = request.cookie(name, value);
        }
        request
    }

    pub fn get(&self, path: &str) -> TestRequest {
        let mut request = TestRequest::get(path);
        for (name, value) in &self.cookies {
            request = request.cookie(name, value);
        }
        request
    }

    /// Applies `Set-Cookie` headers (`Max-Age=0` deletes) and picks up the
    /// session CSRF token of an `authenticated` body.
    pub fn absorb(&mut self, response: &TestResponse) {
        for line in response.set_cookies() {
            let first = line.split(';').next().unwrap();
            let (name, value) = first.split_once('=').unwrap();
            if line.contains("Max-Age=0") || value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        if let Ok(body) = serde_json::from_slice::<Value>(&response.body)
            && let Some(csrf) = body.get("csrf_token").and_then(Value::as_str)
        {
            self.csrf = csrf.to_owned();
        }
    }

    pub async fn send(&mut self, h: &Harness, request: TestRequest) -> TestResponse {
        let response = h.send(request).await;
        self.absorb(&response);
        response
    }

    /// Signs out locally (drops the session cookie) and fetches a new
    /// login-CSRF token, keeping every other cookie (device id, trusted
    /// device).
    pub fn start_over(&mut self, h: &Harness) {
        self.cookies.remove(SESSION_COOKIE);
        let secret = OpaqueToken::generate().unwrap();
        self.csrf = h.service.csrf().pre_session_token(&secret).unwrap();
        self.cookies
            .insert(PRE_SESSION_COOKIE.to_owned(), secret.expose().to_owned());
    }

    pub fn has(&self, name: &str) -> bool {
        self.cookies.contains_key(name)
    }
}

pub fn native(path: &str, body: &Value) -> TestRequest {
    TestRequest::post(path)
        .json(body)
        .header("x-authn-client", "native")
}

pub fn native_challenge(path: &str, body: &Value, token: &str) -> TestRequest {
    native(path, body).header("x-authn-challenge", token)
}

pub fn status_of(response: &TestResponse) -> String {
    response.json::<Value>()["status"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}
