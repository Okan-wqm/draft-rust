//! Generic HTTP SMS provider (NTF-04), through the `HttpClient` port.
//!
//! * `POST notify.sms.http_url` (https only) with a JSON body built from
//!   `notify.sms.http_body_template`. Placeholders (`{{to}}`, `{{text}}`,
//!   `{{sender_id}}`) are substituted **inside the parsed JSON tree** in a
//!   single pass and the tree is re-serialized: a message containing `"`,
//!   `\`, newlines or even `{{to}}` cannot break out of its string or
//!   inject fields.
//! * The API key goes into `http_auth_header` (default
//!   `authorization: Bearer …`), marked sensitive; it never appears in
//!   `Debug` output, logs or errors.
//! * The provider URL is operator-configured, so it is a
//!   `OutboundTarget::Trusted` request (timeouts and response-size limits
//!   still apply in `authn-protect`'s client).
//! * Responses: `2xx` → sent (provider message id taken from
//!   `http_message_id_pointer` when configured); `408`, `425`, `429`, `5xx`
//!   and transport errors → `service_unavailable` (retried, honouring a
//!   numeric `Retry-After` up to one hour); any other status →
//!   `delivery_rejected` (e.g. invalid number; not retried). Response
//!   bodies are never logged.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::notify::{
    SMS_PLACEHOLDER_SENDER_ID, SMS_PLACEHOLDER_TEXT, SMS_PLACEHOLDER_TO, SmsConfig,
};
use authn_core::error::{AuthError, codes};
use authn_core::ports::{
    HttpClient, OutboundRequest, OutboundTarget, SmsMessage, SmsReceipt, SmsSender,
};
use authn_core::secret::ExposeSecret;
use http::header::{ACCEPT, CONTENT_TYPE, RETRY_AFTER};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use super::is_valid_body;
use crate::error::NotifyError;

/// Largest provider response read.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
/// Longest provider message id kept.
const MAX_MESSAGE_ID_LEN: usize = 128;
/// Upper bound of a provider-requested retry delay.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// Sends SMS through a generic JSON-over-HTTPS provider API.
pub struct HttpSmsSender {
    http: Arc<dyn HttpClient>,
    url: Url,
    auth_header: HeaderName,
    auth_value: HeaderValue,
    body_template: Value,
    sender_id: String,
    message_id_pointer: Option<String>,
    timeout: Duration,
}

impl fmt::Debug for HttpSmsSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpSmsSender")
            .field("host", &self.url.host_str())
            .field("auth_header", &self.auth_header)
            .finish_non_exhaustive()
    }
}

/// Substitutes the placeholders of one template string in a single pass
/// (inserted values are never re-scanned).
fn substitute(template: &str, values: &[(&str, &str); 3]) -> String {
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    loop {
        let next = values
            .iter()
            .filter_map(|(placeholder, value)| {
                rest.find(placeholder)
                    .map(|position| (position, placeholder.len(), *value))
            })
            .min_by_key(|(position, _, _)| *position);
        let Some((position, length, value)) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(rest.get(..position).unwrap_or_default());
        out.push_str(value);
        rest = rest.get(position + length..).unwrap_or_default();
    }
}

/// Builds the request body by substituting inside the JSON tree.
fn render_body(template: &Value, values: &[(&str, &str); 3]) -> Value {
    match template {
        Value::String(s) => Value::String(substitute(s, values)),
        Value::Array(items) => Value::Array(items.iter().map(|v| render_body(v, values)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), render_body(v, values)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

fn message_id(body: &[u8], pointer: Option<&str>) -> Option<String> {
    let pointer = pointer?;
    let value: Value = serde_json::from_slice(body).ok()?;
    let id = match value.pointer(pointer)? {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    let printable = !id.is_empty()
        && id.len() <= MAX_MESSAGE_ID_LEN
        && id.bytes().all(|b| b.is_ascii_graphic());
    printable.then_some(id)
}

impl HttpSmsSender {
    /// Builds the sender from `[notify.sms]` (provider `http`).
    pub fn from_config(config: &SmsConfig, http: Arc<dyn HttpClient>) -> Result<Self, NotifyError> {
        let url = config
            .http_url
            .as_deref()
            .and_then(|u| Url::parse(u).ok())
            .filter(|u| u.scheme() == "https" && u.host_str().is_some())
            .ok_or_else(|| NotifyError::config("notify.sms.http_url must be an https URL"))?;
        let api_key = config
            .http_api_key
            .as_ref()
            .ok_or_else(|| NotifyError::config("notify.sms.http_api_key is required"))?;
        let auth_header = HeaderName::from_bytes(config.http_auth_header.as_bytes())
            .map_err(|_| NotifyError::config("notify.sms.http_auth_header is not a header name"))?;
        let raw = Zeroizing::new(if config.http_auth_scheme.is_empty() {
            api_key.expose_secret().to_owned()
        } else {
            format!("{} {}", config.http_auth_scheme, api_key.expose_secret())
        });
        let mut auth_value = HeaderValue::from_str(&raw).map_err(|_| {
            NotifyError::config(
                "notify.sms.http_api_key contains characters not allowed in a header",
            )
        })?;
        auth_value.set_sensitive(true);
        let body_template: Value = serde_json::from_str(&config.http_body_template)
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| {
                NotifyError::config("notify.sms.http_body_template must be a JSON object")
            })?;
        Ok(Self {
            http,
            url,
            auth_header,
            auth_value,
            body_template,
            sender_id: config.sender_id.clone().unwrap_or_default(),
            message_id_pointer: config.http_message_id_pointer.clone(),
            timeout: config.timeout,
        })
    }

    /// The JSON body for `message` (exposed for tests).
    #[must_use]
    pub fn request_body(&self, message: &SmsMessage) -> Value {
        render_body(
            &self.body_template,
            &[
                (SMS_PLACEHOLDER_TO, message.to.as_str()),
                (SMS_PLACEHOLDER_TEXT, message.body.expose()),
                (SMS_PLACEHOLDER_SENDER_ID, self.sender_id.as_str()),
            ],
        )
    }
}

#[async_trait]
impl SmsSender for HttpSmsSender {
    fn is_configured(&self) -> bool {
        true
    }

    async fn send(&self, message: &SmsMessage) -> Result<SmsReceipt, AuthError> {
        if !is_valid_body(message.body.expose()) {
            return Err(AuthError::new(codes::notify::DELIVERY_REJECTED)
                .with_context("SMS body is empty, too long or contains control characters"));
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&self.request_body(message))
                .map_err(|_| AuthError::internal("SMS request serialization failed"))?,
        );
        let mut request =
            OutboundRequest::post(self.url.clone(), body.to_vec(), OutboundTarget::Trusted);
        request
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        request
            .headers
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        request
            .headers
            .insert(self.auth_header.clone(), self.auth_value.clone());
        request.timeout = Some(self.timeout);
        request.max_response_bytes = Some(MAX_RESPONSE_BYTES);

        let response = self.http.execute(request).await.map_err(|err| {
            tracing::warn!(to = %message.to.masked(), code = err.code().code(), "SMS provider unreachable");
            AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("SMS provider request failed")
        })?;
        let status = response.status;
        if status.is_success() {
            return Ok(SmsReceipt {
                provider_message_id: message_id(&response.body, self.message_id_pointer.as_deref()),
            });
        }
        tracing::warn!(
            to = %message.to.masked(),
            status = status.as_u16(),
            "SMS provider refused the request"
        );
        let temporary = status.is_server_error()
            || matches!(
                status,
                StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
            );
        if temporary {
            let mut err = AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("SMS provider temporarily unavailable");
            if let Some(delay) = retry_after(&response.headers) {
                err = err.with_retry_after(delay);
            }
            Err(err)
        } else {
            Err(AuthError::new(codes::notify::DELIVERY_REJECTED)
                .with_context("SMS provider rejected the message"))
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const VALUES: [(&str, &str); 3] = [
        (SMS_PLACEHOLDER_TO, "+905551112233"),
        (SMS_PLACEHOLDER_TEXT, "a \"quoted\" {{to}} \\ text\n"),
        (SMS_PLACEHOLDER_SENDER_ID, "AUTHN"),
    ];

    #[test]
    fn ntf_04_placeholders_are_substituted_once_inside_json_strings() {
        let template: Value = serde_json::from_str(
            r#"{"to":"{{to}}","msg":{"body":"{{text}}","tags":["{{sender_id}}-x", 5, true]},"raw":"{{unknown}}"}"#,
        )
        .unwrap();
        let body = render_body(&template, &VALUES);
        assert_eq!(body["to"], "+905551112233");
        assert_eq!(body["msg"]["body"], "a \"quoted\" {{to}} \\ text\n");
        assert_eq!(body["msg"]["tags"][0], "AUTHN-x");
        assert_eq!(body["msg"]["tags"][1], 5);
        assert_eq!(body["raw"], "{{unknown}}");
        // The serialized body is valid JSON with exactly the template's keys.
        let text = serde_json::to_string(&body).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 3);
    }

    #[test]
    fn ntf_04_message_id_is_extracted_and_bounded() {
        assert_eq!(
            message_id(br#"{"data":{"id":"abc-123"}}"#, Some("/data/id")),
            Some("abc-123".to_owned())
        );
        assert_eq!(
            message_id(br#"{"id":42}"#, Some("/id")),
            Some("42".to_owned())
        );
        assert_eq!(message_id(br#"{"id":"a b"}"#, Some("/id")), None);
        assert_eq!(message_id(b"not json", Some("/id")), None);
        assert_eq!(message_id(br#"{"id":"x"}"#, None), None);
        let long = format!(r#"{{"id":"{}"}}"#, "a".repeat(200));
        assert_eq!(message_id(long.as_bytes(), Some("/id")), None);
    }

    proptest! {
        #[test]
        fn ntf_04_body_template_cannot_be_escaped(text in "\\PC{0,200}", to in "\\+[1-9][0-9]{7,14}") {
            let template: Value = serde_json::from_str(r#"{"to":"{{to}}","text":"{{text}}"}"#).unwrap();
            let body = render_body(&template, &[
                (SMS_PLACEHOLDER_TO, to.as_str()),
                (SMS_PLACEHOLDER_TEXT, text.as_str()),
                (SMS_PLACEHOLDER_SENDER_ID, ""),
            ]);
            let serialized = serde_json::to_string(&body).unwrap();
            let parsed: Value = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(parsed.as_object().unwrap().len(), 2);
            prop_assert_eq!(parsed["to"].as_str().unwrap(), to.as_str());
            prop_assert_eq!(parsed["text"].as_str().unwrap(), text.as_str());
        }
    }
}
