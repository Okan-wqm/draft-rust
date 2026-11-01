//! Organization webhooks (AUD-07).
//!
//! * [`WebhookManager`] — endpoint CRUD, subscriptions, secret rotation,
//!   delivery history, manual redelivery.
//! * [`WebhookFanout`] — `domain_event` outbox handler creating deliveries.
//! * [`WebhookDeliverer`] — `webhook.delivery` outbox handler signing and
//!   sending through the SSRF-safe `HttpClient` port.
//! * [`validate_webhook_url`] — registration-time URL rules.

mod delivery;
mod endpoints;
mod fanout;
mod urls;

pub use delivery::{
    MAX_RESPONSE_BYTES, MAX_WEBHOOK_BODY_BYTES, WEBHOOK_DELIVERY_TOPIC, WEBHOOK_TOPIC_PREFIX,
    WEBHOOK_USER_AGENT, WebhookDeliverer, build_signed_request, signed_delivery_headers,
};
pub use endpoints::{
    ActingPrincipal, CreateWebhookEndpoint, MAX_DESCRIPTION_CHARS, MAX_EVENT_TYPES,
    UpdateWebhookEndpoint, WebhookDeliveryView, WebhookEndpointView, WebhookEndpointWithSecret,
    WebhookManager, rewrap_webhook_secrets, validate_event_types,
};
pub use fanout::{WebhookFanout, webhook_body};
pub use urls::{MAX_URL_LEN, is_public_ip, is_public_ipv4, is_public_ipv6, validate_webhook_url};
