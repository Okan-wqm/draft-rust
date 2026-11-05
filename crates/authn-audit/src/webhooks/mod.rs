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

/// SQL assignments that redact a delivery whose subject's account was
/// erased (`subject_erased_at` set) once it finishes (`status` expression
/// is `'succeeded'` or `'dead'`): the payload keeps only the event id,
/// type, timestamp and organization (K-58, AUD-05, ACC-09). Arguments: the
/// SQL expression of the new status and of "now".
macro_rules! redact_if_erased {
    ($status:literal, $now:literal) => {
        concat!(
            "payload = CASE WHEN subject_erased_at IS NOT NULL AND ",
            $status,
            " IN ('succeeded', 'dead') THEN ",
            "jsonb_build_object('id', payload -> 'id', 'type', payload -> 'type', \
             'timestamp', payload -> 'timestamp', 'organization_id', payload -> 'organization_id', \
             'redacted', true) ELSE payload END, ",
            "redacted_at = CASE WHEN subject_erased_at IS NOT NULL AND ",
            $status,
            " IN ('succeeded', 'dead') THEN coalesce(redacted_at, ",
            $now,
            ") ELSE redacted_at END, ",
            "subject_user_id = CASE WHEN subject_erased_at IS NOT NULL AND ",
            $status,
            " IN ('succeeded', 'dead') THEN NULL ELSE subject_user_id END"
        )
    };
}
pub(crate) use redact_if_erased;
