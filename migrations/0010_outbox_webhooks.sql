-- 0010 transactional outbox and webhooks (AUD-06, AUD-07, NTF-03).
-- Owner: authn-audit (outbox worker + webhooks); authn-notify enqueues
-- `notification.*` topics through the same outbox.

CREATE TABLE outbox (
    id              uuid        PRIMARY KEY,
    -- e.g. notification.email, domain_event, webhook.delivery
    topic           text        NOT NULL,
    org_id          uuid,
    -- Non-secret payload.
    payload         jsonb       NOT NULL,
    -- Envelope-encrypted secret part (tokens, codes); wiped after delivery.
    sealed_payload  bytea,
    status          text        NOT NULL DEFAULT 'pending',
    attempts        integer     NOT NULL DEFAULT 0,
    max_attempts    integer     NOT NULL DEFAULT 10,
    available_at    timestamptz NOT NULL,
    -- Lease of a worker that claimed the message (FOR UPDATE SKIP LOCKED).
    locked_until    timestamptz,
    locked_by       text,
    -- Sanitized error text (never secrets or payload data).
    last_error      text,
    created_at      timestamptz NOT NULL,
    delivered_at    timestamptz,
    CONSTRAINT outbox_topic_check CHECK (
        topic ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND char_length(topic) <= 128),
    CONSTRAINT outbox_payload_check CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT outbox_status_check CHECK (status IN ('pending', 'processing', 'delivered', 'dead')),
    CONSTRAINT outbox_attempts_check CHECK (attempts >= 0 AND max_attempts BETWEEN 1 AND 100),
    CONSTRAINT outbox_last_error_check CHECK (char_length(last_error) <= 1000),
    CONSTRAINT outbox_delivered_check CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CONSTRAINT outbox_sealed_wiped_check CHECK (status <> 'delivered' OR sealed_payload IS NULL)
);
CREATE INDEX outbox_due_idx ON outbox (available_at) WHERE status IN ('pending', 'processing');
CREATE INDEX outbox_dead_idx ON outbox (created_at) WHERE status = 'dead';
CREATE INDEX outbox_delivered_idx ON outbox (delivered_at) WHERE status = 'delivered';

CREATE TABLE webhook_endpoints (
    id                          uuid        PRIMARY KEY,
    org_id                      uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    url                         text        NOT NULL,
    description                 text,
    event_types                 text[]      NOT NULL,
    status                      text        NOT NULL DEFAULT 'active',
    -- Standard Webhooks signing secret, envelope encrypted.
    secret_ciphertext           bytea       NOT NULL,
    -- Previous secret during rotation overlap.
    previous_secret_ciphertext  bytea,
    previous_secret_expires_at  timestamptz,
    consecutive_failures        integer     NOT NULL DEFAULT 0,
    disabled_reason             text,
    created_by                  uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at                  timestamptz NOT NULL,
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webhook_endpoints_url_check CHECK (url ~ '^https?://' AND char_length(url) <= 2048),
    CONSTRAINT webhook_endpoints_description_check CHECK (char_length(description) <= 500),
    CONSTRAINT webhook_endpoints_event_types_check CHECK (cardinality(event_types) BETWEEN 1 AND 64),
    CONSTRAINT webhook_endpoints_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT webhook_endpoints_previous_secret_check CHECK (
        (previous_secret_ciphertext IS NULL) = (previous_secret_expires_at IS NULL)),
    CONSTRAINT webhook_endpoints_failures_check CHECK (consecutive_failures >= 0),
    -- Target of the composite FK from webhook_deliveries (tenant isolation).
    CONSTRAINT webhook_endpoints_id_org_key UNIQUE (id, org_id)
);
CREATE INDEX webhook_endpoints_org_idx ON webhook_endpoints (org_id);
CREATE TRIGGER webhook_endpoints_touch BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

CREATE TABLE webhook_deliveries (
    id               uuid        PRIMARY KEY,
    endpoint_id      uuid        NOT NULL,
    org_id           uuid        NOT NULL,
    -- Domain event id = `webhook-id` header (idempotency for receivers).
    event_id         uuid        NOT NULL,
    event_type       text        NOT NULL,
    payload          jsonb       NOT NULL,
    status           text        NOT NULL DEFAULT 'pending',
    attempts         integer     NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz,
    last_attempt_at  timestamptz,
    response_status  integer,
    response_ms      integer,
    last_error       text,
    created_at       timestamptz NOT NULL,
    CONSTRAINT webhook_deliveries_endpoint_fk FOREIGN KEY (endpoint_id, org_id)
        REFERENCES webhook_endpoints (id, org_id) ON DELETE CASCADE,
    CONSTRAINT webhook_deliveries_event_type_check CHECK (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
    CONSTRAINT webhook_deliveries_payload_check CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT webhook_deliveries_status_check CHECK (status IN ('pending', 'succeeded', 'failed', 'dead')),
    CONSTRAINT webhook_deliveries_attempts_check CHECK (attempts >= 0),
    CONSTRAINT webhook_deliveries_response_check CHECK (response_status BETWEEN 100 AND 599),
    CONSTRAINT webhook_deliveries_last_error_check CHECK (char_length(last_error) <= 1000),
    CONSTRAINT webhook_deliveries_endpoint_event_key UNIQUE (endpoint_id, event_id)
);
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_attempt_at)
    WHERE status IN ('pending', 'failed');
CREATE INDEX webhook_deliveries_org_idx ON webhook_deliveries (org_id, created_at DESC);
