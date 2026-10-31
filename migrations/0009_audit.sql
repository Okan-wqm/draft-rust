-- 0009 tamper-evident audit log (AUD-01 ... AUD-05). Owner: authn-audit.
--
-- Design:
--   * audit_events is append-only (trigger below; plus the least-privilege
--     role recommendation in docs: the application role gets no UPDATE /
--     DELETE / TRUNCATE on it).
--   * hash chain: hash = SHA-256(prev_hash || canonical_json(event)), with
--     prev_hash of the first event = 32 zero bytes. Appends are serialized
--     by locking the single audit_chain_head row (SELECT ... FOR UPDATE).
--   * personal data is NOT part of the chained record: users appear only as
--     random pseudonyms (audit_subjects) and IP / user agent live in
--     audit_event_pii. The chained record holds pii_digest =
--     SHA-256(salt || canonical pii); deleting the PII row (account deletion,
--     AUD-05) therefore never breaks the chain.
--   * retention purge: the only allowed DELETE, inside a transaction that
--     first runs  SET LOCAL authn.audit_purge_before = '<timestamptz>'  and
--     records an audit_chain_checkpoints row for the new chain start.

-- user <-> pseudonym mapping. Deleting the user deletes the mapping (and
-- via cascade the PII rows), leaving only unlinkable pseudonyms.
CREATE TABLE audit_subjects (
    pseudonym   uuid        PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_subjects_user_key UNIQUE (user_id)
);

CREATE TABLE audit_events (
    seq                     bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id                      uuid        NOT NULL,
    occurred_at             timestamptz NOT NULL,
    recorded_at             timestamptz NOT NULL DEFAULT now(),
    kind                    text        NOT NULL,
    outcome                 text        NOT NULL,
    reason                  text,
    actor_type              text        NOT NULL,
    -- Pseudonym of the acting user (actor_type = 'user').
    actor_pseudonym         uuid,
    -- Id of the acting service account / API key (not personal data).
    actor_ref               uuid,
    impersonator_pseudonym  uuid,
    subject_pseudonym       uuid,
    org_id                  uuid,
    resource_type           text,
    resource_id             text,
    request_id              uuid,
    metadata                jsonb       NOT NULL DEFAULT '{}',
    pii_digest              bytea,
    prev_hash               bytea       NOT NULL,
    hash                    bytea       NOT NULL,
    CONSTRAINT audit_events_kind_check CHECK (
        kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND char_length(kind) <= 128),
    CONSTRAINT audit_events_outcome_check CHECK (outcome IN ('success', 'failure')),
    CONSTRAINT audit_events_reason_check CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT audit_events_actor_type_check CHECK (actor_type IN
        ('user', 'service_account', 'api_key', 'system', 'anonymous')),
    CONSTRAINT audit_events_actor_user_check CHECK ((actor_type = 'user') = (actor_pseudonym IS NOT NULL)),
    CONSTRAINT audit_events_actor_ref_check CHECK (
        (actor_type IN ('service_account', 'api_key')) = (actor_ref IS NOT NULL)),
    CONSTRAINT audit_events_resource_type_check CHECK (resource_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT audit_events_resource_id_check CHECK (char_length(resource_id) <= 128),
    CONSTRAINT audit_events_metadata_check CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT audit_events_pii_digest_check CHECK (octet_length(pii_digest) = 32),
    CONSTRAINT audit_events_prev_hash_check CHECK (octet_length(prev_hash) = 32),
    CONSTRAINT audit_events_hash_check CHECK (octet_length(hash) = 32),
    CONSTRAINT audit_events_id_key UNIQUE (id),
    CONSTRAINT audit_events_hash_key UNIQUE (hash)
);
CREATE INDEX audit_events_subject_idx ON audit_events (subject_pseudonym, occurred_at DESC)
    WHERE subject_pseudonym IS NOT NULL;
CREATE INDEX audit_events_actor_idx ON audit_events (actor_pseudonym, occurred_at DESC)
    WHERE actor_pseudonym IS NOT NULL;
CREATE INDEX audit_events_org_idx ON audit_events (org_id, occurred_at DESC) WHERE org_id IS NOT NULL;
CREATE INDEX audit_events_occurred_idx ON audit_events (occurred_at);

-- Personal data of an event (IP, user agent), deletable without touching
-- the chain.
CREATE TABLE audit_event_pii (
    event_id    uuid  PRIMARY KEY REFERENCES audit_events (id) ON DELETE CASCADE,
    -- Whose personal data this is; NULL for anonymous callers.
    pseudonym   uuid  REFERENCES audit_subjects (pseudonym) ON DELETE CASCADE,
    ip          inet,
    user_agent  text,
    salt        bytea NOT NULL,
    CONSTRAINT audit_event_pii_user_agent_check CHECK (char_length(user_agent) <= 512),
    CONSTRAINT audit_event_pii_salt_check CHECK (octet_length(salt) BETWEEN 16 AND 32)
);
CREATE INDEX audit_event_pii_pseudonym_idx ON audit_event_pii (pseudonym) WHERE pseudonym IS NOT NULL;

-- Single-row chain head used to serialize appends.
CREATE TABLE audit_chain_head (
    id          boolean     PRIMARY KEY DEFAULT true,
    last_seq    bigint      NOT NULL DEFAULT 0,
    last_hash   bytea       NOT NULL DEFAULT decode(repeat('00', 32), 'hex'),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_chain_head_singleton_check CHECK (id),
    CONSTRAINT audit_chain_head_hash_check CHECK (octet_length(last_hash) = 32)
);
INSERT INTO audit_chain_head DEFAULT VALUES;

-- Verified anchors: after a retention purge the verifier starts at the
-- latest checkpoint instead of the genesis hash.
CREATE TABLE audit_chain_checkpoints (
    seq         bigint      PRIMARY KEY,
    hash        bytea       NOT NULL,
    reason      text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_chain_checkpoints_hash_check CHECK (octet_length(hash) = 32),
    CONSTRAINT audit_chain_checkpoints_reason_check CHECK (reason IN ('retention_purge', 'manual'))
);

CREATE FUNCTION authn_audit_events_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    purge_before text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        purge_before := current_setting('authn.audit_purge_before', true);
        IF purge_before IS NOT NULL AND purge_before <> ''
           AND OLD.occurred_at < purge_before::timestamptz THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'audit_events is append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION authn_audit_events_guard();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION authn_forbid_truncate();
CREATE TRIGGER audit_chain_checkpoints_no_truncate BEFORE TRUNCATE ON audit_chain_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION authn_forbid_truncate();
