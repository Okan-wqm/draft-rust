-- 0011 data-encryption keys and JWT signing keys (CRY-08, CRY-10).
-- Owner: authn-crypto.

-- DEKs wrapped by a KEK from configuration. Rotating the KEK re-wraps rows
-- here only; ciphertexts elsewhere reference the DEK id in their envelope
-- header (`key_id || nonce || ciphertext`).
CREATE TABLE data_encryption_keys (
    id           uuid        PRIMARY KEY,
    purpose      text        NOT NULL,
    kek_id       text        NOT NULL,
    wrapped_key  bytea       NOT NULL,
    status       text        NOT NULL DEFAULT 'active',
    created_at   timestamptz NOT NULL,
    retired_at   timestamptz,
    CONSTRAINT data_encryption_keys_purpose_check CHECK (purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT data_encryption_keys_kek_check CHECK (kek_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    CONSTRAINT data_encryption_keys_wrapped_check CHECK (octet_length(wrapped_key) BETWEEN 32 AND 256),
    CONSTRAINT data_encryption_keys_status_check CHECK (status IN ('active', 'retired')),
    CONSTRAINT data_encryption_keys_retired_check CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX data_encryption_keys_active_purpose_idx ON data_encryption_keys (purpose)
    WHERE status = 'active';
CREATE INDEX data_encryption_keys_kek_idx ON data_encryption_keys (kek_id);

-- JWT signing keys: pending -> active -> retired -> revoked (CRY-10).
CREATE TABLE signing_keys (
    id                      uuid        PRIMARY KEY,
    algorithm               text        NOT NULL DEFAULT 'EdDSA',
    status                  text        NOT NULL,
    public_key              bytea       NOT NULL,
    -- Envelope-encrypted private key (AAD binds table/column/row id).
    private_key_ciphertext  bytea       NOT NULL,
    created_at              timestamptz NOT NULL,
    -- Earliest activation (>= created_at + JWKS cache TTL).
    activate_after          timestamptz NOT NULL,
    activated_at            timestamptz,
    retired_at              timestamptz,
    -- Leaves the JWKS after this instant (retired keys).
    publish_until           timestamptz,
    revoked_at              timestamptz,
    CONSTRAINT signing_keys_algorithm_check CHECK (algorithm IN ('EdDSA')),
    CONSTRAINT signing_keys_status_check CHECK (status IN ('pending', 'active', 'retired', 'revoked')),
    CONSTRAINT signing_keys_public_key_check CHECK (octet_length(public_key) BETWEEN 32 AND 1024),
    CONSTRAINT signing_keys_activation_check CHECK (activate_after >= created_at),
    CONSTRAINT signing_keys_active_check CHECK (status NOT IN ('active', 'retired') OR activated_at IS NOT NULL),
    CONSTRAINT signing_keys_retired_check CHECK (status <> 'retired' OR retired_at IS NOT NULL),
    CONSTRAINT signing_keys_revoked_check CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);
-- At most one active signing key.
CREATE UNIQUE INDEX signing_keys_single_active_idx ON signing_keys (status) WHERE status = 'active';
