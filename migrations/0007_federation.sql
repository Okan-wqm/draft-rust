-- 0007 federated identities and OAuth/OIDC authorization state.
-- Owner: authn-oidc-client (SOC-*). `identities` is also the Phase 2 anchor
-- for per-organization enterprise SSO connections.

CREATE TABLE identities (
    id                          uuid        PRIMARY KEY,
    user_id                     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- google | apple | microsoft | github | oidc:<slug> | (Phase 2) sso:<connection>
    provider                    text        NOT NULL,
    -- Stable provider subject; for Microsoft multi-tenant `<tid>:<oid>`.
    subject                     text        NOT NULL,
    issuer                      text,
    email                       text,
    email_verified              boolean     NOT NULL DEFAULT false,
    display_name                text,
    -- Provider tokens are not stored by default (SOC-08); when enabled they
    -- are envelope encrypted.
    access_token_ciphertext     bytea,
    refresh_token_ciphertext    bytea,
    token_expires_at            timestamptz,
    created_at                  timestamptz NOT NULL,
    last_login_at               timestamptz,
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT identities_provider_check CHECK (provider ~ '^[a-z0-9][a-z0-9_.:-]{0,63}$'),
    CONSTRAINT identities_subject_check CHECK (char_length(subject) BETWEEN 1 AND 255),
    CONSTRAINT identities_issuer_check CHECK (char_length(issuer) <= 512),
    CONSTRAINT identities_email_check CHECK (octet_length(email) <= 320),
    CONSTRAINT identities_display_name_check CHECK (char_length(display_name) <= 256),
    -- Matching is by (provider, subject), never by e-mail (SOC-05).
    CONSTRAINT identities_provider_subject_key UNIQUE (provider, subject),
    CONSTRAINT identities_user_provider_key UNIQUE (user_id, provider)
);
CREATE TRIGGER identities_touch BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Authorization requests in flight (SOC-02) and native nonces (SOC-04).
CREATE TABLE oauth_states (
    id                        uuid        PRIMARY KEY,
    provider                  text        NOT NULL,
    flow                      text        NOT NULL,
    -- SHA-256 of the `state` parameter.
    state_hash                bytea       NOT NULL,
    -- SHA-256 of the nonce; the ID token nonce is hashed and compared.
    nonce_hash                bytea       NOT NULL,
    -- PKCE verifier (secret), envelope encrypted; NULL for native nonces.
    pkce_verifier_ciphertext  bytea,
    -- Linking flow: the signed-in user.
    user_id                   uuid        REFERENCES users (id) ON DELETE CASCADE,
    -- Validated relative path or allow-listed URL (PRT-10).
    return_to                 text,
    client_kind               text        NOT NULL,
    -- SHA-256 of a browser binding cookie (login CSRF protection).
    binding_hash              bytea,
    created_at                timestamptz NOT NULL,
    expires_at                timestamptz NOT NULL,
    consumed_at               timestamptz,
    CONSTRAINT oauth_states_provider_check CHECK (provider ~ '^[a-z0-9][a-z0-9_.:-]{0,63}$'),
    CONSTRAINT oauth_states_flow_check CHECK (flow IN ('login', 'link', 'native_nonce')),
    CONSTRAINT oauth_states_state_hash_check CHECK (octet_length(state_hash) = 32),
    CONSTRAINT oauth_states_nonce_hash_check CHECK (octet_length(nonce_hash) = 32),
    CONSTRAINT oauth_states_binding_check CHECK (octet_length(binding_hash) = 32),
    CONSTRAINT oauth_states_pkce_check CHECK (flow = 'native_nonce' OR pkce_verifier_ciphertext IS NOT NULL),
    CONSTRAINT oauth_states_link_check CHECK (flow <> 'link' OR user_id IS NOT NULL),
    CONSTRAINT oauth_states_return_to_check CHECK (char_length(return_to) <= 2048),
    CONSTRAINT oauth_states_client_kind_check CHECK (client_kind IN ('web', 'native')),
    CONSTRAINT oauth_states_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT oauth_states_state_hash_key UNIQUE (state_hash),
    CONSTRAINT oauth_states_nonce_hash_key UNIQUE (nonce_hash)
);
CREATE INDEX oauth_states_expiry_idx ON oauth_states (expires_at);
