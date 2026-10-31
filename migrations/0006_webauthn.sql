-- 0006 passkeys / WebAuthn. Owner: authn-webauthn (PKY-*).

-- Random, e-mail independent WebAuthn user handle per user (PKY-03).
CREATE TABLE webauthn_user_handles (
    user_id      uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    user_handle  bytea       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webauthn_user_handles_length_check CHECK (octet_length(user_handle) BETWEEN 16 AND 64),
    CONSTRAINT webauthn_user_handles_handle_key UNIQUE (user_handle)
);

CREATE TABLE webauthn_credentials (
    id                  uuid        PRIMARY KEY,
    user_id             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Authenticator credential id (raw bytes).
    credential_id       bytea       NOT NULL,
    -- Serialized webauthn-rs credential (public key, counter, flags). Public
    -- data only; integrity matters, confidentiality does not.
    passkey             jsonb       NOT NULL,
    name                text        NOT NULL,
    aaguid              uuid,
    -- passwordless (resident, UV required) / second_factor / both (PKY-02).
    usage               text        NOT NULL,
    user_verified       boolean     NOT NULL DEFAULT false,
    backup_eligible     boolean     NOT NULL DEFAULT false,
    backup_state        boolean     NOT NULL DEFAULT false,
    sign_count          bigint      NOT NULL DEFAULT 0,
    transports          text[]      NOT NULL DEFAULT '{}',
    attestation_format  text,
    created_at          timestamptz NOT NULL,
    last_used_at        timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webauthn_credentials_id_length_check CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    CONSTRAINT webauthn_credentials_passkey_check CHECK (jsonb_typeof(passkey) = 'object'),
    CONSTRAINT webauthn_credentials_name_check CHECK (char_length(name) BETWEEN 1 AND 64),
    CONSTRAINT webauthn_credentials_usage_check CHECK (usage IN ('passwordless', 'second_factor', 'both')),
    CONSTRAINT webauthn_credentials_sign_count_check CHECK (sign_count >= 0),
    CONSTRAINT webauthn_credentials_backup_check CHECK (backup_eligible OR NOT backup_state),
    CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id)
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);
CREATE TRIGGER webauthn_credentials_touch BEFORE UPDATE ON webauthn_credentials
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Server-side ceremony state (PKY-01): short-lived, single use, bound to
-- the browser / app that started it.
CREATE TABLE webauthn_ceremonies (
    id            uuid        PRIMARY KEY,
    kind          text        NOT NULL,
    purpose       text        NOT NULL,
    -- NULL for discoverable (username-less) authentication.
    user_id       uuid        REFERENCES users (id) ON DELETE CASCADE,
    session_id    uuid        REFERENCES sessions (id) ON DELETE CASCADE,
    challenge_id  uuid        REFERENCES auth_challenges (id) ON DELETE CASCADE,
    -- Serialized webauthn-rs state (contains the challenge).
    state         jsonb       NOT NULL,
    -- SHA-256 of a client binding secret (cookie / header).
    binding_hash  bytea,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    CONSTRAINT webauthn_ceremonies_kind_check CHECK (kind IN
        ('registration', 'authentication', 'discoverable_authentication')),
    CONSTRAINT webauthn_ceremonies_purpose_check CHECK (purpose IN
        ('register', 'login', 'second_factor', 'step_up')),
    CONSTRAINT webauthn_ceremonies_user_check CHECK (kind = 'discoverable_authentication' OR user_id IS NOT NULL),
    CONSTRAINT webauthn_ceremonies_state_check CHECK (jsonb_typeof(state) = 'object'),
    CONSTRAINT webauthn_ceremonies_binding_check CHECK (octet_length(binding_hash) = 32),
    CONSTRAINT webauthn_ceremonies_expiry_check CHECK (expires_at > created_at)
);
CREATE INDEX webauthn_ceremonies_expiry_idx ON webauthn_ceremonies (expires_at);
