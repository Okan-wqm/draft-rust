-- 0004 sessions, refresh-token families, pending authentication challenges,
-- one-time tokens/codes, trusted devices.
-- Owners: sessions, refresh_tokens, auth_challenges -> authn-session;
-- one_time_tokens -> shared (each purpose owned by one module, see
-- docs/architecture/contracts.md); trusted_devices -> authn-mfa.

CREATE TABLE sessions (
    id                    uuid        PRIMARY KEY,
    user_id               uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_kind           text        NOT NULL,
    -- SHA-256 of the opaque web session token (cookie); NULL for native
    -- sessions, which are represented by their refresh-token family.
    token_hash            bytea,
    remember_me           boolean     NOT NULL DEFAULT false,
    -- "Not my device" (SES-07): browser-session cookie, short lifetime.
    shared_device         boolean     NOT NULL DEFAULT false,
    amr                   text[]      NOT NULL,
    acr                   text,
    auth_time             timestamptz NOT NULL,
    active_org_id         uuid        REFERENCES organizations (id) ON DELETE SET NULL,
    -- Impersonation (ADM-04): the acting admin, read-only flag, reason.
    impersonator_user_id  uuid        REFERENCES users (id) ON DELETE CASCADE,
    impersonation_read_only boolean,
    impersonation_reason  text,
    device_id             text,
    device_name           text,
    user_agent            text,
    created_ip            inet,
    last_seen_ip          inet,
    created_at            timestamptz NOT NULL,
    last_seen_at          timestamptz NOT NULL,
    idle_expires_at       timestamptz NOT NULL,
    absolute_expires_at   timestamptz NOT NULL,
    revoked_at            timestamptz,
    revoked_reason        text,
    CONSTRAINT sessions_client_kind_check CHECK (client_kind IN ('web', 'native')),
    CONSTRAINT sessions_token_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT sessions_web_token_check CHECK (client_kind <> 'web' OR token_hash IS NOT NULL OR revoked_at IS NOT NULL),
    CONSTRAINT sessions_amr_check CHECK (cardinality(amr) BETWEEN 1 AND 16),
    CONSTRAINT sessions_impersonation_check CHECK (
        (impersonator_user_id IS NULL AND impersonation_read_only IS NULL AND impersonation_reason IS NULL)
        OR (impersonator_user_id IS NOT NULL AND impersonation_read_only IS NOT NULL
            AND char_length(impersonation_reason) BETWEEN 1 AND 1000)),
    CONSTRAINT sessions_device_id_check CHECK (device_id ~ '^[A-Za-z0-9_-]{16,128}$'),
    CONSTRAINT sessions_device_name_check CHECK (char_length(device_name) <= 128),
    CONSTRAINT sessions_user_agent_check CHECK (char_length(user_agent) <= 512),
    CONSTRAINT sessions_expiry_check CHECK (
        idle_expires_at <= absolute_expires_at AND absolute_expires_at > created_at),
    CONSTRAINT sessions_revoked_check CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
    CONSTRAINT sessions_revoked_reason_check CHECK (revoked_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash)
);
CREATE INDEX sessions_user_active_idx ON sessions (user_id, created_at) WHERE revoked_at IS NULL;
CREATE INDEX sessions_org_active_idx ON sessions (active_org_id) WHERE revoked_at IS NULL AND active_org_id IS NOT NULL;
CREATE INDEX sessions_expiry_idx ON sessions (absolute_expires_at);

-- Refresh tokens form a rotation lineage per session (SES-05). Exactly one
-- live token per family; replaying a used token revokes the family.
CREATE TABLE refresh_tokens (
    id                    uuid        PRIMARY KEY,
    session_id            uuid        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    token_hash            bytea       NOT NULL,
    parent_id             uuid        REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    generation            integer     NOT NULL,
    created_at            timestamptz NOT NULL,
    idle_expires_at       timestamptz NOT NULL,
    -- Copied from the family; rotation never extends it (SES-06).
    absolute_expires_at   timestamptz NOT NULL,
    used_at               timestamptz,
    replaced_by_id        uuid        REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    -- Envelope-encrypted successor token, kept only during the optional
    -- rotation grace window so a retry returns the *same* new token.
    successor_ciphertext  bytea,
    revoked_at            timestamptz,
    CONSTRAINT refresh_tokens_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_tokens_generation_check CHECK (generation >= 0),
    CONSTRAINT refresh_tokens_expiry_check CHECK (idle_expires_at <= absolute_expires_at),
    CONSTRAINT refresh_tokens_used_check CHECK (replaced_by_id IS NULL OR used_at IS NOT NULL),
    CONSTRAINT refresh_tokens_hash_key UNIQUE (token_hash),
    CONSTRAINT refresh_tokens_session_generation_key UNIQUE (session_id, generation)
);
CREATE UNIQUE INDEX refresh_tokens_one_live_per_family_idx ON refresh_tokens (session_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;

-- Pending login state (SES-02, SES-22), step-up and passwordless challenges.
CREATE TABLE auth_challenges (
    id                uuid        PRIMARY KEY,
    kind              text        NOT NULL,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the opaque challenge token handed to the client.
    token_hash        bytea       NOT NULL,
    -- Step-up challenges are bound to the session they elevate.
    session_id        uuid        REFERENCES sessions (id) ON DELETE CASCADE,
    client_kind       text        NOT NULL,
    amr               text[]      NOT NULL DEFAULT '{}',
    first_factor_at   timestamptz,
    allowed_factors   text[]      NOT NULL DEFAULT '{}',
    required_actions  text[]      NOT NULL DEFAULT '{}',
    remember_me       boolean     NOT NULL DEFAULT false,
    shared_device     boolean     NOT NULL DEFAULT false,
    requested_org_id  uuid        REFERENCES organizations (id) ON DELETE SET NULL,
    risk_level        text,
    attempts          integer     NOT NULL DEFAULT 0,
    max_attempts      integer     NOT NULL DEFAULT 5,
    ip                inet,
    user_agent        text,
    device_id         text,
    metadata          jsonb       NOT NULL DEFAULT '{}',
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    consumed_at       timestamptz,
    CONSTRAINT auth_challenges_kind_check CHECK (kind IN ('login', 'step_up', 'passwordless')),
    CONSTRAINT auth_challenges_token_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT auth_challenges_client_kind_check CHECK (client_kind IN ('web', 'native')),
    CONSTRAINT auth_challenges_step_up_check CHECK (kind <> 'step_up' OR session_id IS NOT NULL),
    CONSTRAINT auth_challenges_factors_check CHECK (allowed_factors <@
        ARRAY['totp', 'webauthn', 'recovery_code', 'email', 'sms']::text[]),
    CONSTRAINT auth_challenges_actions_check CHECK (required_actions <@
        ARRAY['verify_mfa', 'enroll_mfa', 'change_password', 'accept_terms', 'verify_email']::text[]),
    CONSTRAINT auth_challenges_risk_check CHECK (risk_level IN ('low', 'medium', 'high')),
    CONSTRAINT auth_challenges_attempts_check CHECK (
        attempts >= 0 AND max_attempts BETWEEN 1 AND 100 AND attempts <= max_attempts),
    CONSTRAINT auth_challenges_user_agent_check CHECK (char_length(user_agent) <= 512),
    CONSTRAINT auth_challenges_metadata_check CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT auth_challenges_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT auth_challenges_token_hash_key UNIQUE (token_hash)
);
CREATE INDEX auth_challenges_user_idx ON auth_challenges (user_id) WHERE consumed_at IS NULL;
CREATE INDEX auth_challenges_expiry_idx ON auth_challenges (expires_at);

-- Generic single-use tokens and short codes (ARC-06, CRY-06, CRY-07).
--   kind = 'link': 256-bit token, token_hash = SHA-256(token), globally unique.
--   kind = 'code': 6-digit code, token_hash = HMAC-SHA256(server key, code);
--                  looked up by (user_id | challenge_id, purpose), never by
--                  hash alone (codes collide across users).
-- Consumption is atomic:
--   UPDATE one_time_tokens SET consumed_at = $now
--    WHERE id = $id AND consumed_at IS NULL AND revoked_at IS NULL
--      AND expires_at > $now RETURNING ...
CREATE TABLE one_time_tokens (
    id            uuid        PRIMARY KEY,
    purpose       text        NOT NULL,
    kind          text        NOT NULL,
    token_hash    bytea       NOT NULL,
    user_id       uuid        REFERENCES users (id) ON DELETE CASCADE,
    challenge_id  uuid        REFERENCES auth_challenges (id) ON DELETE CASCADE,
    -- Tokens issued together (link + code); consuming one revokes the rest.
    group_id      uuid,
    -- Purpose-specific target, e.g. the new address of an e-mail change.
    target        text,
    attempts      integer     NOT NULL DEFAULT 0,
    max_attempts  integer     NOT NULL DEFAULT 5,
    metadata      jsonb       NOT NULL DEFAULT '{}',
    created_ip    inet,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    revoked_at    timestamptz,
    CONSTRAINT one_time_tokens_purpose_check CHECK (purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT one_time_tokens_kind_check CHECK (kind IN ('link', 'code')),
    CONSTRAINT one_time_tokens_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT one_time_tokens_owner_check CHECK (user_id IS NOT NULL OR challenge_id IS NOT NULL),
    CONSTRAINT one_time_tokens_target_check CHECK (char_length(target) <= 320),
    CONSTRAINT one_time_tokens_attempts_check CHECK (
        attempts >= 0 AND max_attempts BETWEEN 1 AND 100 AND attempts <= max_attempts),
    CONSTRAINT one_time_tokens_metadata_check CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT one_time_tokens_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT one_time_tokens_final_state_check CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);
CREATE UNIQUE INDEX one_time_tokens_link_hash_idx ON one_time_tokens (token_hash) WHERE kind = 'link';
CREATE INDEX one_time_tokens_active_user_idx ON one_time_tokens (user_id, purpose, created_at DESC)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX one_time_tokens_challenge_idx ON one_time_tokens (challenge_id) WHERE challenge_id IS NOT NULL;
CREATE INDEX one_time_tokens_group_idx ON one_time_tokens (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX one_time_tokens_expiry_idx ON one_time_tokens (expires_at);

-- "Don't ask for MFA on this device for 30 days" (MFA-09).
CREATE TABLE trusted_devices (
    id              uuid        PRIMARY KEY,
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the signed device token (cookie / header).
    token_hash      bytea       NOT NULL,
    device_name     text,
    user_agent      text,
    created_ip      inet,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    revoked_reason  text,
    CONSTRAINT trusted_devices_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT trusted_devices_name_check CHECK (char_length(device_name) <= 128),
    CONSTRAINT trusted_devices_user_agent_check CHECK (char_length(user_agent) <= 512),
    CONSTRAINT trusted_devices_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT trusted_devices_revoked_check CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
    CONSTRAINT trusted_devices_token_hash_key UNIQUE (token_hash)
);
CREATE INDEX trusted_devices_user_idx ON trusted_devices (user_id) WHERE revoked_at IS NULL;
