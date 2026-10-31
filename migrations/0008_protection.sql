-- 0008 abuse protection and risk signals. Owner: authn-protect (PRT-*, RSK-*).

-- GCRA state per hashed key (PRT-01). UNLOGGED: losing limiter state on a
-- crash only relaxes limits briefly and keeps WAL traffic low.
CREATE UNLOGGED TABLE rate_limit_buckets (
    -- Keyed hash (HMAC) of RateLimitKey::canonical(); never raw e-mail / IP.
    key_hash    bytea       PRIMARY KEY,
    -- Theoretical arrival time.
    tat         timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    CONSTRAINT rate_limit_buckets_key_check CHECK (octet_length(key_hash) = 32)
);
CREATE INDEX rate_limit_buckets_expiry_idx ON rate_limit_buckets (expires_at);

-- Soft lock (PRT-03): blocks password attempts from unknown devices/IPs
-- without disabling the account (no DoS by lockout).
CREATE TABLE login_soft_locks (
    user_id        uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    locked_until   timestamptz NOT NULL,
    failure_count  integer     NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT login_soft_locks_failures_check CHECK (failure_count >= 0)
);
CREATE TRIGGER login_soft_locks_touch BEFORE UPDATE ON login_soft_locks
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Self-hosted proof-of-work CAPTCHA challenges (PRT-05): single use.
CREATE TABLE captcha_pow_challenges (
    id              uuid        PRIMARY KEY,
    challenge_hash  bytea       NOT NULL,
    action          text        NOT NULL,
    difficulty      smallint    NOT NULL,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    CONSTRAINT captcha_pow_challenges_hash_check CHECK (octet_length(challenge_hash) = 32),
    CONSTRAINT captcha_pow_challenges_action_check CHECK (action ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT captcha_pow_challenges_difficulty_check CHECK (difficulty BETWEEN 1 AND 64),
    CONSTRAINT captcha_pow_challenges_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT captcha_pow_challenges_hash_key UNIQUE (challenge_hash)
);
CREATE INDEX captcha_pow_challenges_expiry_idx ON captcha_pow_challenges (expires_at);

-- Devices seen for a user (RSK-02 "new device").
CREATE TABLE known_devices (
    id             uuid        PRIMARY KEY,
    user_id        uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Keyed hash of the client device id.
    device_hash    bytea       NOT NULL,
    device_name    text,
    first_seen_at  timestamptz NOT NULL,
    last_seen_at   timestamptz NOT NULL,
    last_ip        inet,
    last_country   text,
    last_latitude  double precision,
    last_longitude double precision,
    CONSTRAINT known_devices_hash_check CHECK (octet_length(device_hash) = 32),
    CONSTRAINT known_devices_name_check CHECK (char_length(device_name) <= 128),
    CONSTRAINT known_devices_country_check CHECK (last_country ~ '^[A-Z]{2}$'),
    CONSTRAINT known_devices_user_device_key UNIQUE (user_id, device_hash)
);

-- IP networks (/24 IPv4, /48 IPv6) seen for a user (RSK-02 "new network").
CREATE TABLE known_networks (
    user_id        uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    network        cidr        NOT NULL,
    first_seen_at  timestamptz NOT NULL,
    last_seen_at   timestamptz NOT NULL,
    PRIMARY KEY (user_id, network)
);
