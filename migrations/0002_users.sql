-- 0002 users, profiles, password credentials, consents, deletions.
-- Table owners: users / password_credentials -> authn-store (base CRUD);
-- user_profiles, terms_versions, consents, account_deletions -> authn-account.

CREATE TABLE users (
    id                    uuid        PRIMARY KEY,
    -- Canonical address (NFKC local part, IDNA ASCII lowercase domain).
    email                 text,
    -- Fully lowercased form, unique (ACC-03).
    email_normalized      text,
    email_verified_at     timestamptz,
    status                text        NOT NULL DEFAULT 'pending_verification',
    -- Stable snake_case reason code for the last status change.
    status_reason         text,
    status_changed_at     timestamptz NOT NULL DEFAULT now(),
    -- Temporary lock end (ACC-06 `locked`).
    locked_until          timestamptz,
    is_platform_admin     boolean     NOT NULL DEFAULT false,
    is_break_glass        boolean     NOT NULL DEFAULT false,
    last_login_at         timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_status_check CHECK (status IN (
        'pending_verification', 'active', 'locked', 'suspended',
        'disabled', 'pending_deletion', 'deleted')),
    CONSTRAINT users_status_reason_check CHECK (status_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT users_email_length_check CHECK (octet_length(email) BETWEEN 3 AND 254),
    CONSTRAINT users_email_normalized_length_check
        CHECK (octet_length(email_normalized) BETWEEN 3 AND 254),
    -- Only a deleted (anonymised) account may lose its address.
    CONSTRAINT users_email_present_check CHECK (
        status = 'deleted' OR (email IS NOT NULL AND email_normalized IS NOT NULL)),
    CONSTRAINT users_locked_until_check CHECK (status <> 'locked' OR locked_until IS NOT NULL),
    CONSTRAINT users_break_glass_is_admin_check CHECK (NOT is_break_glass OR is_platform_admin),
    CONSTRAINT users_email_normalized_key UNIQUE (email_normalized)
);
CREATE INDEX users_status_created_idx ON users (status, created_at);
CREATE INDEX users_platform_admin_idx ON users (id) WHERE is_platform_admin;
CREATE TRIGGER users_touch BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

CREATE TABLE user_profiles (
    user_id       uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    display_name  text,
    locale        text        NOT NULL DEFAULT 'en',
    time_zone     text        NOT NULL DEFAULT 'UTC',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_profiles_display_name_check CHECK (char_length(display_name) BETWEEN 1 AND 128),
    CONSTRAINT user_profiles_locale_check CHECK (locale IN ('en', 'tr')),
    CONSTRAINT user_profiles_time_zone_check CHECK (char_length(time_zone) BETWEEN 1 AND 64)
);
CREATE TRIGGER user_profiles_touch BEFORE UPDATE ON user_profiles
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- One password per user; absent for passwordless accounts (PWD-10/11).
CREATE TABLE password_credentials (
    user_id         uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- PHC string (argon2id) or a legacy format understood by authn-crypto (CRY-04).
    password_hash   text        NOT NULL,
    -- Hash scheme, e.g. argon2id, bcrypt, pbkdf2_sha256, argon2id_wrapped_md5.
    algorithm       text        NOT NULL,
    -- Pepper version used (CRY-02); NULL only for imported legacy hashes.
    pepper_version  integer,
    must_change     boolean     NOT NULL DEFAULT false,
    changed_at      timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT password_credentials_hash_check CHECK (octet_length(password_hash) BETWEEN 16 AND 1024),
    CONSTRAINT password_credentials_algorithm_check CHECK (algorithm ~ '^[a-z0-9][a-z0-9_]{0,31}$'),
    CONSTRAINT password_credentials_pepper_check CHECK (pepper_version IS NULL OR pepper_version >= 1),
    CONSTRAINT password_credentials_argon_pepper_check
        CHECK (algorithm <> 'argon2id' OR pepper_version IS NOT NULL)
);
CREATE INDEX password_credentials_changed_idx ON password_credentials (changed_at);
CREATE TRIGGER password_credentials_touch BEFORE UPDATE ON password_credentials
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Published versions of the terms of service / privacy policy (ACC-11).
CREATE TABLE terms_versions (
    id                     uuid        PRIMARY KEY,
    document               text        NOT NULL,
    version                text        NOT NULL,
    url                    text,
    published_at           timestamptz NOT NULL,
    requires_reacceptance  boolean     NOT NULL DEFAULT false,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT terms_versions_document_check CHECK (document IN ('terms_of_service', 'privacy_policy')),
    CONSTRAINT terms_versions_version_check CHECK (char_length(version) BETWEEN 1 AND 64),
    CONSTRAINT terms_versions_url_check CHECK (url ~ '^https?://'),
    CONSTRAINT terms_versions_document_version_key UNIQUE (document, version)
);
CREATE INDEX terms_versions_latest_idx ON terms_versions (document, published_at DESC);

CREATE TABLE consents (
    id                uuid        PRIMARY KEY,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    terms_version_id  uuid        NOT NULL REFERENCES terms_versions (id) ON DELETE RESTRICT,
    accepted_at       timestamptz NOT NULL,
    ip                inet,
    user_agent        text,
    CONSTRAINT consents_user_agent_check CHECK (char_length(user_agent) <= 512),
    CONSTRAINT consents_user_terms_key UNIQUE (user_id, terms_version_id)
);

-- Deletion requests (ACC-09). No FK to users: the record must outlive the
-- user row, which is hard-deleted when the deletion completes.
CREATE TABLE account_deletions (
    id             uuid        PRIMARY KEY,
    user_id        uuid        NOT NULL,
    status         text        NOT NULL DEFAULT 'scheduled',
    requested_at   timestamptz NOT NULL,
    scheduled_for  timestamptz NOT NULL,
    cancelled_at   timestamptz,
    completed_at   timestamptz,
    CONSTRAINT account_deletions_status_check CHECK (status IN ('scheduled', 'cancelled', 'completed')),
    CONSTRAINT account_deletions_schedule_check CHECK (scheduled_for >= requested_at),
    CONSTRAINT account_deletions_cancelled_check CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL)),
    CONSTRAINT account_deletions_completed_check CHECK ((status = 'completed') = (completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX account_deletions_one_scheduled_idx ON account_deletions (user_id)
    WHERE status = 'scheduled';
CREATE INDEX account_deletions_due_idx ON account_deletions (scheduled_for)
    WHERE status = 'scheduled';
