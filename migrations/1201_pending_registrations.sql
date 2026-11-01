-- 1201 pending registrations. Owner: authn-account (range 1200-1299).
-- ADR: docs/architecture/adr/0002-registration-pre-hijacking.md.
--
-- Account pre-hijacking defence (ACC-01, ACC-02, ACC-04, ACC-05): the
-- credentials submitted with a registration are NOT written to
-- password_credentials. Each registration is its own row here, bound to its
-- own e-mailed link and code and to a handle held by the registering client.
-- Only completing *this* registration (link opened by the registering client
-- or confirmed with the password chosen in it, or the code submitted together
-- with the handle) copies *these* credentials into the account; every other
-- pending registration of the address is deleted in the same transaction.
-- A second registration of an unverified address therefore never changes
-- anybody's credentials, and an e-mailed link alone never activates a
-- password its clicker did not choose.
--
-- Personal data: removed with the placeholder user (cascade), when the
-- registration completes (all rows of the user are deleted) and when it
-- expires (cleanup job, ACC-05).
CREATE TABLE pending_registrations (
    id                  uuid        PRIMARY KEY,
    -- The `pending_verification` account the registration is for (created
    -- by the first registration of the address, without credentials).
    user_id             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The address as submitted (canonical form, ACC-03) and its
    -- `users.email_normalized` form; completion requires the account to
    -- still have exactly this address and stores this spelling.
    email               text        NOT NULL,
    email_normalized    text        NOT NULL,
    -- SHA-256 of the 256-bit registration handle returned to the registering
    -- client (response body and `__Host-authn_registration` cookie).
    handle_hash         bytea       NOT NULL,
    -- SHA-256 of the current e-mailed link token (rotated by a resend).
    link_hash           bytea       NOT NULL,
    link_expires_at     timestamptz NOT NULL,
    -- HMAC-SHA256 (sub-key) of the current 6-digit code (rotated by a resend).
    code_hash           bytea       NOT NULL,
    code_expires_at     timestamptz NOT NULL,
    -- Wrong codes over the registration's whole life (a resend does not reset
    -- it) and wrong "password you chose" answers on the link page.
    code_attempts       integer     NOT NULL DEFAULT 0,
    password_attempts   integer     NOT NULL DEFAULT 0,
    -- Credentials and profile submitted with this registration; applied to
    -- the account only when this registration completes.
    password_hash       text        NOT NULL,
    password_algorithm  text        NOT NULL,
    pepper_version      integer,
    display_name        text,
    locale              text        NOT NULL,
    time_zone           text        NOT NULL,
    -- Accepted terms versions (ACC-11), recorded as consents on completion.
    terms_version_ids   uuid[]      NOT NULL DEFAULT '{}',
    created_ip          inet,
    user_agent          text,
    created_at          timestamptz NOT NULL,
    -- End of the registration (account.unverified_purge_after).
    expires_at          timestamptz NOT NULL,
    CONSTRAINT pending_registrations_email_check CHECK (
        octet_length(email) BETWEEN 3 AND 254 AND octet_length(email_normalized) BETWEEN 3 AND 254),
    CONSTRAINT pending_registrations_handle_hash_check CHECK (octet_length(handle_hash) = 32),
    CONSTRAINT pending_registrations_link_hash_check CHECK (octet_length(link_hash) = 32),
    CONSTRAINT pending_registrations_code_hash_check CHECK (octet_length(code_hash) = 32),
    CONSTRAINT pending_registrations_attempts_check
        CHECK (code_attempts BETWEEN 0 AND 100 AND password_attempts BETWEEN 0 AND 100),
    CONSTRAINT pending_registrations_password_hash_check
        CHECK (octet_length(password_hash) BETWEEN 16 AND 1024),
    CONSTRAINT pending_registrations_algorithm_check
        CHECK (password_algorithm ~ '^[a-z0-9][a-z0-9_]{0,31}$'),
    CONSTRAINT pending_registrations_pepper_check
        CHECK (pepper_version IS NULL OR pepper_version >= 1),
    CONSTRAINT pending_registrations_display_name_check
        CHECK (char_length(display_name) BETWEEN 1 AND 128),
    CONSTRAINT pending_registrations_locale_check CHECK (locale IN ('en', 'tr')),
    CONSTRAINT pending_registrations_time_zone_check CHECK (char_length(time_zone) BETWEEN 1 AND 64),
    CONSTRAINT pending_registrations_user_agent_check CHECK (char_length(user_agent) <= 512),
    CONSTRAINT pending_registrations_expiry_check CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX pending_registrations_handle_key ON pending_registrations (handle_hash);
CREATE UNIQUE INDEX pending_registrations_link_key ON pending_registrations (link_hash);
CREATE INDEX pending_registrations_user_idx ON pending_registrations (user_id, created_at DESC);
CREATE INDEX pending_registrations_expiry_idx ON pending_registrations (expires_at);
