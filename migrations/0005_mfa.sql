-- 0005 MFA factors, recovery codes, per-user MFA settings.
-- Owner: authn-mfa (MFA-*).

CREATE TABLE mfa_factors (
    id                 uuid        PRIMARY KEY,
    user_id            uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind               text        NOT NULL,
    -- Pending until confirmed with a valid code (MFA-01, MFA-06).
    status             text        NOT NULL DEFAULT 'pending',
    label              text,
    -- TOTP secret (160 bit), envelope encrypted with AAD = table/column/row id.
    secret_ciphertext  bytea,
    totp_digits        smallint,
    totp_period        smallint,
    -- Last accepted TOTP time step; same or earlier steps are rejected (MFA-02).
    last_used_step     bigint,
    phone_e164         text,
    -- Address for the e-mail factor; NULL means the account address.
    email              text,
    failed_attempts    integer     NOT NULL DEFAULT 0,
    locked_until       timestamptz,
    created_at         timestamptz NOT NULL,
    confirmed_at       timestamptz,
    last_used_at       timestamptz,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT mfa_factors_kind_check CHECK (kind IN ('totp', 'sms', 'email')),
    CONSTRAINT mfa_factors_status_check CHECK (status IN ('pending', 'active', 'disabled')),
    CONSTRAINT mfa_factors_label_check CHECK (char_length(label) BETWEEN 1 AND 64),
    CONSTRAINT mfa_factors_totp_check CHECK (kind <> 'totp' OR (
        secret_ciphertext IS NOT NULL AND totp_digits IN (6, 8) AND totp_period BETWEEN 15 AND 120)),
    CONSTRAINT mfa_factors_sms_check CHECK (kind <> 'sms' OR phone_e164 IS NOT NULL),
    CONSTRAINT mfa_factors_phone_check CHECK (phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
    CONSTRAINT mfa_factors_step_check CHECK (last_used_step >= 0),
    CONSTRAINT mfa_factors_failed_check CHECK (failed_attempts >= 0),
    CONSTRAINT mfa_factors_confirmed_check CHECK (status <> 'active' OR confirmed_at IS NOT NULL)
);
CREATE INDEX mfa_factors_user_idx ON mfa_factors (user_id);
CREATE UNIQUE INDEX mfa_factors_one_phone_idx ON mfa_factors (user_id, phone_e164)
    WHERE kind = 'sms' AND status <> 'disabled';
CREATE TRIGGER mfa_factors_touch BEFORE UPDATE ON mfa_factors
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Recovery codes (MFA-04): HMAC-SHA256 hashes only; a new batch replaces
-- (deletes) the previous one.
CREATE TABLE recovery_codes (
    id          uuid        PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    batch_id    uuid        NOT NULL,
    code_hash   bytea       NOT NULL,
    created_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_ip     inet,
    CONSTRAINT recovery_codes_hash_check CHECK (octet_length(code_hash) = 32),
    CONSTRAINT recovery_codes_user_hash_key UNIQUE (user_id, code_hash)
);
CREATE INDEX recovery_codes_unused_idx ON recovery_codes (user_id) WHERE used_at IS NULL;

-- User-level MFA preference (MFA-08).
CREATE TABLE mfa_user_settings (
    user_id           uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- The user opted into MFA (independent of organization policy).
    mfa_enabled       boolean     NOT NULL DEFAULT false,
    preferred_factor  text,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT mfa_user_settings_preferred_check CHECK (preferred_factor IN
        ('totp', 'webauthn', 'recovery_code', 'email', 'sms'))
);
CREATE TRIGGER mfa_user_settings_touch BEFORE UPDATE ON mfa_user_settings
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();
