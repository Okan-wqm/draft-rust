-- 2201 authn-admin: break-glass passkey enrollment links (ADM-05, K-11),
-- single-flight leases for expensive admin operations (ADM-07, K-09) and
-- legal restrictions of exported justifications (ADM-08, ACC-10, K-39).
-- Owner: authn-admin (range 2200-2299; the only writer of these tables).

-- K-11: single-use, short-lived passkey enrollment links of break-glass
-- admins created by the CLI (`create-admin --passkey-link`). Only the
-- SHA-256 of the 256-bit link token is stored. A link is consumed by one
-- atomic UPDATE in the transaction that stores the passkey; consumed and
-- expired rows are kept for the audit trail and removed with the account.
CREATE TABLE admin_passkey_enrollments (
    id           uuid        PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash   bytea       NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    CONSTRAINT admin_passkey_enrollments_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT admin_passkey_enrollments_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT admin_passkey_enrollments_consumed_check
        CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX admin_passkey_enrollments_user_idx ON admin_passkey_enrollments (user_id);

-- K-09: at most one running instance of an expensive admin operation
-- (full audit chain verification) across every server instance. A lease is
-- taken with one INSERT ... ON CONFLICT statement (no connection is held
-- while the operation runs), released by its holder and expires on its
-- own if the holder dies. No personal data.
CREATE TABLE admin_operation_leases (
    name        text        PRIMARY KEY,
    holder      uuid        NOT NULL,
    acquired_at timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    CONSTRAINT admin_operation_leases_name_check CHECK (name ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT admin_operation_leases_expiry_check CHECK (expires_at > acquired_at)
);

-- K-39: justifications withheld from the subject's data export (ACC-10)
-- under a legal restriction (KVKK art. 28 / GDPR art. 23: fraud or legal
-- investigations). A restriction is itself an audited admin action whose
-- restriction note is stored as that action's justification
-- (`restricted_by` -> its audit event / justification). Append-only like
-- `admin_action_reasons`: a restriction cannot be silently lifted or
-- rewritten; rows go only with the justification they restrict (cascade).
CREATE TABLE admin_reason_restrictions (
    event_id      uuid        PRIMARY KEY REFERENCES admin_action_reasons (event_id) ON DELETE CASCADE,
    restricted_by uuid        NOT NULL REFERENCES audit_events (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL
);
CREATE INDEX admin_reason_restrictions_by_idx ON admin_reason_restrictions (restricted_by);

CREATE FUNCTION authn_admin_reason_restrictions_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() > 1 AND TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'admin_reason_restrictions is append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER admin_reason_restrictions_append_only
    BEFORE UPDATE OR DELETE ON admin_reason_restrictions
    FOR EACH ROW EXECUTE FUNCTION authn_admin_reason_restrictions_guard();
CREATE TRIGGER admin_reason_restrictions_no_truncate BEFORE TRUNCATE ON admin_reason_restrictions
    FOR EACH STATEMENT EXECUTE FUNCTION authn_forbid_truncate();
