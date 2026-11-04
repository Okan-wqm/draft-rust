-- 2200 authn-admin: justifications of platform admin actions (ADM-08).
--
-- Every admin action is recorded in the hash-chained audit log
-- (`admin.action`, `admin.emergency_action`, `admin.impersonation_started`).
-- The chained record may only carry codes and identifiers (AUD-03): the
-- free-text justification typed by the admin can contain personal data, so
-- it lives here, outside the chain, linked by the audit event id.
--
-- * Retention follows the audit log: purging an event removes its
--   justification (ON DELETE CASCADE on `event_id`).
-- * Erasure follows the subject account (ACC-09, AUD-05): deleting the user
--   the action was about removes the text, which may describe that user.
-- * Deleting the acting admin keeps the justification but unlinks it.
-- * Append-only (trigger below): no UPDATE / DELETE / TRUNCATE except the
--   foreign-key actions.
-- Table owner: authn-admin (the only writer).
CREATE TABLE admin_action_reasons (
    event_id         uuid        PRIMARY KEY REFERENCES audit_events (id) ON DELETE CASCADE,
    admin_user_id    uuid        REFERENCES users (id) ON DELETE SET NULL,
    subject_user_id  uuid        REFERENCES users (id) ON DELETE CASCADE,
    action           text        NOT NULL,
    reason           text        NOT NULL,
    created_at       timestamptz NOT NULL,
    CONSTRAINT admin_action_reasons_action_check CHECK (action ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT admin_action_reasons_reason_check CHECK (char_length(reason) BETWEEN 1 AND 1000)
);
CREATE INDEX admin_action_reasons_subject_idx ON admin_action_reasons (subject_user_id)
    WHERE subject_user_id IS NOT NULL;
CREATE INDEX admin_action_reasons_admin_idx ON admin_action_reasons (admin_user_id)
    WHERE admin_user_id IS NOT NULL;

-- The justification is outside the hash chain, so it gets the same
-- append-only barrier as `audit_events` (independent of database grants):
-- no UPDATE, DELETE or TRUNCATE by any statement. The only changes allowed
-- are the foreign-key actions above (`ON DELETE CASCADE` of the subject or
-- of a purged audit event, `ON DELETE SET NULL` of an erased admin), which
-- PostgreSQL runs from its referential-integrity triggers, i.e. at trigger
-- depth > 1. Least-privilege deployments grant the application role only
-- SELECT, INSERT on this table.
CREATE FUNCTION authn_admin_action_reasons_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() > 1 THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        -- Only the SET NULL of an erased admin may change a row.
        IF NEW.admin_user_id IS NULL
           AND OLD.admin_user_id IS NOT NULL
           AND NEW.event_id = OLD.event_id
           AND NEW.subject_user_id IS NOT DISTINCT FROM OLD.subject_user_id
           AND NEW.action = OLD.action
           AND NEW.reason = OLD.reason
           AND NEW.created_at = OLD.created_at THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION 'admin_action_reasons is append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER admin_action_reasons_append_only BEFORE UPDATE OR DELETE ON admin_action_reasons
    FOR EACH ROW EXECUTE FUNCTION authn_admin_action_reasons_guard();
CREATE TRIGGER admin_action_reasons_no_truncate BEFORE TRUNCATE ON admin_action_reasons
    FOR EACH STATEMENT EXECUTE FUNCTION authn_forbid_truncate();
