-- 1701 authn-audit: events withheld from the subject's own security-event
-- view (AUD-04) for a limited time (K-62).
--
-- A legal restriction of an admin justification (KVKK art. 28 / GDPR
-- art. 23; authn-admin, K-39 / K-62) is itself an audited admin action
-- about the user. While the restriction is active, that event must not
-- appear in the user's own list (`GET /v1/me/security-events`), or the
-- list would tip the user off about the investigation. A hold names the
-- event and the instant until which it is hidden; several holds of one
-- event (extensions) count by their latest `hidden_until`. Once every hold
-- has passed, the event is visible again.
--
-- No personal data. Append-only like `audit_events`: a hold cannot be
-- shortened, lengthened or removed silently (an extension adds a row);
-- rows go only with their event (retention purge, ON DELETE CASCADE).
CREATE TABLE audit_subject_view_holds (
    event_id     uuid        NOT NULL REFERENCES audit_events (id) ON DELETE CASCADE,
    hidden_until timestamptz NOT NULL,
    created_at   timestamptz NOT NULL,
    PRIMARY KEY (event_id, hidden_until),
    -- At most the longest legal restriction period (K-62, 180 days) per
    -- row: an event is never withheld indefinitely by one hold; an
    -- extension is a new (audited) row.
    CONSTRAINT audit_subject_view_holds_period_check
        CHECK (hidden_until > created_at AND hidden_until <= created_at + interval '180 days')
);

CREATE FUNCTION authn_audit_subject_view_holds_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() > 1 AND TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_subject_view_holds is append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_subject_view_holds_append_only
    BEFORE UPDATE OR DELETE ON audit_subject_view_holds
    FOR EACH ROW EXECUTE FUNCTION authn_audit_subject_view_holds_guard();
CREATE TRIGGER audit_subject_view_holds_no_truncate BEFORE TRUNCATE ON audit_subject_view_holds
    FOR EACH STATEMENT EXECUTE FUNCTION authn_forbid_truncate();

-- Least privilege (OPS-10): the new table joins the audit tables managed by
-- authn_audit_apply_least_privilege (app role: SELECT, INSERT; maintenance
-- role: SELECT).
CREATE OR REPLACE FUNCTION authn_audit_apply_least_privilege(app_role name, maintenance_role name)
RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF app_role IS NULL OR maintenance_role IS NULL THEN
        RAISE EXCEPTION 'role names must not be NULL';
    END IF;
    EXECUTE format('REVOKE ALL ON audit_events, audit_chain_checkpoints, audit_chain_head, '
        'audit_subjects, audit_event_pii, outbox, webhook_endpoints, webhook_deliveries, '
        'audit_subject_view_holds '
        'FROM %I, %I', app_role, maintenance_role);
    -- Appending (record / record_in_tx) and pseudonymisation.
    EXECUTE format('GRANT SELECT, INSERT ON audit_events TO %I', app_role);
    EXECUTE format('GRANT SELECT ON audit_chain_checkpoints TO %I', app_role);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON audit_subjects, audit_event_pii TO %I', app_role);
    EXECUTE format('GRANT SELECT, UPDATE ON audit_chain_head TO %I', app_role);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON outbox, webhook_endpoints, webhook_deliveries TO %I', app_role);
    EXECUTE format('GRANT SELECT, INSERT ON audit_subject_view_holds TO %I', app_role);
    -- Retention purge and checkpoints (the trigger still guards DELETE).
    EXECUTE format('GRANT SELECT, DELETE ON audit_events TO %I', maintenance_role);
    EXECUTE format('GRANT SELECT, INSERT ON audit_chain_checkpoints TO %I', maintenance_role);
    EXECUTE format('GRANT SELECT ON audit_chain_head, audit_event_pii, audit_subjects TO %I', maintenance_role);
    EXECUTE format('GRANT DELETE ON audit_event_pii TO %I', maintenance_role);
    EXECUTE format('GRANT SELECT, DELETE ON outbox, webhook_deliveries TO %I', maintenance_role);
    EXECUTE format('GRANT SELECT ON audit_subject_view_holds TO %I', maintenance_role);
END;
$$;
