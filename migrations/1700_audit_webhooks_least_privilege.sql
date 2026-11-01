-- 1700 audit / outbox / webhook follow-ups (AUD-02, AUD-06, AUD-07, OPS-10).
-- Owner: authn-audit. Range 1700-1799.

-- AUD-07: auto-disable after *sustained* failures needs to know since when an
-- endpoint has been failing without interruption, and when it last worked.
ALTER TABLE webhook_endpoints
    ADD COLUMN failing_since    timestamptz,
    ADD COLUMN last_success_at  timestamptz;

-- Delivery history of one endpoint, newest first (keyset pagination).
CREATE INDEX webhook_deliveries_endpoint_created_idx
    ON webhook_deliveries (endpoint_id, created_at DESC, id DESC);

-- Finished deliveries are purged after the configured retention.
CREATE INDEX webhook_deliveries_finished_idx
    ON webhook_deliveries (created_at) WHERE status IN ('succeeded', 'dead');

-- Expired leases of crashed workers are found without scanning pending rows.
CREATE INDEX outbox_processing_lease_idx
    ON outbox (locked_until) WHERE status = 'processing';

-- AUD-02 / OPS-10: least-privilege role recommendation, as an executable
-- helper. Run once as the schema owner, e.g.
--
--   CREATE ROLE authn_app LOGIN PASSWORD '...';
--   CREATE ROLE authn_maintenance LOGIN PASSWORD '...';
--   SELECT authn_audit_apply_least_privilege('authn_app', 'authn_maintenance');
--
-- * app_role: may append audit events and use the outbox / webhooks, but has
--   no UPDATE / DELETE / TRUNCATE on audit_events and audit_chain_checkpoints
--   (the append-only trigger is a second, independent barrier).
-- * maintenance_role: additionally may DELETE old audit events, which the
--   trigger only lets through inside a transaction that ran
--   SET LOCAL authn.audit_purge_before = '<timestamptz>' (retention purge,
--   AUD-05), and may insert checkpoints (manual checkpoints, ADM-07).
-- Every privilege either role already had on the audit / outbox / webhook
-- tables (e.g. from GRANT ALL ON ALL TABLES IN SCHEMA public) is revoked
-- first, so nothing beyond the list below survives: in particular no
-- UPDATE on audit_subjects / audit_event_pii (re-attributing history or
-- personal data) and no TRUNCATE / DELETE on audit_chain_head.
CREATE FUNCTION authn_audit_apply_least_privilege(app_role name, maintenance_role name)
RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF app_role IS NULL OR maintenance_role IS NULL THEN
        RAISE EXCEPTION 'role names must not be NULL';
    END IF;
    EXECUTE format('REVOKE ALL ON audit_events, audit_chain_checkpoints, audit_chain_head, '
        'audit_subjects, audit_event_pii, outbox, webhook_endpoints, webhook_deliveries '
        'FROM %I, %I', app_role, maintenance_role);
    -- Appending (record / record_in_tx) and pseudonymisation.
    EXECUTE format('GRANT SELECT, INSERT ON audit_events TO %I', app_role);
    EXECUTE format('GRANT SELECT ON audit_chain_checkpoints TO %I', app_role);
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON audit_subjects, audit_event_pii TO %I', app_role);
    EXECUTE format('GRANT SELECT, UPDATE ON audit_chain_head TO %I', app_role);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON outbox, webhook_endpoints, webhook_deliveries TO %I', app_role);
    -- Retention purge and checkpoints (the trigger still guards DELETE).
    EXECUTE format('GRANT SELECT, DELETE ON audit_events TO %I', maintenance_role);
    EXECUTE format('GRANT SELECT, INSERT ON audit_chain_checkpoints TO %I', maintenance_role);
    EXECUTE format('GRANT SELECT ON audit_chain_head, audit_event_pii, audit_subjects TO %I', maintenance_role);
    EXECUTE format('GRANT DELETE ON audit_event_pii TO %I', maintenance_role);
    EXECUTE format('GRANT SELECT, DELETE ON outbox, webhook_deliveries TO %I', maintenance_role);
END;
$$;
