-- 2902 authn-server: the erasure ledger is append-only for the application
-- role (OPS-10, K-108 audit). Owner: authn-server (range 2900-2999).
--
-- erasure_ledger (1203, authn-account) records every erased account so the
-- erasure can be re-applied after a backup restore (KVKK md. 7, GDPR
-- art. 17). The application only inserts into it (INSERT ... ON CONFLICT
-- DO NOTHING); with the ordinary module grants of 2900/2901 a compromised
-- application role could delete or rewrite the record of an erasure before
-- the operator exported it, and the erased account would come back with
-- the next restore. The table joins the append-only list (SELECT, INSERT).
--
-- Everything else is unchanged from 2901 (see its header). Re-run after
-- this release, as the database owner:
--
--   SELECT authn_apply_least_privilege('authn_app', 'authn_maintenance');
--
-- Runbook: docs/operations/least-privilege.md.
CREATE OR REPLACE FUNCTION authn_apply_least_privilege(app_role name, maintenance_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path FROM CURRENT
AS $$
DECLARE
    t record;
    r name;
    -- The schema of the migrations (search_path pinned at creation).
    target_schema CONSTANT name := current_schema();
    append_only CONSTANT text[] := ARRAY['admin_action_reasons', 'admin_reason_restrictions',
        'admin_reason_restriction_periods', 'erasure_ledger'];
    no_delete CONSTANT text[] := ARRAY['admin_approvals'];
    audit_owned CONSTANT text[] := ARRAY['audit_events', 'audit_chain_checkpoints',
        'audit_chain_head', 'audit_subjects', 'audit_event_pii', 'outbox',
        'webhook_endpoints', 'webhook_deliveries', 'audit_subject_view_holds'];
BEGIN
    IF app_role IS NULL OR maintenance_role IS NULL THEN
        RAISE EXCEPTION 'role names must not be NULL';
    END IF;
    IF app_role = maintenance_role THEN
        RAISE EXCEPTION 'the application and maintenance roles must differ';
    END IF;
    FOREACH r IN ARRAY ARRAY[app_role, maintenance_role] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            RAISE EXCEPTION 'role % does not exist', r;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r AND (rolsuper OR rolbypassrls)) THEN
            RAISE EXCEPTION 'role % is a superuser or bypasses row security; no grant restricts it', r;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles p
                   WHERE p.rolname IN ('pg_read_all_data', 'pg_write_all_data')
                     AND pg_has_role(r, p.oid, 'MEMBER')) THEN
            RAISE EXCEPTION 'role % is a member of pg_read_all_data / pg_write_all_data', r;
        END IF;
    END LOOP;
    IF pg_has_role(app_role, maintenance_role, 'MEMBER')
        OR pg_has_role(maintenance_role, app_role, 'MEMBER') THEN
        RAISE EXCEPTION 'roles % and % must not be members of each other', app_role, maintenance_role;
    END IF;
    FOR t IN
        SELECT c.relname, c.relowner, pg_get_userbyid(c.relowner) AS owner
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = target_schema AND c.relkind IN ('r', 'p')
    LOOP
        -- A member of the owner (the owner itself included) keeps every
        -- privilege on the table.
        FOREACH r IN ARRAY ARRAY[app_role, maintenance_role] LOOP
            IF pg_has_role(r, t.relowner, 'MEMBER') THEN
                RAISE EXCEPTION 'role % is a member of %, the owner of table %; an owner keeps every privilege',
                    r, t.owner, t.relname;
            END IF;
        END LOOP;
        EXECUTE format('REVOKE ALL ON %I.%I FROM %I, %I', target_schema, t.relname, app_role, maintenance_role);
        IF t.relname = '_sqlx_migrations' THEN
            EXECUTE format('GRANT SELECT ON %I.%I TO %I', target_schema, t.relname, app_role);
        ELSIF t.relname = ANY (append_only) THEN
            EXECUTE format('GRANT SELECT, INSERT ON %I.%I TO %I', target_schema, t.relname, app_role);
        ELSIF t.relname = ANY (no_delete) THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE ON %I.%I TO %I', target_schema, t.relname, app_role);
        ELSIF NOT (t.relname = ANY (audit_owned)) THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO %I', target_schema, t.relname, app_role);
        END IF;
    END LOOP;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I, %I', target_schema, app_role, maintenance_role);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', target_schema, app_role);
    -- The audit / outbox / webhook tables (and the maintenance role's purge
    -- rights) exactly as authn-audit specifies them (its unqualified table
    -- names resolve through the pinned search_path).
    EXECUTE format('SELECT %I.authn_audit_apply_least_privilege($1, $2)', target_schema)
        USING app_role, maintenance_role;
    -- No temporary objects (wave 6B, defence in depth after K-77): a
    -- temporary table or function is resolved before the schema whenever
    -- pg_temp is searched first, so a role that can create one can plant
    -- code that a SECURITY DEFINER function or trigger runs with its
    -- owner's rights. TEMPORARY is granted to PUBLIC by default, so it is
    -- revoked from PUBLIC too (the database should be dedicated to this
    -- service; another role that needs temporary tables gets an explicit
    -- GRANT TEMPORARY). Only the database owner (or a superuser) can revoke
    -- the PUBLIC default; for anyone else REVOKE only warns, so the result
    -- is verified below and the call fails instead of reporting success.
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, %I, %I',
        current_database(), app_role, maintenance_role);
    -- has_database_privilege alone only counts inherited privileges: a
    -- membership granted WITH INHERIT FALSE (or a NOINHERIT role) still
    -- lets the role SET ROLE to a role with TEMPORARY and keep the
    -- temporary objects after RESET ROLE. So every role it is a member of
    -- (itself included) is checked.
    FOREACH r IN ARRAY ARRAY[app_role, maintenance_role] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles g
                   WHERE pg_has_role(r, g.oid, 'MEMBER')
                     AND has_database_privilege(g.oid, current_database(), 'TEMPORARY')) THEN
            RAISE EXCEPTION 'role % can still create temporary objects in database %', r, current_database()
                USING HINT = format('Run REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, %I as the database owner '
                    '(and revoke any grant that gives the role TEMPORARY), then call '
                    'authn_apply_least_privilege again.', current_database(), r);
        END IF;
    END LOOP;
END;
$$;
