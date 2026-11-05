-- 2900 authn-server: least-privilege roles for the whole schema (OPS-10,
-- AUD-02, K-42). Owner: authn-server (range 2900-2999).
--
-- Run once as the schema owner after the roles exist, and again after every
-- release that adds tables (it is idempotent):
--
--   CREATE ROLE authn_app LOGIN PASSWORD '...';
--   CREATE ROLE authn_maintenance LOGIN PASSWORD '...';
--   SELECT authn_apply_least_privilege('authn_app', 'authn_maintenance');
--
-- Then run `serve` with database.url = the application role and
-- database.maintenance_url = the maintenance role, and migrations
-- (`rust-authentication migrate`) with the owner. Neither role may own a
-- table (an owner has every privilege). Runbook:
-- docs/operations/least-privilege.md.
--
-- * Every privilege either role has on any table of this schema is revoked
--   first, so nothing beyond the list below survives (e.g. from
--   GRANT ALL ON ALL TABLES).
-- * app_role: SELECT, INSERT, UPDATE, DELETE on the module tables; never
--   TRUNCATE, REFERENCES or TRIGGER. Append-only tables get SELECT, INSERT
--   only: admin_action_reasons, admin_reason_restrictions,
--   admin_reason_restriction_periods (their triggers are a second,
--   independent barrier); admin_approvals SELECT, INSERT, UPDATE (no
--   DELETE: rows only go by cascade with an erased user). A table listed
--   here that does not exist yet is simply skipped. The audit, outbox and webhook
--   tables get exactly what authn_audit_apply_least_privilege (1700)
--   grants (incl. audit_subject_view_holds, 1701): no UPDATE / DELETE on
--   audit_events. _sqlx_migrations: SELECT
--   (readiness check of the schema version).
-- * maintenance_role: only the audit retention purge / checkpoints of 1700
--   (DELETE on audit_events inside the documented escape hatch). Rows that
--   reference purged events (admin_action_reasons, admin_reason_restrictions)
--   go with them by ON DELETE CASCADE, which PostgreSQL runs with the
--   referencing table owner's rights: no grant on them is needed.
-- * Privileges that no REVOKE can remove are refused (wave 3A audit): a
--   superuser / BYPASSRLS role, a role that is a member of a table owner
--   (it inherits the owner's rights) or of pg_read_all_data /
--   pg_write_all_data, and an application role that is a member of the
--   maintenance role or vice versa.
-- * Names are schema-qualified and the function pins the search_path of
--   the migration (SET search_path FROM CURRENT), so an object planted on
--   the caller's search_path cannot be picked up instead of this schema's
--   (SECURITY INVOKER: it runs with the caller's, i.e. the schema owner's,
--   rights; never SECURITY DEFINER).
CREATE FUNCTION authn_apply_least_privilege(app_role name, maintenance_role name)
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
        'admin_reason_restriction_periods'];
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
END;
$$;
