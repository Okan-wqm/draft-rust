-- 1703 keyed audit hash chain (AUD-02, K-77). Owner: authn-audit.
--
-- Before: hash = SHA-256(prev_hash || canonical_json(record)). Anyone who
-- can write to the database can recompute the whole chain; only anchors kept
-- outside the database detected that.
--
-- Now: hash = HMAC-SHA-256(K_v, prev_hash || canonical_json(record)), where
-- K_v is version v of the chain key (derived from crypto.hmac_root_key, never
-- stored in the database). Without the key a rewritten chain does not verify.
--
--   * audit_events.chain_key_version: v of the row; NULL = legacy SHA-256 row
--     written before this migration. Existing rows are never re-hashed
--     (immutability); they keep verifying with the legacy rule.
--   * audit_chain_head.key_version: version of the newest event. Writers
--     use max(head version, configured version), so versions never decrease
--     (also during a rolling restart that rotates the key).
--   * Every change of the version at the head (legacy -> v1, v1 -> v2, ...)
--     records a 'chain_key_switch' checkpoint at the first event of the new
--     version (trigger below, which runs as the table owner: the
--     application role has no INSERT on audit_chain_checkpoints).
--
-- The verifier rejects an unkeyed or lower-version row after a keyed one
-- (downgrade), so a forger cannot fall back to the unkeyed rule for any row
-- after the first keyed row.

ALTER TABLE audit_events ADD COLUMN chain_key_version smallint;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_chain_key_version_check
    CHECK (chain_key_version >= 1);

ALTER TABLE audit_chain_head ADD COLUMN key_version smallint;
ALTER TABLE audit_chain_head ADD CONSTRAINT audit_chain_head_key_version_check
    CHECK (key_version >= 1);

ALTER TABLE audit_chain_checkpoints ADD COLUMN key_version smallint;
ALTER TABLE audit_chain_checkpoints DROP CONSTRAINT audit_chain_checkpoints_reason_check;
ALTER TABLE audit_chain_checkpoints ADD CONSTRAINT audit_chain_checkpoints_reason_check
    CHECK (reason IN ('retention_purge', 'manual', 'chain_key_switch'));
ALTER TABLE audit_chain_checkpoints ADD CONSTRAINT audit_chain_checkpoints_key_version_check
    CHECK ((reason = 'chain_key_switch') = (key_version IS NOT NULL) AND (key_version IS NULL OR key_version >= 1));

-- The trigger function runs as the table owner (SECURITY DEFINER), so its
-- name lookup must not reach objects the caller can plant: the search_path
-- is the migration schema followed by pg_temp *last* (otherwise pg_temp is
-- searched first and a session's temporary `audit_chain_checkpoints` table,
-- with a trigger of its own, would run the caller's SQL with the owner's
-- rights), and every name is schema-qualified.
DO $migration$
DECLARE
    target_schema name := current_schema();
BEGIN
    IF target_schema IS NULL THEN
        RAISE EXCEPTION 'migration 1703 needs a schema on the search_path';
    END IF;
    EXECUTE format($fn$
CREATE FUNCTION %1$I.authn_audit_chain_key_switch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = %1$I, pg_temp AS $body$
BEGIN
    IF NEW.key_version IS NOT NULL
       AND NEW.key_version IS DISTINCT FROM OLD.key_version
       AND NEW.last_seq > OLD.last_seq THEN
        INSERT INTO %1$I.audit_chain_checkpoints (seq, hash, reason, key_version, created_at)
        VALUES (NEW.last_seq, NEW.last_hash, 'chain_key_switch', NEW.key_version, NEW.updated_at)
        ON CONFLICT (seq) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$body$$fn$, target_schema);
END
$migration$;
REVOKE ALL ON FUNCTION authn_audit_chain_key_switch() FROM PUBLIC;

CREATE TRIGGER audit_chain_head_key_switch AFTER UPDATE ON audit_chain_head
    FOR EACH ROW EXECUTE FUNCTION authn_audit_chain_key_switch();
