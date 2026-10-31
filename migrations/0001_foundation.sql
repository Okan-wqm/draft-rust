-- 0001 foundation: shared helper functions.
-- Owner: architect (authn-core / authn-store). Range 0001-0099.
--
-- Conventions used by every migration (see docs/architecture/contracts.md):
--   * primary keys are application-generated UUIDv7 (`uuid`), never serials
--     exposed to clients (ARC-05);
--   * every timestamp is `timestamptz` (UTC); application code passes times
--     from the injected Clock, DB defaults are only a fallback;
--   * enumerations are `text` + CHECK constraints (no PostgreSQL ENUM types);
--   * secrets are never stored in clear text: tokens/codes as 32-byte hashes,
--     reversible secrets as envelope ciphertext (`*_ciphertext bytea`).

-- Keeps `updated_at` current on UPDATE.
CREATE FUNCTION authn_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

-- Generic guard for append-only tables (TRUNCATE is always refused).
CREATE FUNCTION authn_forbid_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only; TRUNCATE is not allowed', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
