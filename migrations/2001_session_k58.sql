-- 2001 session K-58 (owner: authn-session).
--
-- * refresh_tokens.access_token_id: the `jti` of the access token issued
--   together with this refresh token (login, refresh, server-side rotation
--   after a privilege change, grace-window retry). A privilege change of a
--   native session (organization switch, step-up) authenticated with an
--   access token that is not the one paired with the family's live refresh
--   token was overtaken by a concurrent rotation: it is refused (401)
--   instead of retiring the refresh token another response has just handed
--   out — which the client would later present as a "replay" and lose the
--   session (SES-05, SES-13, SES-17). NULL for rows written before this
--   migration (no check).
-- * authn_signing_keys_changed(): every change of signing_keys (rotation,
--   activation, emergency rotation, revocation — application, other
--   instances or the CLI) sends a notification on channel
--   `authn_signing_keys` at commit. Every instance's session service
--   listens and drops its signing-key cache at once (CRY-10, SES-09): an
--   emergency-revoked key stops verifying everywhere within the
--   notification latency instead of `session.signing_key_cache_ttl`.
--   signing_keys belongs to the architect's schema (0011); the trigger only
--   observes it (contract-change-requests.md, "## authn-session", K-58).
--   The payload is empty: the listener reloads from the table.

ALTER TABLE refresh_tokens ADD COLUMN access_token_id uuid;

CREATE FUNCTION authn_signing_keys_changed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path FROM CURRENT
AS $$
BEGIN
    PERFORM pg_notify('authn_signing_keys', '');
    RETURN NULL;
END;
$$;

CREATE TRIGGER signing_keys_notify_change
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON signing_keys
    FOR EACH STATEMENT EXECUTE FUNCTION authn_signing_keys_changed();
