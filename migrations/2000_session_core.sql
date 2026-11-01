-- 2000 session core (owner: authn-session).
--
-- * sessions.login_method: the primary login method of the session. Needed
--   to re-apply an organization's "allowed login methods" policy when the
--   active organization is switched (SES-17, ORG-07). authn-session sets it
--   on every session except impersonation sessions (ADM-04); a session
--   without it never passes a method-restricting organization policy.
-- * sessions.scopes: the `scope` claim of the session's access tokens
--   (SES-08); Phase 2 (OAuth provider) narrows it per client.
-- * auth_challenges.primary_method: the primary method that started a
--   pending login (SES-02, SES-22), carried into the session on completion.
-- * Indexes for the cleanup job (OPS-06) and the grace-window successor
--   wipe (SES-05).
-- * sessions_impersonator_active_idx: revoking every session of a user also
--   ends the impersonation sessions that user started as an admin (ADM-04);
--   the index keeps that lookup off a sequential scan.

ALTER TABLE sessions ADD COLUMN login_method text;
ALTER TABLE sessions ADD COLUMN scopes text[] NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD CONSTRAINT sessions_login_method_check CHECK (
    login_method IN ('password', 'passkey', 'magic_link', 'email_code', 'social'));
ALTER TABLE sessions ADD CONSTRAINT sessions_scopes_check CHECK (cardinality(scopes) <= 32);

ALTER TABLE auth_challenges ADD COLUMN primary_method text;
ALTER TABLE auth_challenges ADD CONSTRAINT auth_challenges_primary_method_check CHECK (
    primary_method IN ('password', 'passkey', 'magic_link', 'email_code', 'social'));

CREATE INDEX sessions_revoked_idx ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX refresh_tokens_successor_idx ON refresh_tokens (used_at)
    WHERE successor_ciphertext IS NOT NULL;
CREATE INDEX sessions_impersonator_active_idx ON sessions (impersonator_user_id)
    WHERE impersonator_user_id IS NOT NULL AND revoked_at IS NULL;
