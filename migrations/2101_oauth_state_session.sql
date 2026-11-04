-- 2101 link flows are bound to the session that started them (owner:
-- authn-oidc-client; K-03, SOC-06, SES-13).
--
-- The callback of a link flow re-validates this session (still active,
-- same user) before linking: a sign-out, password reset or "sign out
-- everywhere" during the flow ends it. No foreign key: `sessions` belongs
-- to authn-session; the check goes through the `SessionLiveness` hook.
--
-- Link flows in flight while this migration runs (at most `state_ttl`,
-- 10 minutes by default) have no session to re-validate: they are ended
-- here and the user simply starts linking again.

DELETE FROM oauth_states WHERE flow = 'link';
ALTER TABLE oauth_states ADD COLUMN session_id uuid;
ALTER TABLE oauth_states ADD CONSTRAINT oauth_states_link_session_check
    CHECK (flow <> 'link' OR session_id IS NOT NULL);
