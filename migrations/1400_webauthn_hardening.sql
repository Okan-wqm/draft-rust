-- 1400 authn-webauthn: clone-detection marker, discoverability hint and
-- ceremony binding invariants. Owner: authn-webauthn (range 1400-1499).
-- PKY-01, PKY-02, PKY-04, PKY-05.

-- PKY-05: set when a signature-counter regression (or a change of the
-- backup-eligibility flag) was observed for the credential. Shown in the
-- passkey list so the user can remove a possibly cloned authenticator.
-- PKY-02/04: client-reported `credProps.rk` at registration (unsigned UX
-- hint only: NULL = unknown). Never used for security decisions.
ALTER TABLE webauthn_credentials
    ADD COLUMN clone_suspected_at timestamptz,
    ADD COLUMN discoverable       boolean;

-- PKY-01: a ceremony is always bound to its owner.
--  * registration ceremonies are started by a logged-in user and are bound
--    to that user's session (the finish request must come from it);
--  * step-up ceremonies are bound to the session they elevate;
--  * every authentication ceremony carries the hash of a client binding
--    token (cookie / native client) so a leaked ceremony id is useless;
--  * kind and purpose are consistent.
ALTER TABLE webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_registration_binding_check
        CHECK (kind <> 'registration' OR (user_id IS NOT NULL AND session_id IS NOT NULL)),
    ADD CONSTRAINT webauthn_ceremonies_step_up_binding_check
        CHECK (purpose <> 'step_up' OR (user_id IS NOT NULL AND session_id IS NOT NULL)),
    ADD CONSTRAINT webauthn_ceremonies_auth_binding_check
        CHECK (kind = 'registration' OR binding_hash IS NOT NULL),
    ADD CONSTRAINT webauthn_ceremonies_purpose_kind_check
        CHECK ((kind = 'registration') = (purpose = 'register')),
    ADD CONSTRAINT webauthn_ceremonies_consumed_check
        CHECK (consumed_at IS NULL OR consumed_at >= created_at);
