-- 1401 authn-webauthn: session-less registration ceremonies bound to an
-- enrollment link (ADM-05, K-11). Owner: authn-webauthn (range 1400-1499).
--
-- A break-glass admin created with an enrollment link has no session yet:
-- the registration ceremony is bound to the user and to the SHA-256 of the
-- single-use link token (binding_hash) instead of a session. A
-- registration ceremony must still be bound to its user AND to exactly one
-- of a session or a link hash, never to neither.
ALTER TABLE webauthn_ceremonies
    DROP CONSTRAINT webauthn_ceremonies_registration_binding_check,
    ADD CONSTRAINT webauthn_ceremonies_registration_binding_check
        CHECK (kind <> 'registration' OR (user_id IS NOT NULL
            AND ((session_id IS NOT NULL) <> (binding_hash IS NOT NULL))));
