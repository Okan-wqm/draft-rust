-- 0014 documentation of the reserved DEK table and an index for the ACC-06
-- unlock job. Owner: architect. CRY-08, ACC-06, OPS-06.
--
-- data_encryption_keys: envelope encryption (CRY-08) uses one fresh DEK per
-- value, wrapped by the KEK and carried *inside* the envelope
-- (version || kek_id || wrapped_dek || nonce || ciphertext). Decryption needs
-- no lookup here and KEK rotation re-wraps each row in place
-- (EnvelopeCipher::rewrap). The table is therefore unused; it is kept, empty,
-- as a reserved slot for a future KMS-backed wrapped-DEK cache. The comment
-- of 0011 ("ciphertexts reference the DEK id") is superseded by this note.
COMMENT ON TABLE data_encryption_keys IS
    'Reserved, unused in Phase 1: envelopes carry their own KEK-wrapped DEK '
    '(CRY-08). Kept for a future KMS wrapped-DEK cache; no code reads or writes it.';

-- UserRepository::claim_next(LockExpiredAt): the unlock job scans locked
-- accounts by lock end (FOR UPDATE SKIP LOCKED, oldest first).
CREATE INDEX users_locked_until_idx ON users (locked_until, id) WHERE status = 'locked';
