-- 1705 scheduled audit chain checkpoints (K-107). Owner: authn-audit.
--
-- The server records a 'scheduled' checkpoint of the chain head once per
-- audit.checkpoint_interval (default 24h, one across every instance) and
-- logs it as an external anchor for `verify-audit-chain --anchor`.
--
-- Expand-only (contracts §6): the CHECK only gains a value. A binary of the
-- previous release keeps verifying the chain (it matches checkpoints by
-- seq/hash and treats only 'chain_key_switch' specially).
ALTER TABLE audit_chain_checkpoints DROP CONSTRAINT audit_chain_checkpoints_reason_check;
ALTER TABLE audit_chain_checkpoints ADD CONSTRAINT audit_chain_checkpoints_reason_check
    CHECK (reason IN ('retention_purge', 'manual', 'chain_key_switch', 'scheduled'));

-- The due check reads the newest scheduled checkpoint.
CREATE INDEX audit_chain_checkpoints_scheduled_idx
    ON audit_chain_checkpoints (created_at) WHERE reason = 'scheduled';
