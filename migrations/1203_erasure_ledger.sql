-- 1203 erasure ledger (K-108, ACC-09, ACC-05). Owner: authn-account.
--
-- One row per erased account, written in the erasure transaction. A restored
-- backup brings erased accounts back (KVKK md. 7 / GDPR art. 17 require
-- erasing them again), but it also brings back an older copy of this table:
-- the authoritative copy lives OUTSIDE the database. The operator exports new
-- rows regularly (`rust-authentication export-erasures --since <time>`, JSON
-- lines; overlapping exports are harmless, the ledger is keyed by account) to
-- storage that is not restored with the database, and after a restore runs
-- `rust-authentication reapply-erasures --from <file>` before starting the
-- server. The cursor is a time, not a sequence: a restored database would
-- hand out already-exported sequence numbers again.
--
-- No personal data: a random account id that, after the erasure, no other
-- row refers to (like account_deletions), the time and a reason code. No
-- foreign key: the row must outlive the account.
CREATE TABLE erasure_ledger (
    user_id    uuid        PRIMARY KEY,
    erased_at  timestamptz NOT NULL,
    reason     text        NOT NULL,
    CONSTRAINT erasure_ledger_reason_check CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$')
);
-- Incremental export (`--since`).
CREATE INDEX erasure_ledger_erased_at_idx ON erasure_ledger (erased_at, user_id);
