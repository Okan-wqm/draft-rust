-- 1600 authn-protect: single-statement GCRA decisions and risk lookups.
-- Owner: authn-protect (range 1600-1699). PRT-01, RSK-02.

-- The PostgreSQL rate limiter decides inside one
--   INSERT … ON CONFLICT (key_hash) DO UPDATE SET … RETURNING
-- statement. PostgreSQL 16 cannot return the *old* row from an upsert, so
-- the outcome of the conditional update (admitted or not) is stored next to
-- the theoretical arrival time and returned with it. The row lock taken by
-- ON CONFLICT DO UPDATE serialises concurrent callers of the same key.
ALTER TABLE rate_limit_buckets
    ADD COLUMN allowed boolean NOT NULL DEFAULT true;

-- Impossible-travel check (RSK-02): most recent located login of a user.
CREATE INDEX known_devices_user_last_seen_idx
    ON known_devices (user_id, last_seen_at DESC);

-- Purge of consumed / expired proof-of-work challenges (OPS-06) already uses
-- captcha_pow_challenges_expiry_idx; soft locks are purged by locked_until.
CREATE INDEX login_soft_locks_locked_until_idx
    ON login_soft_locks (locked_until);
