-- 1300 authn-mfa: per-user verification lock, one e-mail factor per user,
-- cleanup indexes. Owner: authn-mfa (range 1300-1399). MFA-03, MFA-05, OPS-06.

-- Failed second-factor verifications of a user across all factors in the
-- current window (`mfa.per_user_failures`) and the temporary lock engaged
-- when the window's limit is reached (`mfa.lockout_duration`). Every
-- verification locks this row (`SELECT ... FOR UPDATE`), which serializes
-- concurrent attempts of one user: counters are exact and a TOTP step can
-- never be accepted twice.
ALTER TABLE mfa_user_settings
    ADD COLUMN failed_attempts       integer     NOT NULL DEFAULT 0,
    ADD COLUMN failure_window_start  timestamptz,
    ADD COLUMN locked_until          timestamptz,
    ADD CONSTRAINT mfa_user_settings_failed_check CHECK (failed_attempts >= 0);

-- At most one e-mail factor (pending or active) per user (MFA-05).
CREATE UNIQUE INDEX mfa_factors_one_email_idx ON mfa_factors (user_id)
    WHERE kind = 'email' AND status <> 'disabled';

-- Cleanup of abandoned enrollments and expired / revoked trusted devices.
CREATE INDEX mfa_factors_pending_idx ON mfa_factors (created_at) WHERE status = 'pending';
CREATE INDEX trusted_devices_expiry_idx ON trusted_devices (expires_at);
