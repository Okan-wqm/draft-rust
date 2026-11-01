-- 1200 account lifecycle additions. Owner: authn-account (range 1200-1299).
-- Tables touched: account_deletions (owned by authn-account) and the new
-- email_reservations table. No other module's table is changed.

-- ACC-09: the status an account returns to when a scheduled deletion is
-- cancelled (an unverified account must not become `active` by cancelling).
-- NULL only for rows written before this migration.
ALTER TABLE account_deletions
    ADD COLUMN previous_status text,
    ADD CONSTRAINT account_deletions_previous_status_check CHECK (
        previous_status IN ('pending_verification', 'active', 'suspended', 'disabled'));

-- Deletion history of one user (data export, ACC-10).
CREATE INDEX account_deletions_user_idx ON account_deletions (user_id);

-- ACC-07: after an e-mail change the previous address stays reserved for its
-- owner while the "revert" link is valid. Otherwise an attacker who changed
-- the address could register a new account with the old address and make
-- the revert impossible. Reserved addresses are treated like registered ones
-- (registration and e-mail change answer exactly as for an existing account).
-- Personal data: removed with the user (cascade) or when the reservation
-- expires (cleanup job).
CREATE TABLE email_reservations (
    -- `users.email_normalized` form of the reserved address.
    email_normalized  text        PRIMARY KEY,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    reserved_until    timestamptz NOT NULL,
    created_at        timestamptz NOT NULL,
    CONSTRAINT email_reservations_email_check CHECK (octet_length(email_normalized) BETWEEN 3 AND 254),
    CONSTRAINT email_reservations_expiry_check CHECK (reserved_until > created_at)
);
CREATE INDEX email_reservations_user_idx ON email_reservations (user_id);
CREATE INDEX email_reservations_expiry_idx ON email_reservations (reserved_until);
