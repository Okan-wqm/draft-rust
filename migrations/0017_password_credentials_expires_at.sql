-- 0017 optional expiry of a stored password.
-- Owner: architect (authn-store owns password_credentials). ADM-05, K-110.
--
-- The break-glass password printed by `create-admin` is a one-time initial
-- password: it must be changed at first login (must_change) and stops
-- working when it is left unused for too long. expires_at is that bound;
-- NULL (every existing row and every password a user or an admin sets)
-- means the password does not expire. Setting a new password clears it.
-- Expand-only: a nullable column without a default rewrites nothing and an
-- older binary that does not know the column keeps working.

ALTER TABLE password_credentials ADD COLUMN expires_at timestamptz;
