-- 2203 authn-admin: staff roles (K-93, ADM-09).
-- Owner: authn-admin (range 2200-2299; the only writer of this table).
--
-- `users.is_platform_admin` keeps its meaning for every other module: the
-- account is **staff** (admin console access; phishing-resistant MFA at
-- login, no trusted devices, ...). What a staff member may do in the admin
-- API is decided by its role, one of:
--
--   support_readonly  read accounts only
--   support           + account recovery, unlock, revoke sessions, impersonation
--   security          + suspension, emergency operations, audit, four-eyes decisions
--   platform_admin    everything, including staff role changes
--
-- The admin guard reads the role on every request together with the
-- account row; an account without a row here has **no** admin permission
-- (fail closed), whatever `is_platform_admin` says. A row requires
-- `is_platform_admin`, and a break-glass account is always
-- `platform_admin` (the recovery path of last resort is unchanged); both
-- are enforced by the trigger below. Rows go with the account (cascade).
CREATE TABLE admin_staff_roles (
    user_id     uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    role        text        NOT NULL,
    granted_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    CONSTRAINT admin_staff_roles_role_check
        CHECK (role IN ('support_readonly', 'support', 'security', 'platform_admin'))
);

CREATE FUNCTION authn_admin_staff_roles_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    staff boolean;
    break_glass boolean;
BEGIN
    SELECT is_platform_admin, is_break_glass INTO staff, break_glass
    FROM users WHERE id = NEW.user_id;
    IF staff IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'admin_staff_roles: % is not a staff account', NEW.user_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF break_glass AND NEW.role <> 'platform_admin' THEN
        RAISE EXCEPTION 'admin_staff_roles: a break-glass account is always platform_admin'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER admin_staff_roles_guard BEFORE INSERT OR UPDATE ON admin_staff_roles
    FOR EACH ROW EXECUTE FUNCTION authn_admin_staff_roles_guard();

-- Backward compatibility: every existing platform admin (break-glass
-- accounts included) keeps every permission it had.
INSERT INTO admin_staff_roles (user_id, role, granted_at, updated_at)
SELECT id, 'platform_admin', now(), now() FROM users WHERE is_platform_admin;
