-- 1500 authn-org: tenant-isolation and privilege hardening, cleanup and
-- pagination indexes. Owner: authn-org (range 1500-1599).
-- ORG-02, ORG-04, ORG-08, ORG-09, ORG-10, ORG-12, ARC-10, OPS-06.
--
-- Everything below is enforced in application code as well; the database
-- constraints are the second line of defence (a forgotten check in a future
-- code path must not be able to break these invariants).

-- ORG-08 / ORG-09: every API key has exactly one owner — a service account
-- of the organization or a member acting inside the organization.
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_single_owner_check CHECK (num_nonnulls(service_account_id, user_id) = 1);

-- ARC-10: a member's personal key is tied to the membership. A user can only
-- hold keys in organizations they belong to, and removing the membership
-- deletes the keys in the same statement.
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_member_fk FOREIGN KEY (org_id, user_id)
        REFERENCES memberships (org_id, user_id) ON DELETE CASCADE;

-- ORG-04 / ORG-09: service accounts are never owners (owner-only operations
-- need a human with step-up).
ALTER TABLE service_accounts
    ADD CONSTRAINT service_accounts_not_owner_check
        CHECK (role_id <> '01900000-0000-7000-8000-000000000001'::uuid);

-- ORG-04 / ORG-12: the owner-only permissions exist on the built-in owner
-- role only; custom roles can never carry them.
CREATE FUNCTION authn_check_custom_role_permission() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.permission IN ('org:delete', 'org:transfer_ownership')
       AND NOT EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND is_builtin) THEN
        RAISE EXCEPTION 'owner-only permission on a custom role'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'role_permissions_owner_only_check';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER role_permissions_owner_only BEFORE INSERT OR UPDATE ON role_permissions
    FOR EACH ROW EXECUTE FUNCTION authn_check_custom_role_permission();

-- ORG-02: an existing organization always keeps at least one active owner.
-- Checked at commit (deferred) so that a transfer may demote and promote in
-- one transaction. Deleting the organization itself (cascade) is allowed.
CREATE FUNCTION authn_check_org_has_owner() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM organizations WHERE id = OLD.org_id)
       AND NOT EXISTS (
           SELECT 1 FROM memberships
            WHERE org_id = OLD.org_id
              AND role_id = '01900000-0000-7000-8000-000000000001'::uuid
              AND status = 'active') THEN
        RAISE EXCEPTION 'organization must keep an active owner'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'org_last_owner_check';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER memberships_last_owner
    AFTER UPDATE OF role_id, status, org_id OR DELETE ON memberships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION authn_check_org_has_owner();

-- ORG-12 / OPS-06: purge job for organizations whose grace period ended.
CREATE INDEX organizations_deletion_due_idx ON organizations (deletion_scheduled_for)
    WHERE status = 'pending_deletion';

-- ORG-02: owner counting and role usage per organization.
CREATE INDEX memberships_org_role_idx ON memberships (org_id, role_id) WHERE status = 'active';

-- Keyset pagination (created_at, id) per organization.
CREATE INDEX memberships_org_created_idx ON memberships (org_id, created_at, id);
CREATE INDEX service_accounts_org_created_idx ON service_accounts (org_id, created_at, id);
CREATE INDEX invitations_org_created_idx ON invitations (org_id, created_at, id);
CREATE INDEX api_keys_org_created_idx ON api_keys (org_id, created_at, id);

-- Expiry of pending invitations (cleanup job).
CREATE INDEX invitations_pending_expiry_idx ON invitations (expires_at) WHERE status = 'pending';
