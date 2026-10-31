-- 0012 built-in roles and their permissions (ORG-03). Owner: authn-org.
-- Ids are fixed so code and tests can reference them; they never change.
--
--   owner   01900000-0000-7000-8000-000000000001
--   admin   01900000-0000-7000-8000-000000000002
--   member  01900000-0000-7000-8000-000000000003
--   billing 01900000-0000-7000-8000-000000000004
--   viewer  01900000-0000-7000-8000-000000000005

INSERT INTO roles (id, org_id, key, name, description, is_builtin) VALUES
    ('01900000-0000-7000-8000-000000000001', NULL, 'owner', 'Owner',
     'Full control including deletion and ownership transfer.', true),
    ('01900000-0000-7000-8000-000000000002', NULL, 'admin', 'Admin',
     'Manages members, roles, policies, keys and webhooks.', true),
    ('01900000-0000-7000-8000-000000000003', NULL, 'member', 'Member',
     'Regular member.', true),
    ('01900000-0000-7000-8000-000000000004', NULL, 'billing', 'Billing',
     'Manages billing.', true),
    ('01900000-0000-7000-8000-000000000005', NULL, 'viewer', 'Viewer',
     'Read-only access.', true);

INSERT INTO role_permissions (role_id, permission)
SELECT '01900000-0000-7000-8000-000000000001'::uuid, p FROM unnest(ARRAY[
    'org:read', 'org:update', 'org:delete', 'org:transfer_ownership',
    'members:read', 'members:invite', 'members:update', 'members:remove',
    'roles:read', 'roles:manage',
    'policies:read', 'policies:manage',
    'domains:read', 'domains:manage',
    'api_keys:read', 'api_keys:manage',
    'service_accounts:read', 'service_accounts:manage',
    'webhooks:read', 'webhooks:manage',
    'audit:read',
    'billing:read', 'billing:manage'
]) AS p
UNION ALL
SELECT '01900000-0000-7000-8000-000000000002'::uuid, p FROM unnest(ARRAY[
    'org:read', 'org:update',
    'members:read', 'members:invite', 'members:update', 'members:remove',
    'roles:read', 'roles:manage',
    'policies:read', 'policies:manage',
    'domains:read', 'domains:manage',
    'api_keys:read', 'api_keys:manage',
    'service_accounts:read', 'service_accounts:manage',
    'webhooks:read', 'webhooks:manage',
    'audit:read',
    'billing:read'
]) AS p
UNION ALL
SELECT '01900000-0000-7000-8000-000000000003'::uuid, p FROM unnest(ARRAY[
    'org:read', 'members:read'
]) AS p
UNION ALL
SELECT '01900000-0000-7000-8000-000000000004'::uuid, p FROM unnest(ARRAY[
    'org:read', 'billing:read', 'billing:manage'
]) AS p
UNION ALL
SELECT '01900000-0000-7000-8000-000000000005'::uuid, p FROM unnest(ARRAY[
    'org:read', 'members:read', 'roles:read', 'policies:read', 'domains:read'
]) AS p;
