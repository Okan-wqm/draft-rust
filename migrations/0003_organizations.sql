-- 0003 organizations, RBAC, invitations, domains, policies, service
-- accounts, API keys. Owner: authn-org (ORG-*).
--
-- Tenant isolation (ARC-10, ORG-10) is enforced in SQL as well as in code:
-- composite foreign keys and triggers make cross-organization references
-- impossible even if a query forgets an `org_id` filter on write.

CREATE TABLE organizations (
    id                      uuid        PRIMARY KEY,
    slug                    text        NOT NULL,
    name                    text        NOT NULL,
    status                  text        NOT NULL DEFAULT 'active',
    deletion_scheduled_for  timestamptz,
    created_by              uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT organizations_slug_check CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT organizations_name_check CHECK (char_length(name) BETWEEN 1 AND 200),
    CONSTRAINT organizations_status_check CHECK (status IN ('active', 'suspended', 'pending_deletion')),
    CONSTRAINT organizations_deletion_check
        CHECK ((status = 'pending_deletion') = (deletion_scheduled_for IS NOT NULL)),
    CONSTRAINT organizations_slug_key UNIQUE (slug)
);
CREATE TRIGGER organizations_touch BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Built-in roles have org_id NULL (seeded in 0012); custom roles belong to
-- exactly one organization.
CREATE TABLE roles (
    id           uuid        PRIMARY KEY,
    org_id       uuid        REFERENCES organizations (id) ON DELETE CASCADE,
    key          text        NOT NULL,
    name         text        NOT NULL,
    description  text,
    is_builtin   boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT roles_key_check CHECK (key ~ '^[a-z][a-z0-9_]{0,62}$'),
    CONSTRAINT roles_name_check CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT roles_description_check CHECK (char_length(description) <= 500),
    CONSTRAINT roles_builtin_scope_check CHECK (is_builtin = (org_id IS NULL))
);
CREATE UNIQUE INDEX roles_builtin_key_idx ON roles (key) WHERE org_id IS NULL;
CREATE UNIQUE INDEX roles_org_key_idx ON roles (org_id, key) WHERE org_id IS NOT NULL;
CREATE TRIGGER roles_touch BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Permissions are `resource:action` strings (ORG-03).
CREATE TABLE role_permissions (
    role_id     uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission  text NOT NULL,
    PRIMARY KEY (role_id, permission),
    CONSTRAINT role_permissions_format_check
        CHECK (permission ~ '^[a-z][a-z0-9_]{0,31}:[a-z][a-z0-9_]{0,31}$')
);

-- Raises unless the role is built-in or belongs to NEW.org_id.
CREATE FUNCTION authn_check_role_tenant() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    role_org uuid;
    found    boolean;
BEGIN
    SELECT org_id, true INTO role_org, found FROM roles WHERE id = NEW.role_id;
    IF found IS NULL THEN
        RAISE EXCEPTION 'role does not exist' USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF role_org IS NOT NULL AND role_org <> NEW.org_id THEN
        RAISE EXCEPTION 'role belongs to another organization'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'role_tenant_check';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE memberships (
    id          uuid        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id     uuid        NOT NULL REFERENCES roles (id) ON DELETE RESTRICT,
    status      text        NOT NULL DEFAULT 'active',
    invited_by  uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT memberships_status_check CHECK (status IN ('active', 'suspended')),
    CONSTRAINT memberships_org_user_key UNIQUE (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);
CREATE INDEX memberships_role_idx ON memberships (role_id);
CREATE TRIGGER memberships_role_tenant BEFORE INSERT OR UPDATE OF role_id, org_id ON memberships
    FOR EACH ROW EXECUTE FUNCTION authn_check_role_tenant();
CREATE TRIGGER memberships_touch BEFORE UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

CREATE TABLE invitations (
    id                uuid        PRIMARY KEY,
    org_id            uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email             text        NOT NULL,
    email_normalized  text        NOT NULL,
    role_id           uuid        NOT NULL REFERENCES roles (id) ON DELETE RESTRICT,
    -- SHA-256 of the 256-bit invitation token (ORG-05).
    token_hash        bytea       NOT NULL,
    status            text        NOT NULL DEFAULT 'pending',
    invited_by        uuid        REFERENCES users (id) ON DELETE SET NULL,
    send_count        integer     NOT NULL DEFAULT 1,
    last_sent_at      timestamptz NOT NULL DEFAULT now(),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    accepted_at       timestamptz,
    accepted_by       uuid        REFERENCES users (id) ON DELETE SET NULL,
    revoked_at        timestamptz,
    CONSTRAINT invitations_email_check CHECK (octet_length(email_normalized) BETWEEN 3 AND 254),
    CONSTRAINT invitations_token_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT invitations_status_check CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    CONSTRAINT invitations_send_count_check CHECK (send_count >= 1),
    CONSTRAINT invitations_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT invitations_accepted_check CHECK ((status = 'accepted') = (accepted_at IS NOT NULL)),
    CONSTRAINT invitations_revoked_check CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT invitations_token_hash_key UNIQUE (token_hash)
);
CREATE UNIQUE INDEX invitations_one_pending_idx ON invitations (org_id, email_normalized)
    WHERE status = 'pending';
CREATE INDEX invitations_org_idx ON invitations (org_id, created_at DESC);
CREATE TRIGGER invitations_role_tenant BEFORE INSERT OR UPDATE OF role_id, org_id ON invitations
    FOR EACH ROW EXECUTE FUNCTION authn_check_role_tenant();

-- Domain verification via DNS TXT `_authn-verification.<domain>` (ORG-06).
CREATE TABLE org_domains (
    id                  uuid        PRIMARY KEY,
    org_id              uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain              text        NOT NULL,
    -- Random value published in DNS (public by design, not a secret).
    verification_value  text        NOT NULL,
    status              text        NOT NULL DEFAULT 'pending',
    auto_join           boolean     NOT NULL DEFAULT false,
    -- Phase 2: force SSO for this domain.
    sso_required        boolean     NOT NULL DEFAULT false,
    last_checked_at     timestamptz,
    verified_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_domains_domain_check
        CHECK (domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$'
               AND octet_length(domain) <= 253),
    CONSTRAINT org_domains_value_check CHECK (char_length(verification_value) BETWEEN 16 AND 128),
    CONSTRAINT org_domains_status_check CHECK (status IN ('pending', 'verified', 'failed')),
    CONSTRAINT org_domains_verified_check CHECK ((status = 'verified') = (verified_at IS NOT NULL)),
    CONSTRAINT org_domains_policy_check CHECK (status = 'verified' OR (NOT auto_join AND NOT sso_required)),
    CONSTRAINT org_domains_org_domain_key UNIQUE (org_id, domain)
);
-- A domain can be verified by one organization only.
CREATE UNIQUE INDEX org_domains_verified_domain_idx ON org_domains (domain) WHERE status = 'verified';

-- Security policy per organization (ORG-07). NULL arrays mean "no
-- restriction".
CREATE TABLE org_policies (
    org_id                           uuid        PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    mfa_required                     boolean     NOT NULL DEFAULT false,
    phishing_resistant_mfa_required  boolean     NOT NULL DEFAULT false,
    allowed_login_methods            text[],
    allowed_mfa_factors              text[],
    max_session_lifetime_seconds     integer,
    ip_allowlist                     cidr[],
    trusted_devices_allowed          boolean     NOT NULL DEFAULT true,
    -- Allowed authenticator AAGUIDs for passkeys (PKY-08).
    allowed_aaguids                  uuid[],
    updated_by                       uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at                       timestamptz NOT NULL DEFAULT now(),
    updated_at                       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_policies_phishing_check CHECK (NOT phishing_resistant_mfa_required OR mfa_required),
    CONSTRAINT org_policies_login_methods_check CHECK (allowed_login_methods <@
        ARRAY['password', 'passkey', 'magic_link', 'email_code', 'social']::text[]),
    CONSTRAINT org_policies_factors_check CHECK (allowed_mfa_factors <@
        ARRAY['totp', 'webauthn', 'recovery_code', 'email', 'sms']::text[]),
    CONSTRAINT org_policies_lifetime_check CHECK (max_session_lifetime_seconds > 0)
);
CREATE TRIGGER org_policies_touch BEFORE UPDATE ON org_policies
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- Non-human identities owned by an organization (ORG-09).
CREATE TABLE service_accounts (
    id           uuid        PRIMARY KEY,
    org_id       uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name         text        NOT NULL,
    description  text,
    role_id      uuid        NOT NULL REFERENCES roles (id) ON DELETE RESTRICT,
    status       text        NOT NULL DEFAULT 'active',
    created_by   uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT service_accounts_name_check CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT service_accounts_description_check CHECK (char_length(description) <= 500),
    CONSTRAINT service_accounts_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT service_accounts_org_name_key UNIQUE (org_id, name),
    -- Target of the composite FK from api_keys (tenant isolation).
    CONSTRAINT service_accounts_id_org_key UNIQUE (id, org_id)
);
CREATE TRIGGER service_accounts_role_tenant BEFORE INSERT OR UPDATE OF role_id, org_id ON service_accounts
    FOR EACH ROW EXECUTE FUNCTION authn_check_role_tenant();
CREATE TRIGGER service_accounts_touch BEFORE UPDATE ON service_accounts
    FOR EACH ROW EXECUTE FUNCTION authn_touch_updated_at();

-- API keys `ak_<env>_<base62>_<crc32>` (ORG-08). Only the SHA-256 of the full
-- key is stored; the display prefix identifies the key in listings.
CREATE TABLE api_keys (
    id                    uuid        PRIMARY KEY,
    org_id                uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    service_account_id    uuid,
    -- Key acting on behalf of a user inside the organization (optional).
    user_id               uuid        REFERENCES users (id) ON DELETE CASCADE,
    name                  text        NOT NULL,
    environment           text        NOT NULL,
    display_prefix        text        NOT NULL,
    secret_hash           bytea       NOT NULL,
    scopes                text[]      NOT NULL DEFAULT '{}',
    created_by            uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    last_used_at          timestamptz,
    last_used_ip          inet,
    revoked_at            timestamptz,
    revoked_reason        text,
    rotated_from_id       uuid        REFERENCES api_keys (id) ON DELETE SET NULL,
    -- During rotation the old key stays valid until this instant.
    rotation_grace_until  timestamptz,
    CONSTRAINT api_keys_service_account_fk FOREIGN KEY (service_account_id, org_id)
        REFERENCES service_accounts (id, org_id) ON DELETE CASCADE,
    CONSTRAINT api_keys_owner_check CHECK (num_nonnulls(service_account_id, user_id) <= 1),
    CONSTRAINT api_keys_name_check CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT api_keys_environment_check CHECK (environment ~ '^[a-z]{1,8}$'),
    CONSTRAINT api_keys_prefix_check CHECK (char_length(display_prefix) BETWEEN 4 AND 32),
    CONSTRAINT api_keys_secret_hash_check CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT api_keys_scope_check CHECK (cardinality(scopes) <= 64),
    CONSTRAINT api_keys_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT api_keys_revoked_check CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
    CONSTRAINT api_keys_secret_hash_key UNIQUE (secret_hash)
);
CREATE INDEX api_keys_org_idx ON api_keys (org_id, created_at DESC);
CREATE INDEX api_keys_service_account_idx ON api_keys (service_account_id) WHERE service_account_id IS NOT NULL;
CREATE INDEX api_keys_user_idx ON api_keys (user_id) WHERE user_id IS NOT NULL;
