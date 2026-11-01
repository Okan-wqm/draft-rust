-- 1501 authn-org: domain auto-join must never undo a removal or a departure.
-- Owner: authn-org (range 1500-1599). ORG-02, ORG-06.
--
-- Auto-join (ORG-06) adds every user with a verified address of a verified
-- auto-join domain who is not a member. Without a record of past
-- memberships, a removed member (or one who left) was silently re-added at
-- the next login. Removal and leaving record the user here; auto-join skips
-- recorded users; an accepted invitation (an explicit decision of the
-- organization) clears the record.

CREATE TABLE org_auto_join_exclusions (
    org_id      uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    reason      text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    CONSTRAINT org_auto_join_exclusions_reason_check CHECK (reason IN ('removed', 'left'))
);
CREATE INDEX org_auto_join_exclusions_user_idx ON org_auto_join_exclusions (user_id);
