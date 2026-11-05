-- 2202 authn-admin: review dates of legal restrictions (K-62) and
-- four-eyes approvals of critical admin operations (K-66).
-- Owner: authn-admin (range 2200-2299; the only writer of these tables).

-- K-62: a legal restriction (KVKK art. 28 / GDPR art. 23) of a
-- justification lasts until its review date, at most 180 days after it was
-- set; an extension (with its own audited justification) adds a row with a
-- later date. A restriction is active while the latest `review_at` of its
-- event lies in the future; afterwards the justification is exported again
-- (ACC-10). Append-only like `admin_reason_restrictions`; rows go only with
-- the restriction (cascade). `set_by`: the audited admin action (restrict
-- or extend) that set the date.
CREATE TABLE admin_reason_restriction_periods (
    event_id    uuid        NOT NULL REFERENCES admin_reason_restrictions (event_id) ON DELETE CASCADE,
    review_at   timestamptz NOT NULL,
    set_by      uuid        NOT NULL REFERENCES audit_events (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (event_id, set_by),
    CONSTRAINT admin_reason_restriction_periods_review_check
        CHECK (review_at > created_at AND review_at <= created_at + interval '180 days')
);
CREATE INDEX admin_reason_restriction_periods_set_by_idx
    ON admin_reason_restriction_periods (set_by);

CREATE FUNCTION authn_admin_restriction_periods_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() > 1 AND TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'admin_reason_restriction_periods is append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
CREATE TRIGGER admin_reason_restriction_periods_append_only
    BEFORE UPDATE OR DELETE ON admin_reason_restriction_periods
    FOR EACH ROW EXECUTE FUNCTION authn_admin_restriction_periods_guard();
CREATE TRIGGER admin_reason_restriction_periods_no_truncate
    BEFORE TRUNCATE ON admin_reason_restriction_periods
    FOR EACH STATEMENT EXECUTE FUNCTION authn_forbid_truncate();

-- Restrictions set before this migration had no review date: they get the
-- longest allowed one, counted from when they were set.
INSERT INTO admin_reason_restriction_periods (event_id, review_at, set_by, created_at)
SELECT event_id, created_at + interval '180 days', restricted_by, created_at
FROM admin_reason_restrictions;

-- K-66: four-eyes approvals. An admin requests a critical operation
-- (emergency operations, actions on another platform admin) with its exact
-- parameters (`params`, shown to the approver; `params_hash` = SHA-256 of
-- their canonical form, compared when the operation runs) and a
-- justification; a different platform admin approves or denies it; the
-- requester runs the operation once with the approved request before
-- `expires_at`. Consumption is one conditional UPDATE in the operation's
-- transaction (single use). Every step is audited; the justifications live
-- in `admin_action_reasons` (`request_event` / `decision_event`).
-- Rows go with the requesting admin (cascade); the approver is unlinked on
-- erasure. The trigger below keeps the request immutable and lets each of
-- `decision` and `consumed_at` be set once.
CREATE TABLE admin_approvals (
    id              uuid        PRIMARY KEY,
    action          text        NOT NULL,
    params          jsonb       NOT NULL,
    params_hash     bytea       NOT NULL,
    target_user_id  uuid        REFERENCES users (id) ON DELETE CASCADE,
    requested_by    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    request_event   uuid        NOT NULL,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    decision        text,
    decided_by      uuid        REFERENCES users (id) ON DELETE SET NULL,
    decision_event  uuid,
    decided_at      timestamptz,
    consumed_at     timestamptz,
    CONSTRAINT admin_approvals_action_check CHECK (action ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT admin_approvals_hash_check CHECK (octet_length(params_hash) = 32),
    CONSTRAINT admin_approvals_params_check
        CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 1024),
    CONSTRAINT admin_approvals_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT admin_approvals_decision_check CHECK (
        (decision IS NULL AND decided_at IS NULL AND decision_event IS NULL)
        OR (decision IN ('approved', 'denied') AND decided_at IS NOT NULL
            AND decision_event IS NOT NULL)),
    CONSTRAINT admin_approvals_four_eyes_check CHECK (decided_by IS DISTINCT FROM requested_by),
    CONSTRAINT admin_approvals_consumed_check CHECK (
        consumed_at IS NULL OR decision = 'approved')
);
CREATE INDEX admin_approvals_pending_idx ON admin_approvals (expires_at) WHERE decision IS NULL;
CREATE INDEX admin_approvals_requested_by_idx ON admin_approvals (requested_by);
CREATE INDEX admin_approvals_decided_by_idx ON admin_approvals (decided_by) WHERE decided_by IS NOT NULL;
CREATE INDEX admin_approvals_target_idx ON admin_approvals (target_user_id) WHERE target_user_id IS NOT NULL;

CREATE FUNCTION authn_admin_approvals_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF pg_trigger_depth() > 1 THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'admin_approvals rows are not deleted (% refused)', TG_OP
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- Erasure of the approver (ON DELETE SET NULL) only unlinks it.
    IF pg_trigger_depth() > 1 AND NEW.decided_by IS NULL AND OLD.decided_by IS NOT NULL THEN
        NEW.decided_by := NULL;
        IF ROW(NEW.id, NEW.action, NEW.params, NEW.params_hash, NEW.target_user_id, NEW.requested_by,
               NEW.request_event, NEW.created_at, NEW.expires_at, NEW.decision,
               NEW.decision_event, NEW.decided_at, NEW.consumed_at)
           IS NOT DISTINCT FROM
           ROW(OLD.id, OLD.action, OLD.params, OLD.params_hash, OLD.target_user_id, OLD.requested_by,
               OLD.request_event, OLD.created_at, OLD.expires_at, OLD.decision,
               OLD.decision_event, OLD.decided_at, OLD.consumed_at) THEN
            RETURN NEW;
        END IF;
    END IF;
    IF ROW(NEW.id, NEW.action, NEW.params, NEW.params_hash, NEW.target_user_id, NEW.requested_by,
           NEW.request_event, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.action, OLD.params, OLD.params_hash, OLD.target_user_id, OLD.requested_by,
           OLD.request_event, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'admin_approvals: the request is immutable'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.decision IS NOT NULL AND ROW(NEW.decision, NEW.decided_by, NEW.decision_event,
           NEW.decided_at) IS DISTINCT FROM ROW(OLD.decision, OLD.decided_by,
           OLD.decision_event, OLD.decided_at) THEN
        RAISE EXCEPTION 'admin_approvals: the decision is final'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
        RAISE EXCEPTION 'admin_approvals: an approval is used once'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER admin_approvals_guard BEFORE UPDATE OR DELETE ON admin_approvals
    FOR EACH ROW EXECUTE FUNCTION authn_admin_approvals_guard();
CREATE TRIGGER admin_approvals_no_truncate BEFORE TRUNCATE ON admin_approvals
    FOR EACH STATEMENT EXECUTE FUNCTION authn_forbid_truncate();
