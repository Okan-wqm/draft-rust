-- 1514 authn-org (range 1500-1599): periodic re-verification of verified
-- domains (ORG-13, K-97; closes the ORG-06 accepted risk "a verified domain
-- stays verified forever").
--
-- A background job re-checks the TXT record of every verified domain each
-- `org.domain_reverification.interval`. It claims due rows by moving
-- `last_checked_at` forward (FOR UPDATE SKIP LOCKED, so several instances
-- never check the same domain twice), looks the record up with no
-- connection held, then records the outcome:
--
--   present       the value is published: both counters reset
--   absent        definitive absence (NXDOMAIN, no TXT data, TXT records
--                 without the value): check_failures + 1
--   inconclusive  resolver error / SERVFAIL / timeout: check_inconclusive + 1
--                 (does not count as absence)
--
-- At `failure_threshold` absences or `inconclusive_limit` inconclusive
-- checks in a row the domain becomes `failed` (verified_at, auto_join and
-- sso_required cleared by the existing org_domains_policy_check rule),
-- `unverified_at` is set, the event org.domain_unverified is audited and
-- the organization's administrators are notified.
-- Expand-only: new columns with defaults; old binaries ignore them.
ALTER TABLE org_domains
    ADD COLUMN check_failures      integer     NOT NULL DEFAULT 0,
    ADD COLUMN check_inconclusive  integer     NOT NULL DEFAULT 0,
    ADD COLUMN last_check_outcome  text,
    ADD COLUMN unverified_at       timestamptz,
    ADD CONSTRAINT org_domains_check_counters_check
        CHECK (check_failures >= 0 AND check_inconclusive >= 0),
    ADD CONSTRAINT org_domains_check_outcome_check
        CHECK (last_check_outcome IN ('present', 'absent', 'inconclusive'));
