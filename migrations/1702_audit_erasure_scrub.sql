-- 1702 audit K-58 (owner: authn-audit): no user id outlives its purpose in
-- the outbox or in the webhook delivery history (AUD-05, AUD-06, AUD-07,
-- ACC-09).
--
-- * outbox: a delivered message's payload loses `user_id`, `recipient`
--   and `data` at delivery (nothing reads a delivered payload). When an
--   account is erased (`PgAuditSink::pseudonymize_subject`, in the erasure
--   transaction) its dead-letter messages are scrubbed at once and its
--   pending ones are flagged `subject_erased`: they are still delivered
--   (e.g. the `user.deleted` event receivers need) and scrubbed when they
--   finish (delivered or dead).
-- * webhook_deliveries.subject_user_id: the event's `user_id`, for the
--   erasure lookup. On erasure, finished deliveries (succeeded, dead) of
--   the user are redacted (`redacted_at`; payload reduced to id, type,
--   timestamp and organization) and unfinished ones flagged
--   (`subject_erased_at`): redacted when they finish. Deliveries fanned out
--   from a flagged outbox message are flagged too. A redacted delivery
--   cannot be redelivered.

ALTER TABLE outbox ADD COLUMN subject_erased boolean NOT NULL DEFAULT false;
CREATE INDEX outbox_unfinished_user_idx ON outbox ((payload ->> 'user_id'))
    WHERE status IN ('pending', 'processing', 'dead');

ALTER TABLE webhook_deliveries ADD COLUMN subject_user_id uuid;
ALTER TABLE webhook_deliveries ADD COLUMN subject_erased_at timestamptz;
ALTER TABLE webhook_deliveries ADD COLUMN redacted_at timestamptz;
UPDATE webhook_deliveries SET subject_user_id = (payload ->> 'user_id')::uuid
    WHERE payload ->> 'user_id' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
CREATE INDEX webhook_deliveries_subject_idx ON webhook_deliveries (subject_user_id)
    WHERE subject_user_id IS NOT NULL;

-- Delivered messages written before this migration.
UPDATE outbox SET payload = payload - 'user_id' - 'recipient' - 'data'
    WHERE status = 'delivered';
