-- 2102 provider token revocation (owner: authn-oidc-client; K-35, SOC-07,
-- SOC-08, ACC-09).
--
-- * identities.token_client_id: the client id a stored provider token was
--   issued to (Sign in with Apple: the services id for the web flow, the
--   bundle id for the native flow); the revocation must present the same
--   client id.
-- * oauth_token_revocations: a queue of provider tokens to revoke after
--   the identity is gone (account deletion, unlink). Apple requires apps
--   that offer account deletion to revoke the user's tokens. The token is
--   envelope encrypted (AAD = this table / column / row id); the row holds
--   no user id (the account is erased by then) and is deleted when the
--   revocation succeeded or was given up (bounded retries with backoff).

ALTER TABLE identities ADD COLUMN token_client_id text;
ALTER TABLE identities ADD CONSTRAINT identities_token_client_id_check
    CHECK (char_length(token_client_id) BETWEEN 1 AND 255);

CREATE TABLE oauth_token_revocations (
    id                uuid        PRIMARY KEY,
    provider          text        NOT NULL,
    client_id         text        NOT NULL,
    token_ciphertext  bytea       NOT NULL,
    token_type_hint   text        NOT NULL,
    attempts          integer     NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz NOT NULL,
    created_at        timestamptz NOT NULL,
    CONSTRAINT oauth_token_revocations_provider_check
        CHECK (provider ~ '^[a-z0-9][a-z0-9_.:-]{0,63}$'),
    CONSTRAINT oauth_token_revocations_client_id_check
        CHECK (char_length(client_id) BETWEEN 1 AND 255),
    CONSTRAINT oauth_token_revocations_hint_check
        CHECK (token_type_hint IN ('refresh_token', 'access_token')),
    CONSTRAINT oauth_token_revocations_attempts_check CHECK (attempts >= 0)
);
CREATE INDEX oauth_token_revocations_due_idx ON oauth_token_revocations (next_attempt_at);
