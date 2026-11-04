-- 2100 web social login session options (owner: authn-oidc-client; K-32,
-- SES-06, SES-07).
--
-- `GET /v1/oauth/{provider}/start?remember_me=&shared_device=` stores the
-- browser's choices with the authorization state; the callback hands them
-- to the session pipeline (`PrimaryAuthentication`). Only login flows carry
-- them: a link flow never opens a session.

ALTER TABLE oauth_states
    ADD COLUMN remember_me boolean NOT NULL DEFAULT false,
    ADD COLUMN shared_device boolean NOT NULL DEFAULT false;
ALTER TABLE oauth_states ADD CONSTRAINT oauth_states_login_options_check
    CHECK (flow = 'login' OR (NOT remember_me AND NOT shared_device));
