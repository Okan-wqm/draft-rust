-- 2002 session K-78 (owner: authn-session): which second factors produced
-- a session's MFA.
--
-- `amr` alone cannot tell them apart: the e-mailed confirmation of a risky
-- login (RSK-03) adds `email` to `amr` exactly like a verified e-mail
-- factor, and an e-mail code login's `otp` hides a TOTP. Organization
-- policies that restrict the allowed second factors (MFA-08) are checked
-- against `mfa_factors` instead: the factor kinds actually verified as a
-- second factor (login challenge, enrollment during login, step-up). A
-- risk confirmation is never recorded here.
--
-- Sessions and challenges written before this migration have no recorded
-- factor ('{}'): switching into an organization that restricts its factors
-- asks for a step-up once (safe side).

ALTER TABLE sessions ADD COLUMN mfa_factors text[] NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD CONSTRAINT sessions_mfa_factors_check CHECK (
    mfa_factors <@ ARRAY['totp', 'webauthn', 'recovery_code', 'email', 'sms']::text[]
    AND cardinality(mfa_factors) <= 5);

ALTER TABLE auth_challenges ADD COLUMN mfa_factors text[] NOT NULL DEFAULT '{}';
ALTER TABLE auth_challenges ADD CONSTRAINT auth_challenges_mfa_factors_check CHECK (
    mfa_factors <@ ARRAY['totp', 'webauthn', 'recovery_code', 'email', 'sms']::text[]
    AND cardinality(mfa_factors) <= 5);
