-- 0013 every Argon2id-based password hash records its pepper version.
-- Owner: architect (authn-store owns password_credentials). CRY-02, CRY-04.
--
-- 0002 only required pepper_version for algorithm = 'argon2id'. The wrapped
-- legacy formats (argon2id_wrapped_md5, argon2id_wrapped_sha1: Argon2id over
-- HMAC(pepper, legacy_hash(password))) are peppered as well and cannot be
-- verified without the version; a row without it could never log in and
-- would hide a migration bug. Any future argon2id* scheme is covered by the
-- prefix. Plain legacy formats (bcrypt, pbkdf2_sha256) stay pepper-free.
-- No existing row can violate it: authn-crypto always writes the version.

ALTER TABLE password_credentials
    ADD CONSTRAINT password_credentials_wrapped_pepper_check
    CHECK (NOT starts_with(algorithm, 'argon2id') OR pepper_version IS NOT NULL);
