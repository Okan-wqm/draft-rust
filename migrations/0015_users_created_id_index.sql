-- 0015 keyset index for the platform admin user listing. Owner: architect
-- (authn-store). ADM-02, contract change request `## authn-admin`
-- (K-38).
--
-- UserRepository::search pages users newest first with the keyset
-- `(created_at, id) < ($after_at, $after_id) ORDER BY created_at DESC,
-- id DESC`; without this index every page sorts the whole table.
CREATE INDEX users_created_id_idx ON users (created_at DESC, id DESC);
