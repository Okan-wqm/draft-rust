//! Repositories of the tables owned by authn-session: `sessions`,
//! `refresh_tokens`, `auth_challenges`. Runtime-checked SQL only.

pub(crate) mod challenges;
pub(crate) mod refresh;
pub(crate) mod sessions;
