use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::DnsTxtResolver;

use super::lock;

/// TXT records from an in-memory map; names are matched case-insensitively
/// without a trailing dot. Can simulate resolver failures.
#[derive(Debug, Default)]
pub struct FakeDnsTxtResolver {
    records: Mutex<HashMap<String, Vec<String>>>,
    failing: Mutex<bool>,
    hanging: Mutex<bool>,
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl FakeDnsTxtResolver {
    /// Adds a TXT record.
    pub fn add_txt(&self, name: &str, value: &str) {
        lock(&self.records)
            .entry(normalize(name))
            .or_default()
            .push(value.to_owned());
    }

    /// Removes every TXT record of `name` (the name then has no data:
    /// a definitive absence, like NXDOMAIN / NODATA).
    pub fn remove_txt(&self, name: &str) {
        lock(&self.records).remove(&normalize(name));
    }

    /// Simulates a resolver that never answers (the caller's timeout
    /// fires).
    pub fn set_hanging(&self, hanging: bool) {
        *lock(&self.hanging) = hanging;
    }

    /// Simulates resolver failures (`service_unavailable`, e.g. SERVFAIL).
    pub fn set_failing(&self, failing: bool) {
        *lock(&self.failing) = failing;
    }
}

#[async_trait]
impl DnsTxtResolver for FakeDnsTxtResolver {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AuthError> {
        let hanging = *lock(&self.hanging);
        if hanging {
            std::future::pending::<()>().await;
        }
        if *lock(&self.failing) {
            return Err(
                AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_context("fake DNS failure")
            );
        }
        Ok(lock(&self.records)
            .get(&normalize(name))
            .cloned()
            .unwrap_or_default())
    }
}
