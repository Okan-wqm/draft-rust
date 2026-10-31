//! DNS TXT lookups for domain verification (ORG-06). Owner of this file:
//! authn-org (implementation on `hickory-resolver`).

use async_trait::async_trait;

use crate::error::AuthError;

/// Resolves TXT records.
#[async_trait]
pub trait DnsTxtResolver: Send + Sync {
    /// Returns every TXT record string of `name` (each record's character
    /// strings concatenated). An NXDOMAIN / empty answer is `Ok(vec![])`;
    /// resolver failures are errors.
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AuthError>;
}
