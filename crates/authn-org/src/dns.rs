//! [`DnsTxtResolver`] on `hickory-resolver` (ORG-06).
//!
//! * Names are queried fully qualified (a trailing dot is added), so the
//!   resolver's search domains are never appended.
//! * Caching is bounded to short TTLs (a freshly published record should be
//!   visible quickly; a negative answer is cached for at most 30 seconds).
//! * NXDOMAIN / no records is `Ok(vec![])`; any other resolver failure is
//!   `service_unavailable` (logged without the queried name, which may be
//!   customer data).
//! * Answers are bounded: at most 64 TXT records, each truncated to 4 KiB,
//!   invalid UTF-8 replaced.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::DnsTxtResolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;

/// Most TXT records returned per lookup.
const MAX_RECORDS: usize = 64;
/// Longest TXT record kept (bytes, after concatenating its strings).
const MAX_RECORD_BYTES: usize = 4096;

/// TXT lookups with `hickory-resolver`.
#[derive(Clone)]
pub struct HickoryDnsTxtResolver {
    resolver: TokioResolver,
}

impl std::fmt::Debug for HickoryDnsTxtResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryDnsTxtResolver")
            .finish_non_exhaustive()
    }
}

impl HickoryDnsTxtResolver {
    /// Uses the operating system configuration (`/etc/resolv.conf`).
    pub fn from_system_conf(timeout: Duration) -> Result<Self, AuthError> {
        let mut builder = TokioResolver::builder_tokio().map_err(|e| {
            AuthError::internal("cannot read the system DNS configuration").with_source(e)
        })?;
        configure(builder.options_mut(), timeout);
        let resolver = builder
            .build()
            .map_err(|e| AuthError::internal("cannot build the DNS resolver").with_source(e))?;
        Ok(Self { resolver })
    }

    /// Uses explicit name servers (UDP + TCP, port 53).
    pub fn with_name_servers(servers: &[IpAddr], timeout: Duration) -> Result<Self, AuthError> {
        if servers.is_empty() {
            return Err(AuthError::internal("no DNS name servers configured"));
        }
        let config = ResolverConfig::from_name_servers(
            servers
                .iter()
                .map(|ip| NameServerConfig::udp_and_tcp(*ip))
                .collect(),
        );
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        configure(builder.options_mut(), timeout);
        let resolver = builder
            .build()
            .map_err(|e| AuthError::internal("cannot build the DNS resolver").with_source(e))?;
        Ok(Self { resolver })
    }
}

fn configure(options: &mut hickory_resolver::config::ResolverOpts, timeout: Duration) {
    options.timeout = timeout;
    options.attempts = 1;
    options.positive_max_ttl = Some(Duration::from_secs(60));
    options.negative_max_ttl = Some(Duration::from_secs(30));
    options.cache_size = 256;
}

/// The name with exactly one trailing dot.
fn fully_qualified(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    format!("{trimmed}.")
}

#[async_trait]
impl DnsTxtResolver for HickoryDnsTxtResolver {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, AuthError> {
        let lookup = match self.resolver.txt_lookup(fully_qualified(name)).await {
            Ok(lookup) => lookup,
            Err(err) if err.is_no_records_found() || err.is_nx_domain() => return Ok(Vec::new()),
            Err(err) => {
                tracing::warn!(error = %err, "dns txt lookup failed");
                return Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                    .with_context("dns txt lookup failed"));
            }
        };
        let mut out = Vec::new();
        for record in lookup.answers() {
            if out.len() >= MAX_RECORDS {
                break;
            }
            if let RData::TXT(txt) = &record.data {
                let mut bytes = Vec::new();
                for part in &*txt.txt_data {
                    bytes.extend_from_slice(part);
                    if bytes.len() > MAX_RECORD_BYTES {
                        bytes.truncate(MAX_RECORD_BYTES);
                        break;
                    }
                }
                out.push(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_06_names_are_fully_qualified() {
        assert_eq!(
            fully_qualified("_authn-verification.example.com"),
            "_authn-verification.example.com."
        );
        assert_eq!(fully_qualified("example.com."), "example.com.");
        assert_eq!(fully_qualified("example.com.."), "example.com.");
    }

    #[tokio::test]
    async fn org_06_resolver_with_explicit_servers_builds() {
        let resolver = HickoryDnsTxtResolver::with_name_servers(
            &["127.0.0.1".parse().unwrap()],
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(format!("{resolver:?}").contains("HickoryDnsTxtResolver"));
        assert!(HickoryDnsTxtResolver::with_name_servers(&[], Duration::from_secs(1)).is_err());
    }
}
