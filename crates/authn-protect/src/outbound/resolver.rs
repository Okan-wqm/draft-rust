//! DNS resolution for outbound HTTP (PRT-12).
//!
//! [`HostResolver`] is the lookup itself (system configuration through
//! `hickory-resolver`, or a static table for tests). [`VettingResolver`]
//! plugs it into `reqwest` as *the* resolver of the user-supplied client:
//! reqwest connects to exactly the addresses it returns, and it returns
//! addresses only after **all** of them were classified as public. There is
//! one resolution per connection and no second lookup between the check and
//! the connect, which defeats DNS rebinding.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use hickory_resolver::TokioResolver;

use super::ip::{AddressClass, classify};

/// Upper bound on addresses taken from one lookup.
const MAX_ADDRESSES: usize = 32;

/// Resolves a host name to IP addresses.
#[async_trait]
pub trait HostResolver: Send + Sync {
    /// All addresses of `host` (A and AAAA). An empty list is an error.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, AuthError>;
}

/// The operating system's resolver configuration (`/etc/resolv.conf`,
/// `/etc/hosts`) through `hickory-resolver`; falls back to `getaddrinfo`
/// (tokio) when the system configuration cannot be read.
pub struct SystemResolver {
    hickory: Option<TokioResolver>,
}

impl fmt::Debug for SystemResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemResolver")
            .field("hickory", &self.hickory.is_some())
            .finish()
    }
}

impl SystemResolver {
    /// Reads the system configuration.
    #[must_use]
    pub fn new() -> Self {
        let hickory = match TokioResolver::builder_tokio()
            .and_then(hickory_resolver::ResolverBuilder::build)
        {
            Ok(resolver) => Some(resolver),
            Err(err) => {
                tracing::warn!(error = %err, "hickory system resolver unavailable; using getaddrinfo");
                None
            }
        };
        Self { hickory }
    }
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new()
    }
}

fn dns_failure(context: &'static str) -> AuthError {
    AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_context(context)
}

#[async_trait]
impl HostResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, AuthError> {
        let addrs: Vec<IpAddr> = match &self.hickory {
            Some(resolver) => resolver
                .lookup_ip(host)
                .await
                .map_err(|_| dns_failure("dns lookup failed"))?
                .iter()
                .take(MAX_ADDRESSES)
                .collect(),
            None => tokio::net::lookup_host((host, 0))
                .await
                .map_err(|_| dns_failure("dns lookup failed"))?
                .map(|s| s.ip())
                .take(MAX_ADDRESSES)
                .collect(),
        };
        if addrs.is_empty() {
            return Err(dns_failure("dns lookup returned no address"));
        }
        Ok(addrs)
    }
}

/// A fixed host → addresses table (tests, air-gapped deployments). Lookups
/// are counted so tests can prove there is exactly one resolution per
/// connection.
#[derive(Debug, Default)]
pub struct StaticResolver {
    table: HashMap<String, Vec<IpAddr>>,
    lookups: AtomicUsize,
}

impl StaticResolver {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry (host names are matched case-insensitively).
    #[must_use]
    pub fn with(mut self, host: &str, addrs: &[IpAddr]) -> Self {
        self.table.insert(host.to_ascii_lowercase(), addrs.to_vec());
        self
    }

    /// Number of lookups performed so far.
    #[must_use]
    pub fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl HostResolver for StaticResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, AuthError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        match self.table.get(&key) {
            Some(addrs) if !addrs.is_empty() => Ok(addrs.clone()),
            _ => Err(dns_failure("host not in static table")),
        }
    }
}

/// Marker error: a resolved address is not an allowed destination. Carried
/// through reqwest's error chain so the client can map it to
/// `outbound_destination_not_allowed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedDestination(pub AddressClass);

impl fmt::Display for BlockedDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "destination address not allowed ({:?})", self.0)
    }
}

impl std::error::Error for BlockedDestination {}

/// Checks a resolved address set: every address must be allowed (a single
/// private answer rejects the whole set — no "pick the good one" games).
pub fn vet_addresses(addrs: &[IpAddr], allow_private: bool) -> Result<(), BlockedDestination> {
    if allow_private {
        return Ok(());
    }
    for ip in addrs {
        let class = classify(*ip);
        if !class.is_public() {
            return Err(BlockedDestination(class));
        }
    }
    Ok(())
}

/// The reqwest resolver of the user-supplied client: resolve once, vet all
/// addresses, hand exactly those to the connector.
#[derive(Clone)]
pub struct VettingResolver {
    inner: Arc<dyn HostResolver>,
    allow_private: bool,
}

impl fmt::Debug for VettingResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VettingResolver")
            .field("allow_private", &self.allow_private)
            .finish_non_exhaustive()
    }
}

impl VettingResolver {
    /// Wraps `inner`; `allow_private` is the development-only switch.
    #[must_use]
    pub fn new(inner: Arc<dyn HostResolver>, allow_private: bool) -> Self {
        Self {
            inner,
            allow_private,
        }
    }

    /// Resolves and vets `host`.
    pub async fn resolve_vetted(&self, host: &str) -> Result<Vec<IpAddr>, VetError> {
        let addrs = self.inner.resolve(host).await.map_err(VetError::Lookup)?;
        vet_addresses(&addrs, self.allow_private).map_err(VetError::Blocked)?;
        Ok(addrs)
    }
}

/// Failure of [`VettingResolver::resolve_vetted`].
#[derive(Debug)]
pub enum VetError {
    /// DNS failed.
    Lookup(AuthError),
    /// An address is not allowed.
    Blocked(BlockedDestination),
}

impl fmt::Display for VetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(_) => f.write_str("dns lookup failed"),
            Self::Blocked(b) => fmt::Display::fmt(b, f),
        }
    }
}

impl std::error::Error for VetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lookup(_) => None,
            Self::Blocked(b) => Some(b),
        }
    }
}

impl reqwest::dns::Resolve for VettingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let this = self.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            match this.resolve_vetted(&host).await {
                Ok(addrs) => {
                    let iter: reqwest::dns::Addrs =
                        Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
                    Ok(iter)
                }
                Err(VetError::Blocked(blocked)) => {
                    Err(Box::new(blocked) as Box<dyn std::error::Error + Send + Sync>)
                }
                Err(err @ VetError::Lookup(_)) => {
                    Err(Box::new(err) as Box<dyn std::error::Error + Send + Sync>)
                }
            }
        })
    }
}

/// Resolver of the trusted client (operator-configured endpoints): plain
/// resolution through the same [`HostResolver`], no vetting.
#[derive(Clone)]
pub struct PlainResolver(pub Arc<dyn HostResolver>);

impl fmt::Debug for PlainResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PlainResolver")
    }
}

impl reqwest::dns::Resolve for PlainResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let inner = self.0.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            match inner.resolve(&host).await {
                Ok(addrs) => {
                    let iter: reqwest::dns::Addrs =
                        Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
                    Ok(iter)
                }
                Err(_) => Err(Box::new(VetError::Lookup(dns_failure("dns lookup failed")))
                    as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prt_12_any_private_answer_rejects_the_whole_set() {
        let resolver = Arc::new(
            StaticResolver::new()
                .with(
                    "mixed.test",
                    &["8.8.8.8".parse().unwrap(), "10.0.0.1".parse().unwrap()],
                )
                .with("public.test", &["8.8.4.4".parse().unwrap()])
                .with("meta.test", &["169.254.169.254".parse().unwrap()])
                .with("mapped.test", &["::ffff:127.0.0.1".parse().unwrap()]),
        );
        let vetting = VettingResolver::new(resolver.clone(), false);
        assert!(matches!(
            vetting.resolve_vetted("mixed.test").await,
            Err(VetError::Blocked(BlockedDestination(AddressClass::Private)))
        ));
        assert!(matches!(
            vetting.resolve_vetted("meta.test").await,
            Err(VetError::Blocked(BlockedDestination(
                AddressClass::CloudMetadata
            )))
        ));
        assert!(matches!(
            vetting.resolve_vetted("mapped.test").await,
            Err(VetError::Blocked(BlockedDestination(
                AddressClass::Loopback
            )))
        ));
        assert_eq!(
            vetting.resolve_vetted("PUBLIC.test.").await.unwrap(),
            vec!["8.8.4.4".parse::<IpAddr>().unwrap()]
        );
        assert!(matches!(
            vetting.resolve_vetted("unknown.test").await,
            Err(VetError::Lookup(_))
        ));
        assert_eq!(resolver.lookups(), 5);

        let dev = VettingResolver::new(resolver, true);
        assert_eq!(dev.resolve_vetted("mixed.test").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn prt_12_system_resolver_resolves_localhost_which_is_then_blocked() {
        let vetting = VettingResolver::new(Arc::new(SystemResolver::new()), false);
        // `localhost` comes from /etc/hosts — no network needed.
        match vetting.resolve_vetted("localhost").await {
            Err(VetError::Blocked(BlockedDestination(AddressClass::Loopback))) => {}
            Err(VetError::Lookup(_)) => {} // hosts file without localhost: still not reachable
            other => panic!("localhost must never be allowed: {other:?}"),
        }
    }
}
