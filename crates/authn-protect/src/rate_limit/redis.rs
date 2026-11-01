//! Redis GCRA rate limiter (PRT-01, cargo feature `redis`).
//!
//! The decision is one Lua script (`EVAL`), which Redis executes atomically:
//! read TAT, decide, write TAT with a TTL equal to the time until the bucket
//! is empty again. Keys are `authn:rl:<hex keyed hash>`; a single key per
//! call keeps the script valid on Redis Cluster.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use authn_core::secret::{ExposeSecret, SecretString};
use fred::prelude::{
    Client, ClientLike, Config, ConnectionConfig, KeysInterface, LuaInterface, PerformanceConfig,
    ReconnectPolicy,
};

use super::gcra::{self, Plan};
use crate::keys::KeyHasher;

/// `KEYS[1]` bucket; `ARGV`: now (µs), increment (µs), effective period
/// (µs), `1` to consume / `0` to peek. Returns `{1, new_tat}` when admitted,
/// `{0, retry_after_us}` when denied. All values are integers below 2^53, so
/// Lua's doubles represent them exactly.
const GCRA_SCRIPT: &str = r"
local now = tonumber(ARGV[1])
local inc = tonumber(ARGV[2])
local period = tonumber(ARGV[3])
local tat = tonumber(redis.call('GET', KEYS[1]))
if tat == nil or tat < now then tat = now end
local new_tat = tat + inc
local ahead = new_tat - now
if ahead > period then
  local wait = ahead - period
  if wait < 1 then wait = 1 end
  return {0, wait}
end
if ARGV[4] == '1' and inc > 0 then
  local ttl_ms = math.ceil(ahead / 1000)
  if ttl_ms < 1 then ttl_ms = 1 end
  redis.call('SET', KEYS[1], string.format('%d', new_tat), 'PX', ttl_ms)
end
return {1, new_tat}
";

const KEY_PREFIX: &str = "authn:rl:";

/// The Redis rate limiter. Cheap to clone.
#[derive(Clone)]
pub struct RedisRateLimiter {
    client: Client,
    clock: Arc<dyn Clock>,
    hasher: KeyHasher,
}

impl std::fmt::Debug for RedisRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimiter").finish_non_exhaustive()
    }
}

fn unavailable(err: &fred::error::Error) -> AuthError {
    // Never echo the URL / credentials; the error kind is enough.
    AuthError::new(codes::common::SERVICE_UNAVAILABLE)
        .with_context(format!("redis rate limiter: {:?}", err.kind()))
}

impl RedisRateLimiter {
    /// Connects to `url` (`redis://` or `rediss://`) and waits for the
    /// connection. Commands time out after 2 s so a hung Redis fails the
    /// request (`service_unavailable`) instead of hanging it.
    pub async fn connect(
        url: &SecretString,
        clock: Arc<dyn Clock>,
        hasher: KeyHasher,
    ) -> Result<Self, AuthError> {
        authn_core::tls::install_crypto_provider();
        let config = Config::from_url(url.expose_secret())
            .map_err(|_| AuthError::internal("invalid redis URL (value not logged)"))?;
        let perf = PerformanceConfig {
            default_command_timeout: Duration::from_secs(2),
            ..PerformanceConfig::default()
        };
        let connection = ConnectionConfig {
            connection_timeout: Duration::from_secs(5),
            ..ConnectionConfig::default()
        };
        let policy = ReconnectPolicy::new_exponential(0, 100, 10_000, 2);
        let client = Client::new(config, Some(perf), Some(connection), Some(policy));
        client.init().await.map_err(|e| unavailable(&e))?;
        Ok(Self {
            client,
            clock,
            hasher,
        })
    }

    /// Closes the connection (graceful shutdown).
    pub async fn quit(&self) -> Result<(), AuthError> {
        self.client.quit().await.map_err(|e| unavailable(&e))
    }

    fn redis_key(&self, key: &RateLimitKey) -> String {
        let hash = self.hasher.rate_limit_key(key);
        let mut out = String::with_capacity(KEY_PREFIX.len() + 64);
        out.push_str(KEY_PREFIX);
        for byte in hash {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    async fn run(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
        consume: bool,
    ) -> Result<RateLimitDecision, AuthError> {
        let params = match gcra::plan(policy, cost)? {
            Plan::Reject(decision) => return Ok(decision),
            Plan::Gcra(params) => params,
        };
        let now_us = gcra::unix_micros(self.clock.now());
        let args: Vec<String> = vec![
            now_us.to_string(),
            params.increment_us.to_string(),
            params.period_us.to_string(),
            if consume { "1" } else { "0" }.to_owned(),
        ];
        let reply: Vec<i64> = self
            .client
            .eval(GCRA_SCRIPT, vec![self.redis_key(key)], args)
            .await
            .map_err(|e| unavailable(&e))?;
        match reply.as_slice() {
            [1, new_tat] => Ok(RateLimitDecision::allow(gcra::remaining_after(
                *new_tat, now_us, params,
            ))),
            [0, wait] => Ok(RateLimitDecision::deny(Duration::from_micros(
                u64::try_from((*wait).max(1)).unwrap_or(1),
            ))),
            _ => Err(AuthError::internal("unexpected redis rate-limit reply")),
        }
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        self.run(key, policy, cost, true).await
    }

    async fn peek(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        self.run(key, policy, 1, false).await
    }

    async fn reset(&self, key: &RateLimitKey) -> Result<(), AuthError> {
        let _: i64 = self
            .client
            .del(self.redis_key(key))
            .await
            .map_err(|e| unavailable(&e))?;
        Ok(())
    }
}
