#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-58 pool pattern (wave 4B audit): the sign-up background job and the
//! e-mail change must never wait for a second pooled connection (the
//! production rate limiter, `PostgresRateLimiter`, takes one from the same
//! pool) while their transaction holds the first one. With a one-connection
//! pool such a flow stalls until the acquire timeout and its work is lost.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use authn_testkit::fakes::AllowAllRateLimiter;
use common::{Harness, Options, PASSWORD, registrations};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// A limiter that, like `PostgresRateLimiter`, needs a pooled connection
/// for every check.
struct PooledLimiter {
    pool: PgPool,
    inner: AllowAllRateLimiter,
}

#[async_trait]
impl RateLimiter for PooledLimiter {
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT 1").execute(&mut *conn).await?;
        drop(conn);
        self.inner.check(key, policy, cost).await
    }

    async fn peek(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT 1").execute(&mut *conn).await?;
        drop(conn);
        self.inner.peek(key, policy).await
    }

    async fn reset(&self, key: &RateLimitKey) -> Result<(), AuthError> {
        self.inner.reset(key).await
    }
}

async fn one_connection_harness(pool: &PgPool) -> Harness {
    let small = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let limiter: Arc<dyn RateLimiter> = Arc::new(PooledLimiter {
        pool: small.clone(),
        inner: AllowAllRateLimiter,
    });
    Harness::build(
        small,
        Options {
            rate_limiter: Some(limiter),
            ..Options::default()
        },
        |_| {},
    )
    .await
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_01_k58_signup_job_never_waits_for_a_second_pooled_connection(pool: PgPool) {
    let h = one_connection_harness(&pool).await;

    // First registration of an address (automatic send + resend cooldown).
    h.signup_with("new@example.com", PASSWORD).await;
    let user = h.user("new@example.com").await.expect("account created");
    assert_eq!(h.mails("email_verification", "new@example.com").len(), 1);

    // Another registration of the unverified address (daily e-mail budget).
    h.signup_with("new@example.com", PASSWORD).await;
    assert_eq!(registrations(&pool, user.id).await, 2);
    assert_eq!(h.mails("email_verification", "new@example.com").len(), 2);

    // Registration attempt for a verified account (owner notice budget).
    h.active_user("owner@example.com").await;
    h.signup_with("owner@example.com", PASSWORD).await;
    assert_eq!(
        h.mails("registration_attempt", "owner@example.com").len(),
        1,
        "the owner notice must be sent"
    );

    // E-mail change to an address in use (owner notice budget).
    let mover = h.active_user("mover@example.com").await;
    h.service
        .request_email_change(&h.fresh(mover), &h.ctx(), "owner@example.com")
        .await
        .unwrap();
    h.drain().await;
    assert_eq!(
        h.mails("registration_attempt", "owner@example.com").len(),
        2,
        "the address-in-use notice must be sent"
    );
}
