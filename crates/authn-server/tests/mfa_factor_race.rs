#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-69 (MFA-07, PKY-04, contracts §4): `ServerAccountMethods::mfa_facts`
//! reads the MFA policy input through the connection of the passkey
//! removal (which holds the user row lock), never from the pool.
//!
//! * The same user removing the last TOTP and the last passkey of an
//!   account that must keep MFA, concurrently, never ends with zero
//!   factors: exactly one removal succeeds, the other answers
//!   `mfa_last_factor_required`.
//! * The removal never waits for a second pooled connection while it holds
//!   one (HANDOFF §7): with a pool that is exactly as large as the number
//!   of concurrent removals, every removal still completes.

mod common;

use std::time::Duration;

use authn_core::domain::{AuthMethodRef, Locale, Principal, PrincipalCredential, Subject};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{CredentialId, FactorId, SessionId, UserId};
use authn_core::ports::Clock;
use common::App;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// An application whose pool has exactly `size` connections and gives up
/// waiting for one after a few seconds (a starved removal fails instead
/// of hanging the test).
async fn app_with_pool_size(pool: &PgPool, size: u32) -> App {
    let small = PgPoolOptions::new()
        .max_connections(size)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    App::new(small).await
}

/// A member of an organization whose policy requires MFA (MFA-08), with
/// a password.
async fn mfa_required_user(app: &App, admin_pool: &PgPool) -> UserId {
    let user = app.user("alice@example.com").await;
    let org = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, slug, name) VALUES ($1, 'acme', 'Acme')")
        .bind(org)
        .execute(admin_pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, role_id) \
         VALUES ($1, $2, $3, '01900000-0000-7000-8000-000000000003')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(org)
    .bind(user)
    .execute(admin_pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO org_policies (org_id, mfa_required) VALUES ($1, true)")
        .bind(org)
        .execute(admin_pool)
        .await
        .unwrap();
    user
}

/// One active TOTP factor and one second-factor passkey (the removals
/// below never decrypt or verify them).
async fn factors(pool: &PgPool, user: UserId) -> (FactorId, CredentialId) {
    let totp = FactorId::generate();
    sqlx::query(
        "INSERT INTO mfa_factors \
         (id, user_id, kind, status, label, secret_ciphertext, totp_digits, totp_period, \
          created_at, confirmed_at) \
         VALUES ($1, $2, 'totp', 'active', 'Phone', '\\x00'::bytea, 6, 30, now(), now())",
    )
    .bind(totp)
    .bind(user)
    .execute(pool)
    .await
    .unwrap();
    let passkey = CredentialId::generate();
    sqlx::query(
        "INSERT INTO webauthn_credentials \
         (id, user_id, credential_id, passkey, name, usage, created_at) \
         VALUES ($1, $2, $3, '{}'::jsonb, 'Key', 'second_factor', now())",
    )
    .bind(passkey)
    .bind(user)
    .bind(uuid::Uuid::now_v7().as_bytes().to_vec())
    .execute(pool)
    .await
    .unwrap();
    (totp, passkey)
}

/// A step-up-fresh session principal.
fn principal(app: &App, user: UserId) -> Principal {
    Principal {
        subject: Subject::User { user_id: user },
        credential: PrincipalCredential::SessionCookie {
            session_id: SessionId::generate(),
        },
        active_org: None,
        amr: vec![AuthMethodRef::Pwd],
        acr: None,
        auth_time: Some(app.ports.clock.now() - Duration::from_secs(5)),
        scopes: vec![],
        impersonation: None,
        is_platform_admin: false,
    }
}

async fn remaining_factors(pool: &PgPool, user: UserId) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM mfa_factors WHERE user_id = $1 AND status = 'active') \
              + (SELECT count(*) FROM webauthn_credentials WHERE user_id = $1)",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Waits until `n` backends of this test database wait for a lock.
async fn wait_for_lock_waiters(pool: &PgPool, n: i64) {
    for _ in 0..500 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        if waiting >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {n} lock waiter(s)");
}

#[derive(Debug, Clone, Copy)]
enum First {
    Passkey,
    Totp,
}

/// Lines both removals up behind a lock on the user row held by a third
/// connection (`first` queues first, so it gets the row first), releases
/// the row and returns both results.
async fn race(
    app: &App,
    admin_pool: &PgPool,
    user: UserId,
    totp: FactorId,
    passkey: CredentialId,
    first: First,
) -> (Result<(), AuthError>, Result<(), AuthError>) {
    let mut blocker = admin_pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let ctx = RequestContext::system(Locale::default());
    let remove_passkey = {
        let webauthn = app.services.webauthn.clone();
        let (ctx, principal) = (ctx.clone(), principal(app, user));
        move || async move { webauthn.delete_passkey(&ctx, &principal, passkey).await }
    };
    let remove_totp = {
        let mfa = app.services.mfa.clone();
        let (ctx, principal) = (ctx.clone(), principal(app, user));
        move || async move { mfa.remove_factor(&ctx, &principal, totp).await }
    };
    let (passkey_task, totp_task) = match first {
        First::Passkey => {
            let p = tokio::spawn(remove_passkey());
            wait_for_lock_waiters(admin_pool, 1).await;
            let t = tokio::spawn(remove_totp());
            wait_for_lock_waiters(admin_pool, 2).await;
            (p, t)
        }
        First::Totp => {
            let t = tokio::spawn(remove_totp());
            wait_for_lock_waiters(admin_pool, 1).await;
            let p = tokio::spawn(remove_passkey());
            wait_for_lock_waiters(admin_pool, 2).await;
            (p, t)
        }
    };
    blocker.commit().await.unwrap();
    (passkey_task.await.unwrap(), totp_task.await.unwrap())
}

/// K-69: concurrent "remove the last TOTP" and "remove the last passkey"
/// of the same user on an account that must keep MFA. Whichever order the
/// row lock grants, exactly one removal succeeds, the other is refused
/// with `mfa_last_factor_required`, and one factor is left. The pool is
/// exactly as large as the two removals (the blocker uses the test pool):
/// before the fix the passkey removal waited for a third pooled
/// connection while holding the row lock the TOTP removal was queued on.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_k69_concurrent_last_totp_and_last_passkey_removal_keep_a_factor(pool: PgPool) {
    let app = app_with_pool_size(&pool, 2).await;
    let user = mfa_required_user(&app, &pool).await;
    for round in 0..3 {
        for first in [First::Passkey, First::Totp] {
            sqlx::query("DELETE FROM mfa_factors WHERE user_id = $1")
                .bind(user)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("DELETE FROM webauthn_credentials WHERE user_id = $1")
                .bind(user)
                .execute(&pool)
                .await
                .unwrap();
            let (totp, passkey) = factors(&pool, user).await;
            let (passkey_result, totp_result) = race(&app, &pool, user, totp, passkey, first).await;
            let label = format!("round {round}, {first:?} first");
            assert_eq!(remaining_factors(&pool, user).await, 1, "{label}");
            let refused = |r: &Result<(), AuthError>| matches!(r, Err(e) if e.code() == codes::mfa::MFA_LAST_FACTOR_REQUIRED);
            match first {
                First::Passkey => {
                    assert!(passkey_result.is_ok(), "{label}: {passkey_result:?}");
                    assert!(refused(&totp_result), "{label}: {totp_result:?}");
                }
                First::Totp => {
                    assert!(totp_result.is_ok(), "{label}: {totp_result:?}");
                    assert!(refused(&passkey_result), "{label}: {passkey_result:?}");
                }
            }
        }
    }
}

/// K-69 (HANDOFF §7): removing the last passkey of an MFA-required
/// account works on a single-connection pool, i.e. the MFA facts are read
/// through the removal's own transaction. Before the fix the hook asked
/// the pool for a second connection while the removal held the only one,
/// and the request failed after the acquire timeout.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_k69_last_passkey_removal_needs_no_second_pooled_connection(pool: PgPool) {
    let app = app_with_pool_size(&pool, 1).await;
    let user = mfa_required_user(&app, &pool).await;
    let (totp, passkey) = factors(&pool, user).await;
    let ctx = RequestContext::system(Locale::default());
    app.services
        .webauthn
        .delete_passkey(&ctx, &principal(&app, user), passkey)
        .await
        .unwrap();
    // The remaining TOTP is now the last factor and stays.
    let err = app
        .services
        .mfa
        .remove_factor(&ctx, &principal(&app, user), totp)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_LAST_FACTOR_REQUIRED);
    assert_eq!(remaining_factors(&pool, user).await, 1);
}

/// Audit finding (MFA-07, PKY-04, K-69 follow-up): the passkey removal
/// must count only the factors the policy still **permits**. Under a
/// phishing-resistant organization policy a TOTP factor does not satisfy
/// MFA, so removing the last passkey would leave the account without a
/// usable factor; the TOTP removal path (`MfaService::remove_factor`)
/// already refuses the equivalent removal. Before the fix the server's
/// `mfa_facts` counted every enrolled non-passkey factor and the removal
/// succeeded.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_07_last_permitted_factor_cannot_be_removed_as_a_passkey(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let user = mfa_required_user(&app, &pool).await;
    sqlx::query("UPDATE org_policies SET phishing_resistant_mfa_required = true")
        .execute(&pool)
        .await
        .unwrap();
    let (_totp, passkey) = factors(&pool, user).await;
    let ctx = RequestContext::system(Locale::default());
    let err = app
        .services
        .webauthn
        .delete_passkey(&ctx, &principal(&app, user), passkey)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::mfa::MFA_LAST_FACTOR_REQUIRED);
    assert_eq!(remaining_factors(&pool, user).await, 2);

    // Without the phishing-resistant requirement the TOTP is a permitted
    // factor and the passkey may go.
    sqlx::query(
        "UPDATE org_policies SET phishing_resistant_mfa_required = false, mfa_required = true",
    )
    .execute(&pool)
    .await
    .unwrap();
    app.services
        .webauthn
        .delete_passkey(&ctx, &principal(&app, user), passkey)
        .await
        .unwrap();
    assert_eq!(remaining_factors(&pool, user).await, 1);
}

type Removal = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AuthError>> + Send>>;

/// Lines two removals up behind a lock on the user row held by a third
/// connection (`first` queues first), releases the row and returns both
/// results in the order given.
async fn race_pair(
    admin_pool: &PgPool,
    user: UserId,
    first: impl FnOnce() -> Removal,
    second: impl FnOnce() -> Removal,
) -> (Result<(), AuthError>, Result<(), AuthError>) {
    let mut blocker = admin_pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let a = tokio::spawn(first());
    wait_for_lock_waiters(admin_pool, 1).await;
    let b = tokio::spawn(second());
    wait_for_lock_waiters(admin_pool, 2).await;
    blocker.commit().await.unwrap();
    (a.await.unwrap(), b.await.unwrap())
}

/// Strong sign-in methods left (password, passwordless passkey, linked
/// identity).
async fn strong_methods(pool: &PgPool, user: UserId) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM password_credentials WHERE user_id = $1) \
              + (SELECT count(*) FROM webauthn_credentials WHERE user_id = $1 \
                 AND usage IN ('passwordless', 'both')) \
              + (SELECT count(*) FROM identities WHERE user_id = $1)",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn login_passkey(pool: &PgPool, user: UserId) -> CredentialId {
    let id = CredentialId::generate();
    sqlx::query(
        "INSERT INTO webauthn_credentials \
         (id, user_id, credential_id, passkey, name, usage, created_at) \
         VALUES ($1, $2, $3, '{}'::jsonb, 'Key', 'passwordless', now())",
    )
    .bind(id)
    .bind(user)
    .bind(uuid::Uuid::now_v7().as_bytes().to_vec())
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn identity(pool: &PgPool, user: UserId) -> authn_core::id::IdentityId {
    let id = authn_core::id::IdentityId::generate();
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, subject, created_at) \
         VALUES ($1, $2, 'google', $3, now())",
    )
    .bind(id)
    .bind(user)
    .bind(uuid::Uuid::now_v7().to_string())
    .execute(pool)
    .await
    .unwrap();
    id
}

/// PWD-11 / PKY-04 / SOC-06 (K-69 audit): the last-login-method rule
/// across modules, with the server's real hook adapters. "Remove the
/// password" racing "delete the only passkey", and "remove the password"
/// racing "unlink the only identity", in both lock orders: one succeeds,
/// the other is refused, one strong method is left. All three paths lock
/// the same `users` row and read the other modules' state through their
/// own transaction, on a pool exactly as large as the two removals.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_11_k69_cross_module_last_login_method_races_keep_one_method(pool: PgPool) {
    let app = app_with_pool_size(&pool, 2).await;
    let user = app.user("bob@example.com").await;
    let ctx = RequestContext::system(Locale::default());
    let refused = |r: &Result<(), AuthError>| {
        matches!(r, Err(e) if [
            codes::password::PASSWORD_REMOVAL_NOT_ALLOWED,
            codes::webauthn::PASSKEY_LAST_LOGIN_METHOD,
            codes::oidc_client::IDENTITY_LAST_LOGIN_METHOD,
        ].contains(&e.code()))
    };
    let (hash, algorithm, pepper): (String, String, Option<i32>) = sqlx::query_as(
        "SELECT password_hash, algorithm, pepper_version FROM password_credentials \
         WHERE user_id = $1",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    let reset = || {
        let (pool, hash, algorithm) = (pool.clone(), hash.clone(), algorithm.clone());
        async move {
            for table in ["webauthn_credentials", "identities", "password_credentials"] {
                let sql = match table {
                    "webauthn_credentials" => "DELETE FROM webauthn_credentials WHERE user_id = $1",
                    "identities" => "DELETE FROM identities WHERE user_id = $1",
                    _ => "DELETE FROM password_credentials WHERE user_id = $1",
                };
                sqlx::query(sql).bind(user).execute(&pool).await.unwrap();
            }
            sqlx::query(
                "INSERT INTO password_credentials (user_id, password_hash, algorithm, pepper_version) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(user)
            .bind(hash)
            .bind(algorithm)
            .bind(pepper)
            .execute(&pool)
            .await
            .unwrap();
        }
    };

    for password_first in [true, false] {
        // Password vs. the only passwordless passkey.
        reset().await;
        let passkey = login_passkey(&pool, user).await;
        let remove_password = {
            let (s, c, p) = (
                app.services.passwords.clone(),
                ctx.clone(),
                principal(&app, user),
            );
            move || -> Removal { Box::pin(async move { s.remove_password(&c, &p).await }) }
        };
        let remove_passkey = {
            let (s, c, p) = (
                app.services.webauthn.clone(),
                ctx.clone(),
                principal(&app, user),
            );
            move || -> Removal { Box::pin(async move { s.delete_passkey(&c, &p, passkey).await }) }
        };
        let (pw, pk) = if password_first {
            race_pair(&pool, user, remove_password, remove_passkey).await
        } else {
            let (pk, pw) = race_pair(&pool, user, remove_passkey, remove_password).await;
            (pw, pk)
        };
        let label = format!("password/passkey, password first: {password_first}");
        assert_eq!(
            strong_methods(&pool, user).await,
            1,
            "{label}: {pw:?} {pk:?}"
        );
        assert!(pw.is_ok() != pk.is_ok(), "{label}: {pw:?} {pk:?}");
        assert!(refused(&pw) || refused(&pk), "{label}: {pw:?} {pk:?}");

        // Password vs. the only linked identity.
        reset().await;
        let linked = identity(&pool, user).await;
        let remove_password = {
            let (s, c, p) = (
                app.services.passwords.clone(),
                ctx.clone(),
                principal(&app, user),
            );
            move || -> Removal { Box::pin(async move { s.remove_password(&c, &p).await }) }
        };
        let unlink = {
            let (s, c, p) = (
                app.services.oidc.clone(),
                ctx.clone(),
                principal(&app, user),
            );
            move || -> Removal { Box::pin(async move { s.unlink(&c, &p, linked).await }) }
        };
        let (pw, un) = if password_first {
            race_pair(&pool, user, remove_password, unlink).await
        } else {
            let (un, pw) = race_pair(&pool, user, unlink, remove_password).await;
            (pw, un)
        };
        let label = format!("password/identity, password first: {password_first}");
        assert_eq!(
            strong_methods(&pool, user).await,
            1,
            "{label}: {pw:?} {un:?}"
        );
        assert!(pw.is_ok() != un.is_ok(), "{label}: {pw:?} {un:?}");
        assert!(refused(&pw) || refused(&un), "{label}: {pw:?} {un:?}");
    }
}
