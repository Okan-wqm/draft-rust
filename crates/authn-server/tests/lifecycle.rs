#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OPS-07: dropping the last `Services` handle releases every service and
//! its database pool. The late-bound hooks used to form reference cycles
//! (passkeys ↔ MFA, accounts → revert hook → social login → accounts), so a
//! dropped application kept its pool alive forever: a child pool never
//! returned the connections it borrowed from its parent (exactly how
//! `#[sqlx::test]` pools work, which made long test binaries time out).

mod common;

use std::time::Duration;

use common::App;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_07_dropped_services_release_their_pool(pool: PgPool) {
    let options = (*pool.connect_options()).clone();
    // A parent with room for one child at a time.
    let parent = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy_with(options.clone());
    for round in 0..4 {
        let child = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .parent(parent.clone())
            .connect_with(options.clone())
            .await
            .unwrap_or_else(|e| {
                panic!("round {round}: the previous application leaked its pool: {e}")
            });
        {
            let app = App::new(child.clone()).await;
            app.user(&format!("u{round}@example.com")).await;
            let mut browser = app.browser();
            browser
                .login(&app, &format!("u{round}@example.com"), common::PASSWORD)
                .await;
            app.drain().await;
        }
        child.close().await;
        drop(child);
    }
}

/// Wave 3A audit: a module service that outlives the last `Services`
/// handle cannot reach its late-bound hooks any more; the hook then fails
/// with an error instead of answering "nothing found" (fail closed: here
/// MFA could otherwise under-count the second factors of a user).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_07_hooks_fail_closed_once_the_services_are_dropped(pool: PgPool) {
    let app = App::new(pool).await;
    let user = app.user("late@example.com").await;
    let mfa = app.services.mfa.clone();
    // While the application lives, the policy input is computed.
    mfa.evaluate_for_user(user, None, false).await.unwrap();
    drop(app);
    let err = mfa.evaluate_for_user(user, None, false).await.unwrap_err();
    assert!(err.status().is_server_error(), "{err}");
}
