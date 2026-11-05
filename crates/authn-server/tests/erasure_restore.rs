#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-108 (ACC-09; KVKK md. 7, GDPR art. 17): erasures completed after a
//! backup are re-applied after restoring it, from the erasure ledger
//! exported outside the database.
//!
//! The restore is simulated with a real copy of the database
//! (`CREATE DATABASE … TEMPLATE …`) taken before the erasure.

mod common;

use std::time::Duration;

use authn_account::{ErasureRecord, ReapplyOutcome};
use authn_core::id::UserId;
use axum::http::StatusCode;
use common::{App, PASSWORD};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const DAY: Duration = Duration::from_secs(24 * 3600);

/// A copy of `pool`'s database as of now (the "backup"). Closes `pool`.
async fn snapshot(pool: PgPool) -> (PgConnectOptions, String) {
    let options = (*pool.connect_options()).clone();
    let source = options.get_database().unwrap().to_owned();
    pool.close().await;
    let master = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let copy = format!("k108_{}", uuid::Uuid::now_v7().simple());
    // Database names cannot be bound; both are generated.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{copy}\" TEMPLATE \"{source}\""
    )))
    .execute(&master)
    .await
    .unwrap();
    master.close().await;
    (options, copy)
}

async fn open(options: &PgConnectOptions, database: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options.clone().database(database))
        .await
        .unwrap()
}

async fn drop_database(name: &str) {
    let master = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
    )))
    .execute(&master)
    .await;
    master.close().await;
}

async fn user_exists(pool: &PgPool, user: UserId) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Requests the deletion of `email`'s account through the API and lets the
/// grace period run out.
async fn delete_through_the_api(app: &App, email: &str) {
    let mut browser = app.browser();
    let body = browser.login(app, email, PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    browser.csrf(app).await;
    let r = browser.send(app, browser.delete("/v1/me")).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.text());
    app.advance(DAY * 31);
    let report = app.services.accounts.purge_due_deletions(10).await.unwrap();
    assert_eq!(report.purged, 1, "{report:?}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_108_erasure_is_reapplied_after_restoring_an_older_backup(pool: PgPool) {
    // Day 0: alice and bob exist; the nightly backup is taken.
    let (alice, bob) = {
        let app = App::new(pool.clone()).await;
        let alice = app.user("alice@example.com").await;
        let bob = app.user("bob@example.com").await;
        (alice, bob)
    };
    let (options, backup) = snapshot(pool).await;
    let live_db = options.get_database().unwrap().to_owned();

    // After the backup: alice deletes her account; it is erased.
    let live = open(&options, &live_db).await;
    let exported: Vec<ErasureRecord> = {
        let app = App::new(live.clone()).await;
        app.advance(DAY);
        delete_through_the_api(&app, "alice@example.com").await;
        assert!(!user_exists(&live, alice).await);
        // The operator's periodic export (`export-erasures`), kept outside
        // the database.
        app.services
            .accounts
            .export_erasures(time::OffsetDateTime::UNIX_EPOCH, None, 1000)
            .await
            .unwrap()
    };
    live.close().await;
    let entry = exported
        .iter()
        .find(|e| e.user_id == alice)
        .expect("the erasure is in the ledger");
    assert_eq!(entry.reason, "grace_period_elapsed");
    assert!(exported.iter().all(|e| e.user_id != bob));

    // Disaster: the database is restored from the day-0 backup.
    let restored = open(&options, &backup).await;
    {
        let app = App::new(restored.clone()).await;
        app.advance(DAY * 40);
        // The defect: the restore brought alice back, the restored ledger
        // does not know her erasure, and no job removes her.
        assert!(user_exists(&restored, alice).await);
        let totals = authn_server::jobs::run_maintenance_once(&app.services).await;
        assert_eq!(totals.failed, 0, "{totals:?}");
        assert!(user_exists(&restored, alice).await);

        // The fix: re-apply the exported ledger (`reapply-erasures`).
        for e in &exported {
            assert_eq!(
                app.services.accounts.reapply_erasure(e).await.unwrap(),
                ReapplyOutcome::Erased
            );
        }
        assert!(!user_exists(&restored, alice).await);
        assert!(user_exists(&restored, bob).await);
        // Erased through the normal path: audit pseudonym unlinked, a
        // ledger row with the ORIGINAL time and reason, login impossible.
        let linked: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM audit_subjects WHERE user_id = $1)")
                .bind(alice)
                .fetch_one(&restored)
                .await
                .unwrap();
        assert!(!linked, "the audit pseudonym still points at alice");
        let ledger = app
            .services
            .accounts
            .export_erasures(time::OffsetDateTime::UNIX_EPOCH, None, 1000)
            .await
            .unwrap();
        assert_eq!(ledger, exported);
        let mut browser = app.browser();
        let body = browser.login(&app, "alice@example.com", PASSWORD).await;
        assert_ne!(body["status"], "authenticated", "{body}");

        // Idempotent: a second run (or an overlapping export) changes
        // nothing.
        for e in &exported {
            assert_eq!(
                app.services.accounts.reapply_erasure(e).await.unwrap(),
                ReapplyOutcome::AlreadyErased
            );
        }
        assert!(user_exists(&restored, bob).await);
    }
    restored.close().await;
    drop_database(&backup).await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_108_reapply_erases_every_status_and_completes_a_restored_schedule(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let now = authn_core::ports::Clock::now(app.ports.clock.as_ref());
    let mut entries = Vec::new();
    for (i, status) in [
        "active",
        "suspended",
        "disabled",
        "locked",
        "pending_verification",
        "pending_deletion",
    ]
    .into_iter()
    .enumerate()
    {
        let user = app.user(&format!("u{i}@example.com")).await;
        if status == "pending_verification" {
            sqlx::query("UPDATE users SET email_verified_at = NULL WHERE id = $1")
                .bind(user)
                .execute(&pool)
                .await
                .unwrap();
        }
        let locked_until = (status == "locked").then(|| now + time::Duration::days(1));
        sqlx::query("UPDATE users SET status = $2, locked_until = $3 WHERE id = $1")
            .bind(user)
            .bind(status)
            .bind(locked_until)
            .execute(&pool)
            .await
            .unwrap();
        if status == "pending_deletion" {
            // The restored, not yet due schedule.
            sqlx::query(
                "INSERT INTO account_deletions (id, user_id, status, requested_at, scheduled_for, previous_status) \
                 VALUES ($1, $2, 'scheduled', $3, $4, 'active')",
            )
            .bind(uuid::Uuid::now_v7())
            .bind(user)
            .bind(now)
            .bind(now + time::Duration::days(30))
            .execute(&pool)
            .await
            .unwrap();
        }
        entries.push((
            status,
            ErasureRecord {
                user_id: user,
                erased_at: now - time::Duration::days(1),
                reason: "grace_period_elapsed".to_owned(),
            },
        ));
    }
    for (status, entry) in &entries {
        assert_eq!(
            app.services.accounts.reapply_erasure(entry).await.unwrap(),
            ReapplyOutcome::Erased,
            "{status}"
        );
        assert!(!user_exists(&pool, entry.user_id).await, "{status}");
    }
    let open_schedules: i64 =
        sqlx::query_scalar("SELECT count(*) FROM account_deletions WHERE status = 'scheduled'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(open_schedules, 0);
    // The audit trail records the re-applied erasures.
    let erased: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE kind = 'account.deleted' \
         AND metadata->>'reason' = 'erasure_reapplied'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(erased, 6);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_108_last_owner_is_reported_not_erased(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let owner = app.user("owner@example.com").await;
    let mut browser = app.browser();
    let body = browser.login(&app, "owner@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    browser.csrf(&app).await;
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/orgs",
                &serde_json::json!({"name": "Acme", "slug": "acme"}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{} {}", r.status, r.text());
    let entry = ErasureRecord {
        user_id: owner,
        erased_at: authn_core::ports::Clock::now(app.ports.clock.as_ref()),
        reason: "grace_period_elapsed".to_owned(),
    };
    assert_eq!(
        app.services.accounts.reapply_erasure(&entry).await.unwrap(),
        ReapplyOutcome::BlockedLastOwner
    );
    assert!(user_exists(&pool, owner).await);
}
