//! K-106: rolling deployments. Migrations are expand-only
//! (`docs/architecture/contracts.md` §6), so a binary keeps working on a
//! schema that a **newer** release has already extended: readiness and
//! start-up accept applied migrations unknown to this binary, while a
//! missing, failed or modified migration of this binary is still refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use authn_store::{MIGRATOR, migration_status};
use sqlx::PgPool;

/// A version inside the architect range that no released migration uses.
const FUTURE_VERSION: i64 = 99;

/// Records `FUTURE_VERSION` as applied, as the `migrate` step of a newer
/// release would (with a real, additive DDL statement).
async fn apply_future_migration(pool: &PgPool, success: bool) {
    assert!(
        MIGRATOR.iter().all(|m| m.version != FUTURE_VERSION),
        "pick another future version"
    );
    sqlx::query("CREATE TABLE k106_future_table (id bigint PRIMARY KEY)")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES ($1, 'future release', $2, $3, 1)",
    )
    .bind(FUTURE_VERSION)
    .bind(success)
    .bind(vec![0xab_u8; 48])
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn k_106_schema_ahead_of_the_binary_is_compatible(pool: PgPool) {
    authn_store::run_migrations(&pool).await.unwrap();
    apply_future_migration(&pool, true).await;

    let status = migration_status(&pool).await.unwrap();
    assert_eq!(status.unknown_applied, vec![FUTURE_VERSION]);
    assert!(status.pending.is_empty(), "{status:?}");
    // Not identical to this binary any more …
    assert!(!status.is_up_to_date(), "{status:?}");
    // … but every migration of this binary is applied unchanged: an older
    // instance keeps serving during a rolling deployment.
    assert!(status.is_compatible(), "{status:?}");
}

#[sqlx::test(migrations = false)]
async fn k_106_migrate_on_start_tolerates_a_schema_ahead_of_the_binary(pool: PgPool) {
    authn_store::run_migrations(&pool).await.unwrap();
    apply_future_migration(&pool, true).await;
    // `database.migrate_on_start = true` on an old instance restarting
    // after the new release migrated: nothing to apply, start-up succeeds
    // (sqlx alone refuses with "migration 99 was previously applied but is
    // missing in the resolved migrations").
    authn_store::run_migrations(&pool).await.unwrap();
    assert!(migration_status(&pool).await.unwrap().is_compatible());
}

#[sqlx::test(migrations = false)]
async fn k_106_a_failed_newer_migration_does_not_take_old_instances_down(pool: PgPool) {
    authn_store::run_migrations(&pool).await.unwrap();
    apply_future_migration(&pool, false).await;
    let status = migration_status(&pool).await.unwrap();
    assert!(status.failed.is_empty(), "{status:?}");
    assert_eq!(status.unknown_applied, vec![FUTURE_VERSION]);
    assert!(status.is_compatible(), "{status:?}");
    // Nothing of this binary is pending: start-up does not touch the
    // dirty migration (only the release that owns it can repair it).
    authn_store::run_migrations(&pool).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn k_106_modified_migration_of_the_binary_is_still_refused(pool: PgPool) {
    authn_store::run_migrations(&pool).await.unwrap();
    apply_future_migration(&pool, true).await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 1")
        .bind(vec![0_u8; 48])
        .execute(&pool)
        .await
        .unwrap();
    let status = migration_status(&pool).await.unwrap();
    assert_eq!(status.checksum_mismatch, vec![1]);
    assert!(!status.is_compatible(), "{status:?}");
}

#[sqlx::test(migrations = false)]
async fn k_106_missing_migration_of_the_binary_is_still_refused(pool: PgPool) {
    authn_store::run_migrations(&pool).await.unwrap();
    apply_future_migration(&pool, true).await;
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 14")
        .execute(&pool)
        .await
        .unwrap();
    let status = migration_status(&pool).await.unwrap();
    assert_eq!(status.pending, vec![14]);
    assert!(!status.is_compatible(), "{status:?}");
}

#[sqlx::test(migrations = false)]
async fn k_106_failed_migration_of_the_binary_is_still_refused(pool: PgPool) {
    authn_store::run_migrations(&pool).await.unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = 14")
        .execute(&pool)
        .await
        .unwrap();
    let status = migration_status(&pool).await.unwrap();
    assert_eq!(status.failed, vec![14]);
    assert!(!status.is_compatible(), "{status:?}");
}

/// K-106 audit: a newer release that cannot keep the expand-only rule
/// names its contracting migration `<version>_contract_<description>.sql`
/// (contracts §6). An older binary must refuse that schema (start-up,
/// readiness, `migrate`) instead of serving on removed columns — the
/// rollback / downgrade case, and an old instance restarted after the
/// maintenance window.
#[sqlx::test(migrations = false)]
async fn k_106_contract_migration_of_a_newer_release_is_refused(pool: PgPool) {
    authn_store::run_migrations(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES ($1, 'contract drop users legacy column', true, $2, 1)",
    )
    .bind(FUTURE_VERSION)
    .bind(vec![0xab_u8; 48])
    .execute(&pool)
    .await
    .unwrap();
    let status = migration_status(&pool).await.unwrap();
    assert_eq!(status.unknown_applied, vec![FUTURE_VERSION]);
    assert_eq!(status.contract_applied, vec![FUTURE_VERSION]);
    assert!(!status.is_compatible(), "{status:?}");
    // `migrate_on_start` / `migrate` of the old binary refuse it too.
    assert!(authn_store::run_migrations(&pool).await.is_err());
}
