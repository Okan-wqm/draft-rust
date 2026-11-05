//! Embedded migrations (`/migrations`, OPS-10) and readiness status (OPS-05).

use std::collections::HashMap;

use sqlx::PgPool;
use sqlx::migrate::Migrator;

use crate::error::StoreError;

/// Migration version ranges per owning crate (`docs/architecture/contracts.md`).
/// A module adds follow-up migrations only inside its own range, so parallel
/// work never collides on a version number.
pub const MIGRATION_RANGES: &[(&str, i64, i64)] = &[
    ("architect (authn-core / authn-store)", 1, 99),
    ("authn-crypto", 1000, 1099),
    ("authn-password", 1100, 1199),
    ("authn-account", 1200, 1299),
    ("authn-mfa", 1300, 1399),
    ("authn-webauthn", 1400, 1499),
    ("authn-org", 1500, 1599),
    ("authn-protect", 1600, 1699),
    ("authn-audit", 1700, 1799),
    ("authn-notify", 1800, 1899),
    ("authn-session", 2000, 2099),
    ("authn-oidc-client", 2100, 2199),
    ("authn-admin", 2200, 2299),
    ("authn-server", 2900, 2999),
];

/// The owner of a migration version, if it lies in a declared range.
#[must_use]
pub fn range_owner(version: i64) -> Option<&'static str> {
    MIGRATION_RANGES
        .iter()
        .find(|(_, low, high)| (*low..=*high).contains(&version))
        .map(|(owner, _, _)| *owner)
}

/// Every migration of the workspace, embedded at compile time.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Applies pending migrations. Safe with several instances: sqlx serializes
/// runs with an advisory lock.
///
/// K-106 (rolling deployments): migrations applied by a **newer** release
/// are tolerated — migrations are expand-only (contracts §6), so this
/// binary does not depend on them. When nothing of this binary is pending
/// the migrator is not run at all (a dirty migration of a newer release is
/// that release's to repair, it must not stop older instances from
/// starting); checksums of this binary's migrations are checked by
/// [`migration_status`] / [`MigrationStatus::is_compatible`].
pub async fn run_migrations(pool: &PgPool) -> Result<(), StoreError> {
    let status = migration_status(pool).await?;
    if !status.contract_applied.is_empty() {
        // A newer release contracted the schema: this binary must not
        // touch (or run on) it.
        tracing::error!(
            contract_migrations = ?status.contract_applied,
            "database schema was contracted by a newer release; this binary is incompatible"
        );
        return Err(StoreError::Config(
            "database schema was contracted by a newer release (see logs)",
        ));
    }
    if status.pending.is_empty() {
        return Ok(());
    }
    let mut migrator = Migrator::with_migrations(MIGRATOR.iter().cloned().collect());
    migrator.set_ignore_missing(true);
    migrator.run(pool).await.map_err(|e| {
        tracing::error!(error = %e, "database migration failed");
        match e {
            sqlx::migrate::MigrateError::Execute(inner) => StoreError::from(inner),
            _ => StoreError::Config("migration failed (see logs)"),
        }
    })
}

/// Comparison of embedded and applied migrations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationStatus {
    /// Embedded versions not applied yet.
    pub pending: Vec<i64>,
    /// Versions recorded as failed (dirty).
    pub failed: Vec<i64>,
    /// Applied versions whose checksum differs from the embedded file.
    pub checksum_mismatch: Vec<i64>,
    /// Versions applied in the database (successfully or not) but unknown
    /// to this binary: a newer release already migrated (rolling
    /// deployment), or a migration file was removed (never done: migrations
    /// are append-only).
    pub unknown_applied: Vec<i64>,
    /// The subset of [`Self::unknown_applied`] that a newer release marked
    /// as **contracting** (file name `<version>_contract_<…>.sql`, contracts
    /// §6): the schema no longer supports older binaries (rollback,
    /// maintenance-window releases), so this binary is incompatible.
    pub contract_applied: Vec<i64>,
}

/// Description prefix (from the file name `<version>_contract_<…>.sql`)
/// of a migration that breaks older binaries (K-106, contracts §6).
pub const CONTRACT_MIGRATION_PREFIX: &str = "contract ";

impl MigrationStatus {
    /// Whether the schema matches this binary exactly (`migrate` output).
    #[must_use]
    pub fn is_up_to_date(&self) -> bool {
        self.is_compatible() && self.unknown_applied.is_empty()
    }

    /// Whether this binary can run on the schema (K-106; readiness and
    /// start-up): every migration of the binary is applied, none failed,
    /// none was modified. Migrations of a **newer** release are tolerated
    /// because migrations are expand-only (contracts §6): during a rolling
    /// deployment the new release migrates first and the old instances
    /// keep serving until they are replaced.
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.pending.is_empty()
            && self.failed.is_empty()
            && self.checksum_mismatch.is_empty()
            && self.contract_applied.is_empty()
    }

    /// Whether the database is ahead of this binary (newer release applied
    /// migrations it does not know).
    #[must_use]
    pub fn is_ahead(&self) -> bool {
        !self.unknown_applied.is_empty()
    }
}

#[derive(sqlx::FromRow)]
struct AppliedRow {
    version: i64,
    description: String,
    success: bool,
    checksum: Vec<u8>,
}

/// Reads `_sqlx_migrations` and compares it with [`MIGRATOR`].
pub async fn migration_status(pool: &PgPool) -> Result<MigrationStatus, StoreError> {
    let table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await?;
    let applied: Vec<AppliedRow> = if table_exists {
        sqlx::query_as(
            "SELECT version, description, success, checksum FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(pool)
        .await?
    } else {
        Vec::new()
    };
    let applied: HashMap<i64, AppliedRow> = applied.into_iter().map(|r| (r.version, r)).collect();

    let mut status = MigrationStatus::default();
    for migration in MIGRATOR
        .iter()
        .filter(|m| m.migration_type.is_up_migration())
    {
        match applied.get(&migration.version) {
            None => status.pending.push(migration.version),
            Some(row) if !row.success => status.failed.push(migration.version),
            Some(row) if row.checksum.as_slice() != migration.checksum.as_ref() => {
                status.checksum_mismatch.push(migration.version);
            }
            Some(_) => {}
        }
    }
    let known: std::collections::HashSet<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    status.unknown_applied = applied
        .keys()
        .copied()
        .filter(|v| !known.contains(v))
        .collect();
    status.unknown_applied.sort_unstable();
    status.contract_applied = status
        .unknown_applied
        .iter()
        .copied()
        .filter(|v| {
            applied
                .get(v)
                .is_some_and(|row| row.description.starts_with(CONTRACT_MIGRATION_PREFIX))
        })
        .collect();
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_10_every_migration_is_in_a_declared_range() {
        for migration in MIGRATOR.iter() {
            assert!(
                range_owner(migration.version).is_some(),
                "migration {} ({}) is outside every declared range",
                migration.version,
                migration.description
            );
        }
    }

    #[test]
    fn ops_10_ranges_do_not_overlap() {
        for (i, (a, a_low, a_high)) in MIGRATION_RANGES.iter().enumerate() {
            assert!(a_low <= a_high, "{a}");
            for (b, b_low, b_high) in MIGRATION_RANGES.iter().skip(i + 1) {
                assert!(a_high < b_low || b_high < a_low, "{a} overlaps {b}");
            }
        }
    }
}
