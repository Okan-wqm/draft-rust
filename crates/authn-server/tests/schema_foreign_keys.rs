#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-70 (wave 6B): schema-wide foreign-key index check over every
//! migration of the workspace.
//!
//! A foreign key whose referencing columns lead no valid index makes every
//! delete (or key update) of a referenced row scan the whole referencing
//! table once per row: the purge of 100 sessions over 300k refresh tokens
//! took 23.8 s before migrations 2050–2053 and 17 ms after
//! (`docs/operations/performance.md`). `authn-session/tests/k70_indexes.rs`
//! pins the session tables; this test covers every table of the schema, so
//! a new foreign key without an index fails here.
//!
//! [`KNOWN_UNINDEXED`] lists the foreign keys that existed without an index
//! when this check was introduced. Each entry is owned by the module of its
//! table and is tracked in `docs/handoff/remaining-work.md`; the list may
//! only shrink — an entry that gains an index (or disappears) fails the
//! test until it is removed here.

use std::collections::BTreeSet;

use sqlx::PgPool;

/// Foreign keys (constraint names) without an index whose referencing
/// columns are exactly its leading columns, with the owning module and
/// the reason the gap is accepted. Never add an entry for a new foreign
/// key: index it (`CREATE INDEX CONCURRENTLY`, `-- no-transaction`, see
/// migrations 2050–2053, 1402–1404 and the K-103 set).
///
/// K-103 (wave 7) indexed the 21 other keys that were listed here
/// (`0016`, `1202`, `1301`, `1502`–`1513`, `1704`, `2054`–`2057`, `2103`).
const KNOWN_UNINDEXED: &[(&str, &str)] = &[
    // authn-audit (1700–1799). The composite key (endpoint_id, org_id)
    // only pins the tenant: endpoint_id alone is unique (primary key), so
    // the foreign-key action is served by webhook_deliveries_endpoint_created_idx
    // and webhook_deliveries_endpoint_event_key, which both lead with
    // endpoint_id. A third index on the busiest webhook table would only
    // add write cost; `k_103_webhook_endpoint_deletion_uses_an_endpoint_index`
    // pins the plan.
    ("webhook_deliveries_endpoint_fk", "authn-audit"),
];

/// Foreign keys of the migrated schema whose referencing columns are not
/// exactly the leading columns of a valid B-tree index (any order). A
/// partial index counts only when its predicate is `<column> IS NOT NULL`
/// of a single-column key: the foreign-key action looks for every non-NULL
/// key, so an index of a subset of the rows (`WHERE revoked_at IS NULL`)
/// cannot serve it (wave 6B audit).
async fn unindexed_foreign_keys(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT c.conname::text FROM pg_constraint c \
         JOIN pg_class r ON r.oid = c.conrelid \
         WHERE c.contype = 'f' AND r.relnamespace = current_schema()::regnamespace \
         AND NOT EXISTS (SELECT 1 FROM pg_index i \
             JOIN pg_class ic ON ic.oid = i.indexrelid \
             JOIN pg_am am ON am.oid = ic.relam \
             WHERE i.indrelid = c.conrelid \
             AND i.indisvalid AND am.amname = 'btree' \
             AND (i.indkey::int2[])[0:cardinality(c.conkey) - 1] @> c.conkey \
             AND (i.indkey::int2[])[0:cardinality(c.conkey) - 1] <@ c.conkey \
             AND (i.indpred IS NULL \
                  OR (cardinality(c.conkey) = 1 \
                      AND pg_get_expr(i.indpred, i.indrelid) = format('(%s IS NOT NULL)', \
                          (SELECT quote_ident(a.attname) FROM pg_attribute a \
                           WHERE a.attrelid = c.conrelid AND a.attnum = c.conkey[1])))))",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .collect()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_every_foreign_key_of_the_schema_is_indexed(pool: PgPool) {
    let unindexed = unindexed_foreign_keys(&pool).await;
    let known: BTreeSet<String> = KNOWN_UNINDEXED
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let new: Vec<&String> = unindexed.difference(&known).collect();
    assert!(
        new.is_empty(),
        "foreign keys without an index (add a CREATE INDEX CONCURRENTLY migration): {new:?}"
    );
    let stale: Vec<&String> = known.difference(&unindexed).collect();
    assert!(
        stale.is_empty(),
        "indexed or removed; delete from KNOWN_UNINDEXED: {stale:?}"
    );
}

/// The check itself sees a foreign key without an index (and stops seeing
/// it once indexed), so an always-green query cannot hide one.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_the_foreign_key_check_detects_a_missing_index(pool: PgPool) {
    sqlx::raw_sql(
        "CREATE TABLE k70_probe (id uuid PRIMARY KEY, \
             user_id uuid REFERENCES users (id) ON DELETE CASCADE)",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        unindexed_foreign_keys(&pool)
            .await
            .contains("k70_probe_user_id_fkey")
    );
    sqlx::raw_sql(
        "CREATE INDEX k70_probe_user_idx ON k70_probe (user_id) WHERE user_id IS NOT NULL",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        !unindexed_foreign_keys(&pool)
            .await
            .contains("k70_probe_user_id_fkey")
    );
}

/// Wave 6B: the passkey ceremony table is indexed on every foreign key
/// (migrations 1402–1404) and the cascade from an auth challenge uses the
/// index.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_ceremony_foreign_keys_are_indexed(pool: PgPool) {
    let unindexed = unindexed_foreign_keys(&pool).await;
    for fk in [
        "webauthn_ceremonies_user_id_fkey",
        "webauthn_ceremonies_session_id_fkey",
        "webauthn_ceremonies_challenge_id_fkey",
    ] {
        assert!(!unindexed.contains(fk), "{fk}");
    }
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN DELETE FROM webauthn_ceremonies \
         WHERE challenge_id = '00000000-0000-7000-8000-000000000009'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let plan = plan.join("\n");
    assert!(plan.contains("webauthn_ceremonies_challenge_idx"), "{plan}");
}

/// `(version, index, statement)` of every `-- no-transaction` migration
/// that builds an index with `CREATE INDEX CONCURRENTLY`.
fn concurrent_index_migrations() -> Vec<(i64, String, String)> {
    authn_testkit::MIGRATOR
        .iter()
        .filter(|m| m.no_tx)
        .filter_map(|m| {
            let statement = m
                .sql
                .as_str()
                .lines()
                .find(|l| l.starts_with("CREATE INDEX CONCURRENTLY "))?;
            let name = statement
                .strip_prefix("CREATE INDEX CONCURRENTLY ")?
                .split_whitespace()
                .next()?;
            Some((m.version, name.to_owned(), statement.to_owned()))
        })
        .collect()
}

/// Every concurrent index migration (not only 2050–2053, which
/// `authn-session` pins) refuses to be recorded over an INVALID index left
/// by an interrupted build, and the documented remedy (drop, migrate again)
/// builds a valid index. Guards against `IF NOT EXISTS` in a new one.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_concurrent_index_migrations_never_keep_an_invalid_index(pool: PgPool) {
    let migrations = concurrent_index_migrations();
    let versions: Vec<i64> = migrations.iter().map(|(v, _, _)| *v).collect();
    for expected in [
        16, 1202, 1301, 1402, 1403, 1404, 1502, 1503, 1504, 1505, 1506, 1507, 1508, 1509, 1510,
        1511, 1512, 1513, 1704, 2050, 2051, 2052, 2053, 2054, 2055, 2056, 2057, 2103,
    ] {
        assert!(versions.contains(&expected), "{expected}: {versions:?}");
    }
    for (version, index, statement) in migrations {
        assert!(
            !statement.contains("IF NOT EXISTS"),
            "{version}: IF NOT EXISTS would record the migration over an INVALID index"
        );
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE pg_index SET indisvalid = false WHERE indexrelid = to_regclass($1)")
            .bind(&index)
            .execute(&pool)
            .await
            .unwrap();
        let rerun = authn_testkit::MIGRATOR.run(&pool).await;
        let valid: Option<bool> = sqlx::query_scalar(
            "SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)",
        )
        .bind(&index)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(
            rerun.is_err() || valid == Some(true),
            "{index}: migration {version} was recorded as applied over an INVALID index"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP INDEX CONCURRENTLY IF EXISTS {index}"
        )))
        .execute(&pool)
        .await
        .unwrap();
        authn_testkit::MIGRATOR.run(&pool).await.unwrap();
        let valid: bool = sqlx::query_scalar(
            "SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)",
        )
        .bind(&index)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(valid, "{index}: rebuilt after the drop");
    }
}

/// Wave 6B audit: a partial index only serves the foreign-key action when
/// its predicate is implied by "the key is not NULL". An index of the
/// active rows (`WHERE revoked_at IS NULL`) is useless to a cascade that
/// must find the revoked ones too, and must not hide the missing index;
/// neither may an index whose leading column is another column.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_the_foreign_key_check_ignores_unusable_indexes(pool: PgPool) {
    sqlx::raw_sql(
        "CREATE TABLE k70_probe (id uuid PRIMARY KEY, revoked_at timestamptz, \
             user_id uuid REFERENCES users (id) ON DELETE CASCADE); \
         CREATE INDEX k70_probe_active_user_idx ON k70_probe (user_id) \
             WHERE revoked_at IS NULL; \
         CREATE INDEX k70_probe_revoked_user_idx ON k70_probe (revoked_at, user_id)",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        unindexed_foreign_keys(&pool)
            .await
            .contains("k70_probe_user_id_fkey"),
        "an index the foreign-key action cannot use was counted"
    );
    sqlx::raw_sql("CREATE INDEX k70_probe_user_idx ON k70_probe (user_id, revoked_at)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !unindexed_foreign_keys(&pool)
            .await
            .contains("k70_probe_user_id_fkey")
    );
}

/// Plans of `statement` with sequential scans disabled: a remaining
/// `Seq Scan` means no index can serve it at all.
async fn plan_without_seq_scan(pool: &PgPool, statement: String) -> String {
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("EXPLAIN {statement}")))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    plan.join("\n")
}

/// K-103: deleting a user (ACC-09 erasure, ACC-05 placeholder purge) runs
/// one foreign-key action per referencing column — `DELETE … WHERE col = $1`
/// for `ON DELETE CASCADE`, `UPDATE … SET col = NULL WHERE col = $1` for
/// `SET NULL`. Every one of them (read from the catalog, so a new reference
/// to `users` is covered) is planned as an index scan, not a scan of the
/// whole table per deleted user. Before the K-103 migrations 14 of them
/// (sessions, auth challenges, one-time tokens, trusted devices, OAuth
/// states and the "who did it" columns of the org and webhook tables)
/// could only scan.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_103_user_deletion_cascades_use_indexes(pool: PgPool) {
    let references: Vec<(String, String)> = sqlx::query_as(
        "SELECT quote_ident(r.relname), quote_ident(a.attname) FROM pg_constraint c \
         JOIN pg_class r ON r.oid = c.conrelid \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] \
         WHERE c.contype = 'f' AND c.confrelid = 'users'::regclass \
         AND cardinality(c.conkey) = 1 ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(references.len() >= 30, "{references:?}");
    let mut scanned = Vec::new();
    for (table, column) in &references {
        let plan = plan_without_seq_scan(
            &pool,
            format!(
                "DELETE FROM ONLY {table} \
                 WHERE {column} = '00000000-0000-7000-8000-000000000001'::uuid"
            ),
        )
        .await;
        if plan.contains("Seq Scan") {
            scanned.push(format!("{table}.{column}:\n{plan}"));
        }
    }
    assert!(scanned.is_empty(), "{}", scanned.join("\n\n"));
    // A representative plan names the new index.
    let plan = plan_without_seq_scan(
        &pool,
        "DELETE FROM ONLY sessions WHERE user_id = '00000000-0000-7000-8000-000000000001'::uuid"
            .to_owned(),
    )
    .await;
    assert!(plan.contains("sessions_user_id_idx"), "{plan}");
}

/// K-103: the composite foreign keys indexed by K-103 (member and service
/// account API keys) and the one kept in [`KNOWN_UNINDEXED`] (webhook
/// deliveries of an endpoint) are served by an index whose leading
/// columns are the key.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_103_webhook_endpoint_deletion_uses_an_endpoint_index(pool: PgPool) {
    for (statement, index) in [
        (
            "DELETE FROM ONLY webhook_deliveries \
             WHERE endpoint_id = '00000000-0000-7000-8000-000000000001'::uuid \
             AND org_id = '00000000-0000-7000-8000-000000000002'::uuid",
            "webhook_deliveries_endpoint_",
        ),
        (
            "DELETE FROM ONLY api_keys \
             WHERE user_id = '00000000-0000-7000-8000-000000000001'::uuid \
             AND org_id = '00000000-0000-7000-8000-000000000002'::uuid",
            "api_keys_",
        ),
        (
            "DELETE FROM ONLY api_keys \
             WHERE service_account_id = '00000000-0000-7000-8000-000000000001'::uuid \
             AND org_id = '00000000-0000-7000-8000-000000000002'::uuid",
            "api_keys_",
        ),
    ] {
        let plan = plan_without_seq_scan(&pool, statement.to_owned()).await;
        assert!(!plan.contains("Seq Scan"), "{plan}");
        assert!(plan.contains(index), "{plan}");
    }
}
