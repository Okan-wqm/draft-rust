#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-70: every foreign key of the session tables has an index on its
//! referencing column. Without one, deleting a referenced row (the session
//! purge job, OPS-06; account deletion) scans the whole referencing table
//! once per deleted row — measured: purging 100 sessions over 300k refresh
//! tokens took 23.8 s before migrations 2050–2053 and 17 ms after.

use sqlx::PgPool;

/// Single-column foreign keys of `table` whose column does not lead any
/// valid index.
async fn unindexed_foreign_keys(pool: &PgPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT a.attname::text FROM pg_constraint c \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] \
         WHERE c.contype = 'f' AND c.conrelid = $1::regclass AND cardinality(c.conkey) = 1 \
         AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid \
             AND i.indisvalid AND i.indkey[0] = c.conkey[1]) \
         ORDER BY 1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_session_table_foreign_keys_are_indexed(pool: PgPool) {
    for table in ["sessions", "refresh_tokens", "auth_challenges"] {
        assert_eq!(
            unindexed_foreign_keys(&pool, table).await,
            Vec::<String>::new(),
            "{table}: foreign keys without an index"
        );
    }
}

/// The purge of ended sessions still cascades through the refresh-token
/// chain (the `ON DELETE SET NULL` self references) with the new indexes.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_purging_sessions_cascades_through_refresh_token_chains(pool: PgPool) {
    sqlx::raw_sql(
        "INSERT INTO users (id, email, email_normalized, status, created_at) \
         VALUES ('00000000-0000-7000-8000-000000000001', 'a@example.com', 'a@example.com', \
                 'active', now()); \
         INSERT INTO sessions (id, user_id, client_kind, amr, auth_time, created_at, \
             last_seen_at, idle_expires_at, absolute_expires_at) \
         SELECT gen_random_uuid(), '00000000-0000-7000-8000-000000000001', 'native', '{pwd}', \
             now() - interval '100 days', now() - interval '100 days', now() - interval '99 days', \
             now() - interval '90 days', now() - interval '10 days' FROM generate_series(1, 50); \
         INSERT INTO refresh_tokens (id, session_id, token_hash, generation, created_at, \
             idle_expires_at, absolute_expires_at, used_at) \
         SELECT gen_random_uuid(), s.id, sha256(convert_to(s.id::text || g, 'UTF8')), g, \
             now() - interval '100 days', now() - interval '90 days', now() - interval '10 days', \
             CASE WHEN g < 2 THEN now() - interval '95 days' END \
         FROM sessions s, generate_series(0, 2) g; \
         UPDATE refresh_tokens r SET parent_id = p.id FROM refresh_tokens p \
             WHERE p.session_id = r.session_id AND p.generation = r.generation - 1; \
         UPDATE refresh_tokens r SET replaced_by_id = n.id FROM refresh_tokens n \
             WHERE n.session_id = r.session_id AND n.generation = r.generation + 1;",
    )
    .execute(&pool)
    .await
    .unwrap();
    let deleted =
        sqlx::query("DELETE FROM sessions WHERE id IN (SELECT id FROM sessions LIMIT 20)")
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected();
    assert_eq!(deleted, 20);
    let (tokens, dangling): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE (parent_id IS NOT NULL AND NOT EXISTS \
             (SELECT 1 FROM refresh_tokens p WHERE p.id = r.parent_id)) \
             OR (replaced_by_id IS NOT NULL AND NOT EXISTS \
             (SELECT 1 FROM refresh_tokens n WHERE n.id = r.replaced_by_id))) \
         FROM refresh_tokens r",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tokens, 90, "the purged sessions' tokens cascade away");
    assert_eq!(dangling, 0);
    // The index is what the foreign-key action uses.
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN UPDATE refresh_tokens SET parent_id = NULL \
         WHERE parent_id = '00000000-0000-7000-8000-000000000009'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let plan = plan.join("\n");
    assert!(plan.contains("refresh_tokens_parent_idx"), "{plan}");
}

/// An interrupted `CREATE INDEX CONCURRENTLY` (deploy killed mid-build,
/// statement timeout, deadlock with a second migrating instance) leaves an
/// INVALID index behind and records nothing in `_sqlx_migrations`. The
/// re-run must not record the migration as applied over that index: it
/// fails loudly (the documented remedy is `DROP INDEX CONCURRENTLY` and a
/// new run), and after the drop it builds a valid index.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_rerun_after_an_interrupted_index_build_never_keeps_an_invalid_index(pool: PgPool) {
    for (version, index) in [
        (2050_i64, "refresh_tokens_parent_idx"),
        (2051, "refresh_tokens_replaced_by_idx"),
        (2052, "auth_challenges_session_idx"),
        (2053, "auth_challenges_requested_org_idx"),
    ] {
        // State after an interrupted build: the index exists but is
        // INVALID, the migration is not recorded.
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE pg_index SET indisvalid = false \
             WHERE indexrelid = to_regclass($1)",
        )
        .bind(index)
        .execute(&pool)
        .await
        .unwrap();
        let rerun = authn_testkit::MIGRATOR.run(&pool).await;
        let valid: Option<bool> = sqlx::query_scalar(
            "SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)",
        )
        .bind(index)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(
            rerun.is_err() || valid == Some(true),
            "{index}: migration {version} was recorded as applied over an INVALID index"
        );
        // The documented remedy: drop the index, run the migrations again.
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
        .bind(index)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(valid, "{index}: rebuilt after the drop");
    }
}
