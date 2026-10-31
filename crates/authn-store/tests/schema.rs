//! Schema invariants of the initial migrations (owned by the architect).
//! These pin down security-relevant database guarantees that every module
//! relies on.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use authn_store::{MIGRATOR, StoreError, migration_status};
use sqlx::PgPool;

async fn exec(pool: &PgPool, sql: &str) -> Result<(), StoreError> {
    // Test-only fixed fixtures: no user input reaches these statements.
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(StoreError::from)
}

const USER_A: &str = "01900000-0000-7000-8000-0000000000aa";
const ORG_A: &str = "01900000-0000-7000-8000-0000000000b1";
const ORG_B: &str = "01900000-0000-7000-8000-0000000000b2";

async fn seed_user_and_orgs(pool: &PgPool) {
    exec(
        pool,
        &format!(
            "INSERT INTO users (id, email, email_normalized) VALUES ('{USER_A}', 'a@example.com', 'a@example.com');
             INSERT INTO organizations (id, slug, name) VALUES ('{ORG_A}', 'org-a', 'A'), ('{ORG_B}', 'org-b', 'B');"
        ),
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn ops_10_migrations_apply_cleanly_and_report_up_to_date(pool: PgPool) {
    let before = migration_status(&pool).await.unwrap();
    assert!(!before.is_up_to_date());
    assert_eq!(before.pending.len(), MIGRATOR.iter().count());
    authn_store::run_migrations(&pool).await.unwrap();
    let after = migration_status(&pool).await.unwrap();
    assert!(after.is_up_to_date(), "{after:?}");
    // Idempotent.
    authn_store::run_migrations(&pool).await.unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn ops_10_architect_migrations_use_reserved_range(pool: PgPool) {
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(versions.iter().all(|v| *v >= 1), "{versions:?}");
    assert!(versions.contains(&1));
}

#[sqlx::test(migrations = "../../migrations")]
async fn arc_10_custom_role_of_another_org_cannot_be_assigned(pool: PgPool) {
    seed_user_and_orgs(&pool).await;
    exec(
        &pool,
        &format!("INSERT INTO roles (id, org_id, key, name) VALUES ('01900000-0000-7000-8000-0000000000c1', '{ORG_A}', 'custom', 'Custom')"),
    )
    .await
    .unwrap();
    let err = exec(
        &pool,
        &format!(
            "INSERT INTO memberships (id, org_id, user_id, role_id) VALUES \
             ('01900000-0000-7000-8000-0000000000d1', '{ORG_B}', '{USER_A}', '01900000-0000-7000-8000-0000000000c1')"
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, StoreError::CheckViolation { ref constraint } if constraint == "role_tenant_check"),
        "{err:?}"
    );
    // Built-in roles are usable in every organization; same-org custom roles too.
    exec(
        &pool,
        &format!(
            "INSERT INTO memberships (id, org_id, user_id, role_id) VALUES \
             ('01900000-0000-7000-8000-0000000000d2', '{ORG_B}', '{USER_A}', '01900000-0000-7000-8000-000000000003'),
             ('01900000-0000-7000-8000-0000000000d3', '{ORG_A}', '{USER_A}', '01900000-0000-7000-8000-0000000000c1')"
        ),
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn arc_10_api_key_service_account_must_belong_to_same_org(pool: PgPool) {
    seed_user_and_orgs(&pool).await;
    exec(
        &pool,
        &format!(
            "INSERT INTO service_accounts (id, org_id, name, role_id) VALUES \
             ('01900000-0000-7000-8000-0000000000e1', '{ORG_A}', 'ci', '01900000-0000-7000-8000-000000000003')"
        ),
    )
    .await
    .unwrap();
    let err = exec(
        &pool,
        &format!(
            "INSERT INTO api_keys (id, org_id, service_account_id, name, environment, display_prefix, secret_hash, expires_at) VALUES \
             ('01900000-0000-7000-8000-0000000000f1', '{ORG_B}', '01900000-0000-7000-8000-0000000000e1', 'k', 'live', 'ak_live_abcd', \
              decode(repeat('ab', 32), 'hex'), now() + interval '1 day')"
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, StoreError::ForeignKeyViolation { .. }),
        "{err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn aud_02_audit_events_are_append_only(pool: PgPool) {
    exec(
        &pool,
        "INSERT INTO audit_events (id, occurred_at, kind, outcome, actor_type, prev_hash, hash) VALUES \
         ('01900000-0000-7000-8000-0000000000a1', now() - interval '500 days', 'login.failed', 'failure', 'anonymous', \
          decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'))",
    )
    .await
    .unwrap();
    for sql in [
        "UPDATE audit_events SET kind = 'logout'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events CASCADE",
    ] {
        let err = exec(&pool, sql).await.unwrap_err();
        assert!(matches!(err, StoreError::NotPermitted(_)), "{sql}: {err:?}");
    }
    // Retention purge escape hatch only removes rows older than the cutoff.
    exec(
        &pool,
        "BEGIN; SET LOCAL authn.audit_purge_before = '2000-01-01T00:00:00Z'; DELETE FROM audit_events; COMMIT;",
    )
    .await
    .unwrap_err();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('authn.audit_purge_before', (now() - interval '400 days')::text, true)",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let deleted =
        sqlx::query("DELETE FROM audit_events WHERE occurred_at < now() - interval '400 days'")
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected();
    tx.commit().await.unwrap();
    assert_eq!(deleted, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn aud_02_chain_head_is_a_singleton_with_genesis_hash(pool: PgPool) {
    let (seq, hash): (i64, Vec<u8>) =
        sqlx::query_as("SELECT last_seq, last_hash FROM audit_chain_head")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(seq, 0);
    assert_eq!(hash, vec![0_u8; 32]);
    let err = exec(&pool, "INSERT INTO audit_chain_head (id) VALUES (false)")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::CheckViolation { .. }), "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn ses_05_only_one_live_refresh_token_per_family(pool: PgPool) {
    seed_user_and_orgs(&pool).await;
    exec(
        &pool,
        &format!(
            "INSERT INTO sessions (id, user_id, client_kind, amr, auth_time, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES \
             ('01900000-0000-7000-8000-000000000101', '{USER_A}', 'native', ARRAY['pwd'], now(), now(), now(), now() + interval '1 day', now() + interval '2 days');
             INSERT INTO refresh_tokens (id, session_id, token_hash, generation, created_at, idle_expires_at, absolute_expires_at) VALUES \
             ('01900000-0000-7000-8000-000000000201', '01900000-0000-7000-8000-000000000101', decode(repeat('01', 32), 'hex'), 0, now(), now() + interval '1 day', now() + interval '2 days');"
        ),
    )
    .await
    .unwrap();
    let err = exec(
        &pool,
        "INSERT INTO refresh_tokens (id, session_id, token_hash, generation, created_at, idle_expires_at, absolute_expires_at) VALUES \
         ('01900000-0000-7000-8000-000000000202', '01900000-0000-7000-8000-000000000101', decode(repeat('02', 32), 'hex'), 1, now(), now() + interval '1 day', now() + interval '2 days')",
    )
    .await
    .unwrap_err();
    assert!(
        err.is_unique_violation("refresh_tokens_one_live_per_family_idx"),
        "{err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cry_10_at_most_one_active_signing_key(pool: PgPool) {
    let insert = |id: &str| {
        format!(
            "INSERT INTO signing_keys (id, status, public_key, private_key_ciphertext, created_at, activate_after, activated_at) VALUES \
             ('{id}', 'active', decode(repeat('aa', 32), 'hex'), decode(repeat('bb', 64), 'hex'), now(), now(), now())"
        )
    };
    exec(&pool, &insert("01900000-0000-7000-8000-000000000301"))
        .await
        .unwrap();
    let err = exec(&pool, &insert("01900000-0000-7000-8000-000000000302"))
        .await
        .unwrap_err();
    assert!(
        err.is_unique_violation("signing_keys_single_active_idx"),
        "{err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn arc_06_link_token_hashes_are_unique_but_codes_may_collide(pool: PgPool) {
    seed_user_and_orgs(&pool).await;
    let insert = |id: &str, kind: &str| {
        format!(
            "INSERT INTO one_time_tokens (id, purpose, kind, token_hash, user_id, created_at, expires_at) VALUES \
             ('{id}', 'password_reset', '{kind}', decode(repeat('cd', 32), 'hex'), '{USER_A}', now(), now() + interval '30 minutes')"
        )
    };
    exec(
        &pool,
        &insert("01900000-0000-7000-8000-000000000401", "code"),
    )
    .await
    .unwrap();
    exec(
        &pool,
        &insert("01900000-0000-7000-8000-000000000402", "code"),
    )
    .await
    .unwrap();
    exec(
        &pool,
        &insert("01900000-0000-7000-8000-000000000403", "link"),
    )
    .await
    .unwrap();
    let err = exec(
        &pool,
        &insert("01900000-0000-7000-8000-000000000404", "link"),
    )
    .await
    .unwrap_err();
    assert!(
        err.is_unique_violation("one_time_tokens_link_hash_idx"),
        "{err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn aud_05_deleting_a_user_unlinks_audit_pseudonym_and_pii(pool: PgPool) {
    seed_user_and_orgs(&pool).await;
    exec(
        &pool,
        &format!(
            "INSERT INTO audit_subjects (pseudonym, user_id) VALUES ('01900000-0000-7000-8000-000000000501', '{USER_A}');
             INSERT INTO audit_events (id, occurred_at, kind, outcome, actor_type, actor_pseudonym, prev_hash, hash) VALUES \
             ('01900000-0000-7000-8000-000000000502', now(), 'login.succeeded', 'success', 'user', '01900000-0000-7000-8000-000000000501', \
              decode(repeat('00', 32), 'hex'), decode(repeat('22', 32), 'hex'));
             INSERT INTO audit_event_pii (event_id, pseudonym, ip, user_agent, salt) VALUES \
             ('01900000-0000-7000-8000-000000000502', '01900000-0000-7000-8000-000000000501', '203.0.113.5', 'UA', decode(repeat('33', 16), 'hex'));"
        ),
    )
    .await
    .unwrap();
    exec(&pool, &format!("DELETE FROM users WHERE id = '{USER_A}'"))
        .await
        .unwrap();
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM audit_events), (SELECT count(*) FROM audit_subjects), (SELECT count(*) FROM audit_event_pii)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counts, (1, 0, 0));
}
