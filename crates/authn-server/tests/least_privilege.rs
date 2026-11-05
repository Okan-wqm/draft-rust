#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OPS-10 / K-42: the least-privilege roles of migration 2900
//! (`authn_apply_least_privilege`) — the exact grants, and the whole
//! application running as the restricted application role with audit
//! maintenance on the separate maintenance-role pool.

mod common;

use std::time::Duration;

use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::{App, PASSWORD};
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

struct Roles {
    app: String,
    maintenance: String,
    password: String,
}

/// Two fresh login roles (cluster-wide; dropped by [`drop_roles`]).
async fn create_roles(pool: &PgPool) -> Roles {
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let roles = Roles {
        app: format!("authn_test_app_{suffix}"),
        maintenance: format!("authn_test_maint_{suffix}"),
        password: format!("pw-{suffix}"),
    };
    for role in [&roles.app, &roles.maintenance] {
        // Identifiers cannot be bound; the names are generated above.
        let sql = format!("CREATE ROLE {role} LOGIN PASSWORD '{}'", roles.password);
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
            .execute(pool)
            .await
            .unwrap();
    }
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .unwrap();
    let sql = format!(
        "GRANT CONNECT ON DATABASE \"{db}\" TO {}, {}",
        roles.app, roles.maintenance
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("SELECT authn_apply_least_privilege($1, $2)")
        .bind(&roles.app)
        .bind(&roles.maintenance)
        .execute(pool)
        .await
        .unwrap();
    roles
}

async fn drop_roles(pool: &PgPool, roles: &Roles) {
    for role in [&roles.app, &roles.maintenance] {
        let sql = format!("DROP OWNED BY {role}; DROP ROLE {role}");
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(sql)).execute(pool).await;
    }
}

async fn pool_as(pool: &PgPool, role: &str, password: &str) -> PgPool {
    let options: PgConnectOptions = (*pool.connect_options())
        .clone()
        .username(role)
        .password(password);
    PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap()
}

async fn privilege(pool: &PgPool, role: &str, table: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
        .bind(role)
        .bind(table)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_10_least_privilege_grants_are_exact(pool: PgPool) {
    let roles = create_roles(&pool).await;
    let (app, maint) = (roles.app.as_str(), roles.maintenance.as_str());

    // Append-only: no UPDATE / DELETE / TRUNCATE for the application role.
    for table in [
        "audit_events",
        "admin_action_reasons",
        "admin_reason_restrictions",
    ] {
        assert!(privilege(&pool, app, table, "SELECT").await, "{table}");
        assert!(privilege(&pool, app, table, "INSERT").await, "{table}");
        for denied in ["UPDATE", "DELETE", "TRUNCATE"] {
            assert!(
                !privilege(&pool, app, table, denied).await,
                "{table} {denied}"
            );
        }
    }
    // Wave 3B (K-62, K-66): append-only restriction periods, approvals
    // without DELETE.
    let periods = "admin_reason_restriction_periods";
    assert!(privilege(&pool, app, periods, "INSERT").await);
    for denied in ["UPDATE", "DELETE", "TRUNCATE"] {
        assert!(
            !privilege(&pool, app, periods, denied).await,
            "{periods} {denied}"
        );
    }
    for granted in ["SELECT", "INSERT", "UPDATE"] {
        assert!(
            privilege(&pool, app, "admin_approvals", granted).await,
            "{granted}"
        );
    }
    assert!(!privilege(&pool, app, "admin_approvals", "DELETE").await);
    assert!(privilege(&pool, app, "audit_subject_view_holds", "INSERT").await);
    assert!(!privilege(&pool, app, "audit_subject_view_holds", "UPDATE").await);

    // Ordinary module tables, including the wave 2 ones.
    for table in [
        "users",
        "sessions",
        "identities",
        "oauth_states",
        "oauth_token_revocations",
        "admin_passkey_enrollments",
        "admin_operation_leases",
        "pending_registrations",
    ] {
        for granted in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            assert!(
                privilege(&pool, app, table, granted).await,
                "{table} {granted}"
            );
        }
        for denied in ["TRUNCATE", "REFERENCES", "TRIGGER"] {
            assert!(
                !privilege(&pool, app, table, denied).await,
                "{table} {denied}"
            );
        }
        assert!(!privilege(&pool, maint, table, "SELECT").await, "{table}");
    }
    // The schema version is readable, not writable.
    assert!(privilege(&pool, app, "_sqlx_migrations", "SELECT").await);
    assert!(!privilege(&pool, app, "_sqlx_migrations", "INSERT").await);
    // The maintenance role purges audit events, nothing else of the users'.
    assert!(privilege(&pool, maint, "audit_events", "DELETE").await);
    assert!(!privilege(&pool, maint, "audit_events", "UPDATE").await);
    assert!(!privilege(&pool, maint, "users", "DELETE").await);

    // Every table of the schema is covered (nothing left with no grant
    // for the application role except the audit-owned tables it reaches
    // through 1700).
    let uncovered: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') \
         AND NOT has_table_privilege($1, c.oid, 'SELECT')",
    )
    .bind(app)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(uncovered.is_empty(), "tables without grants: {uncovered:?}");

    // Same role twice, or an owner role, is refused.
    let err = sqlx::query("SELECT authn_apply_least_privilege($1, $1)")
        .bind(app)
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("must differ"), "{err}");
    drop_roles(&pool, &roles).await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_10_the_application_runs_as_the_restricted_role(pool: PgPool) {
    let roles = create_roles(&pool).await;
    let app_pool = pool_as(&pool, &roles.app, &roles.password).await;
    let maintenance_pool = pool_as(&pool, &roles.maintenance, &roles.password).await;
    {
        let app = App::new(app_pool.clone()).await;
        // Login, a session, MFA-free flows and the audit trail as the app role.
        app.user("alice@example.com").await;
        let mut browser = app.browser();
        let body = browser.login(&app, "alice@example.com", PASSWORD).await;
        assert_eq!(body["status"], "authenticated", "{body}");
        assert_eq!(app.send(browser.get("/v1/me")).await.status, StatusCode::OK);
        let r = app.send(TestRequest::get("/health/ready")).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        // The application role can neither rewrite nor delete history.
        let err = sqlx::query("DELETE FROM audit_events")
            .execute(&app_pool)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("permission denied"), "{err}");
        // Cleanups of module tables work as the app role.
        let totals = authn_server::jobs::run_maintenance_once(&app.services).await;
        assert_eq!(totals.failed, 0, "{totals:?}");
        // Wave 3A audit: the write paths that touch the append-only and
        // audit tables also work as the app role — an offline admin action
        // (justification row, K-07) and a full account erasure (ACC-09:
        // cascades, audit pseudonymisation, erasure hooks).
        let root = app.user("root@example.com").await;
        sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
            .bind(root)
            .execute(&pool)
            .await
            .unwrap();
        let outcome = app
            .services
            .admin
            .suspend_admin_offline(
                &authn_admin::OfflineOperator::parse("oncall").unwrap(),
                &authn_admin::OfflineTarget::Id(root),
                &authn_admin::Justification::parse(Some("least privilege drill")).unwrap(),
            )
            .await
            .unwrap();
        assert!(outcome.changed);
        browser.csrf(&app).await;
        let r = browser.send(&app, browser.delete("/v1/me")).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.text());
        app.advance(Duration::from_secs(60 * 24 * 3600));
        let purged = app.services.accounts.purge_due_deletions(10).await.unwrap();
        assert_eq!(purged.purged, 1, "{purged:?}");
        // Audit retention runs on the maintenance pool (OPS-10).
        app.advance(Duration::from_secs(5 * 365 * 24 * 3600));
        app.services
            .audit
            .run_maintenance(&maintenance_pool)
            .await
            .unwrap();
        let _ = json!({});
    }
    app_pool.close().await;
    maintenance_pool.close().await;
    drop_roles(&pool, &roles).await;
}

async fn exec(pool: &PgPool, sql: String) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(pool)
        .await
        .unwrap();
}

async fn apply(pool: &PgPool, app: &str, maintenance: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT authn_apply_least_privilege($1, $2)")
        .bind(app)
        .bind(maintenance)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Wave 3A audit: a restricted role that is a *member* of a table owner
/// (or of the other restricted role, or a superuser) inherits privileges
/// no grant can take away; the helper must refuse such a set-up instead
/// of reporting success.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_10_roles_inheriting_owner_or_peer_privileges_are_refused(pool: PgPool) {
    let roles = create_roles(&pool).await;
    let (app, maint) = (roles.app.clone(), roles.maintenance.clone());
    let owner = format!("{app}_owner");

    // 1. The application role is a member of a role that owns a table.
    exec(&pool, format!("CREATE ROLE {owner} NOLOGIN")).await;
    exec(
        &pool,
        format!(
            "CREATE TABLE lp_probe_{owner} (id int); ALTER TABLE lp_probe_{owner} OWNER TO {owner}"
        ),
    )
    .await;
    exec(&pool, format!("GRANT {owner} TO {app}")).await;
    let err = apply(&pool, &app, &maint).await.unwrap_err();
    assert!(err.to_string().contains("member"), "{err}");
    exec(&pool, format!("REVOKE {owner} FROM {app}")).await;
    // The maintenance role likewise.
    exec(&pool, format!("GRANT {owner} TO {maint}")).await;
    assert!(apply(&pool, &app, &maint).await.is_err());
    exec(&pool, format!("REVOKE {owner} FROM {maint}")).await;
    exec(
        &pool,
        format!("DROP TABLE lp_probe_{owner}; DROP ROLE {owner}"),
    )
    .await;

    // 2. The application role is a member of the maintenance role (it
    //    would inherit DELETE on audit_events), or the other way round.
    exec(&pool, format!("GRANT {maint} TO {app}")).await;
    let err = apply(&pool, &app, &maint).await.unwrap_err();
    assert!(err.to_string().contains("member"), "{err}");
    exec(&pool, format!("REVOKE {maint} FROM {app}")).await;
    exec(&pool, format!("GRANT {app} TO {maint}")).await;
    assert!(apply(&pool, &app, &maint).await.is_err());
    exec(&pool, format!("REVOKE {app} FROM {maint}")).await;

    // 3. A superuser (or BYPASSRLS) role ignores every grant.
    exec(&pool, format!("ALTER ROLE {app} SUPERUSER")).await;
    let err = apply(&pool, &app, &maint).await.unwrap_err();
    assert!(err.to_string().contains("superuser"), "{err}");
    exec(&pool, format!("ALTER ROLE {app} NOSUPERUSER")).await;

    // A clean set-up still applies.
    apply(&pool, &app, &maint).await.unwrap();
    drop_roles(&pool, &roles).await;
}

/// Wave 3A audit: the helper runs with the schema owner's rights, so it
/// must not resolve anything through the caller's `search_path` (an
/// object planted in an earlier schema would run as the owner).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_10_least_privilege_helper_ignores_the_callers_search_path(pool: PgPool) {
    let roles = create_roles(&pool).await;
    exec(
        &pool,
        "CREATE SCHEMA lp_planted; \
         CREATE FUNCTION lp_planted.authn_audit_apply_least_privilege(a name, b name) \
         RETURNS void LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'planted function ran'; END $$"
            .to_owned(),
    )
    .await;
    let schema: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    exec_conn(&mut conn, format!("SET search_path = lp_planted, {schema}")).await;
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {schema}.authn_apply_least_privilege($1, $2)"
    )))
    .bind(&roles.app)
    .bind(&roles.maintenance)
    .execute(&mut *conn)
    .await;
    exec_conn(&mut conn, "RESET search_path".to_owned()).await;
    drop(conn);
    result.unwrap();
    // The real grants were applied to this schema's tables.
    assert!(!privilege(&pool, &roles.app, "audit_events", "DELETE").await);
    assert!(privilege(&pool, &roles.app, "users", "UPDATE").await);
    drop_roles(&pool, &roles).await;
}

async fn exec_conn(conn: &mut sqlx::PgConnection, sql: String) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(conn)
        .await
        .unwrap();
}
