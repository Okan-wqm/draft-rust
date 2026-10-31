//! Transaction helper behaviour (ARC-06).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use authn_core::error::{AuthError, codes};
use authn_store::{begin, begin_serializable, commit, with_tx};
use sqlx::PgPool;

async fn count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM terms_versions")
        .fetch_one(pool)
        .await
        .unwrap()
}

const INSERT: &str = "INSERT INTO terms_versions (id, document, version, published_at) \
                      VALUES ($1, 'terms_of_service', $2, now())";

#[sqlx::test(migrations = "../../migrations")]
async fn arc_06_with_tx_commits_on_ok_and_rolls_back_on_err(pool: PgPool) {
    with_tx(&pool, |conn| {
        Box::pin(async move {
            sqlx::query(INSERT)
                .bind(uuid::Uuid::now_v7())
                .bind("v1")
                .execute(conn)
                .await?;
            Ok::<_, AuthError>(())
        })
    })
    .await
    .unwrap();
    assert_eq!(count(&pool).await, 1);

    let err = with_tx(&pool, |conn| {
        Box::pin(async move {
            sqlx::query(INSERT)
                .bind(uuid::Uuid::now_v7())
                .bind("v2")
                .execute(conn)
                .await?;
            Err::<(), _>(AuthError::new(codes::common::CONFLICT))
        })
    })
    .await
    .unwrap_err();
    assert!(err.is(codes::common::CONFLICT));
    assert_eq!(count(&pool).await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn arc_06_begin_and_commit(pool: PgPool) {
    let mut tx = begin_serializable(&pool).await.unwrap();
    let level: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(level, "serializable");
    sqlx::query(INSERT)
        .bind(uuid::Uuid::now_v7())
        .bind("v3")
        .execute(&mut *tx)
        .await
        .unwrap();
    commit(tx).await.unwrap();
    let tx = begin(&pool).await.unwrap();
    drop(tx); // implicit rollback
    assert_eq!(count(&pool).await, 1);
}
