//! Transaction helpers (ARC-06: every state change runs in a transaction).

use authn_core::error::AuthError;
use futures::future::BoxFuture;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

/// A PostgreSQL transaction borrowed from the pool.
pub type PgTx = Transaction<'static, Postgres>;

/// Begins a `READ COMMITTED` transaction.
pub async fn begin(pool: &PgPool) -> Result<PgTx, AuthError> {
    Ok(pool.begin().await?)
}

/// Begins a `SERIALIZABLE` transaction — for invariants that span rows
/// (e.g. "an organization keeps at least one owner"). Retry on
/// [`StoreError::Retryable`](crate::StoreError::Retryable).
pub async fn begin_serializable(pool: &PgPool) -> Result<PgTx, AuthError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Commits a transaction.
pub async fn commit(tx: PgTx) -> Result<(), AuthError> {
    Ok(tx.commit().await?)
}

/// Runs `f` inside a transaction: commit on `Ok`, rollback on `Err`.
///
/// The closure receives the connection and returns a boxed future; move
/// owned values into it:
///
/// ```ignore
/// let user = with_tx(&pool, move |conn| Box::pin(async move {
///     UserRepository::create(conn, &new_user).await.map_err(AuthError::from)
/// })).await?;
/// ```
pub async fn with_tx<T, F>(pool: &PgPool, f: F) -> Result<T, AuthError>
where
    T: Send,
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, AuthError>> + Send,
{
    let mut tx = pool.begin().await?;
    match f(&mut tx).await {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(err) => {
            if let Err(rollback_err) = tx.rollback().await {
                tracing::warn!(error = %rollback_err, "transaction rollback failed");
            }
            Err(err)
        }
    }
}
