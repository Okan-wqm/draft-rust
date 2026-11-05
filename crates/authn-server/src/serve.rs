//! `serve`: HTTP server with graceful shutdown (OPS-07).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::ports::{Clock, SystemClock};
use tokio::net::TcpListener;
use tokio::sync::Notify;

use tokio_util::sync::CancellationToken;

use crate::app::build_router;
use crate::error::ServerError;
use crate::jobs;
use crate::services::{Ports, Services};
use crate::state::AppState;

/// Runs the server until SIGINT / SIGTERM, then drains in-flight requests
/// for at most `server.shutdown_grace_period`.
pub async fn serve(config: AppConfig) -> Result<(), ServerError> {
    let config = Arc::new(config);
    let pool = authn_store::connect(&config.database).await?;

    if config.database.migrate_on_start {
        authn_store::run_migrations(&pool).await?;
    }
    let status = authn_store::migration_status(&pool).await?;
    if !status.is_up_to_date() {
        return Err(ServerError::SchemaOutdated(format!("{status:?}")));
    }

    if let Some(addr) = config.server.metrics_bind_addr {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(addr)
            .install()
            .map_err(|e| ServerError::Telemetry(e.to_string()))?;
        tracing::info!(%addr, "metrics listener started");
    }

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let ports = Ports::from_config(&config, clock).map_err(ServerError::Startup)?;
    // OPS-10: audit retention runs with the maintenance role when one is
    // configured (the application role then needs no DELETE on audit_events).
    let maintenance_pool = match config.database.maintenance() {
        Some(maintenance) => authn_store::connect(&maintenance).await?,
        None => {
            tracing::warn!(
                "database.maintenance_url is not set; audit maintenance uses the application role"
            );
            pool.clone()
        }
    };
    let services =
        Services::build_with_maintenance_pool(config.clone(), pool, maintenance_pool, ports)
            .await
            .map_err(ServerError::Startup)?;
    // CRY-10: a signing key must exist before the first token is issued.
    jobs::rotate_signing_keys(&services)
        .await
        .map_err(ServerError::Startup)?;
    services
        .accounts
        .sync_terms_versions()
        .await
        .map_err(ServerError::Startup)?;
    let shutdown_jobs = CancellationToken::new();
    let mut background =
        jobs::spawn(services.clone(), shutdown_jobs.clone()).map_err(ServerError::Startup)?;
    let state = AppState::new(services.clone());
    let router = build_router(state).map_err(ServerError::Startup)?;

    let listener = TcpListener::bind(config.server.bind_addr).await?;
    tracing::info!(addr = %config.server.bind_addr, "listening");

    let shutdown_started = Arc::new(Notify::new());
    let notify = shutdown_started.clone();
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received; draining requests");
        notify.notify_one();
    });

    let grace = config.server.shutdown_grace_period;
    tokio::select! {
        result = server => result?,
        () = deadline(shutdown_started, grace) => {
            tracing::warn!(grace_secs = grace.as_secs(), "grace period elapsed; aborting in-flight requests");
        }
    }
    // OPS-07: stop the jobs, finish queued work.
    shutdown_jobs.cancel();
    while background.join_next().await.is_some() {}
    services.passwords.drain_background_jobs().await;
    services.accounts.drain_background_jobs().await;
    services.sessions.drain_background_jobs().await;
    tracing::info!("server stopped");
    Ok(())
}

async fn deadline(started: Arc<Notify>, grace: Duration) {
    started.notified().await;
    tokio::time::sleep(grace).await;
}

/// Resolves on Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "cannot listen for ctrl-c");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
