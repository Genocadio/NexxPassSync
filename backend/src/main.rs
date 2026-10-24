use nexxpass_sync_server::{config::Config, http, state::AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing()?;
    let config = Config::from_env()?;
    let state = AppState::connect(&config).await?;
    state.migrate().await?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let maintenance_state = state.clone();
    let maintenance_interval = std::time::Duration::from_secs(config.maintenance_interval_seconds);

    let maintenance_handle = tokio::spawn(async move {
        let mut interval_timer = tokio::time::interval(maintenance_interval);
        interval_timer.tick().await;

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    tracing::info!("running scheduled background maintenance");
                    if let Err(e) = nexxpass_sync_server::maintenance::run_maintenance(&maintenance_state.database).await {
                        tracing::error!(error = %e, "background maintenance execution failed");
                    }
                }
                _ = shutdown_rx.changed() => {
                    tracing::info!("stopping background maintenance task");
                    break;
                }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!(address = %config.bind_addr, "NexxPass Sync service started");
    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    let _ = shutdown_tx.send(true);
    let _ = maintenance_handle.await;

    Ok(())
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init()?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for Ctrl+C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                let _ = signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to listen for SIGTERM"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
