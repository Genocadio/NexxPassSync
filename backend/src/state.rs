use std::sync::{
    atomic::{AtomicI64, AtomicU64},
    Arc,
};

use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::broadcast;

use crate::{config::Config, rate_limit::RateLimiter, replay::ReplayFilter};

#[derive(Debug)]
pub struct Metrics {
    pub start_time: std::time::Instant,
    pub total_requests: AtomicU64,
    pub error_requests: AtomicU64,
    pub active_sse_connections: AtomicI64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            total_requests: AtomicU64::new(0),
            error_requests: AtomicU64::new(0),
            active_sse_connections: AtomicI64::new(0),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SyncNotification {
    pub account_id: Vec<u8>,
    pub seq: Option<i64>,
    pub revoked_device_id: Option<uuid::Uuid>,
    pub revoked_reason: Option<String>,
    pub revocation_proof: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub database: PgPool,
    pub token_hmac_key: [u8; 32],
    pub deployment_epoch: u64,
    pub rate_limiter: RateLimiter,
    pub replay_filter: Arc<ReplayFilter>,
    pub sync_notifier: broadcast::Sender<SyncNotification>,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    pub async fn connect(config: &Config) -> Result<Self, sqlx::Error> {
        let database = PgPoolOptions::new()
            .max_connections(config.database_max_connections)
            .min_connections(std::cmp::min(2, config.database_max_connections))
            .acquire_timeout(std::time::Duration::from_secs(5))
            .idle_timeout(std::time::Duration::from_secs(600))
            .max_lifetime(std::time::Duration::from_secs(1800))
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("SET statement_timeout = '10s'")
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&config.database_url)
            .await?;
        let (sync_notifier, _) = broadcast::channel(2048);
        Ok(Self {
            database,
            token_hmac_key: config.token_hmac_key,
            deployment_epoch: config.deployment_epoch,
            rate_limiter: RateLimiter::new(),
            replay_filter: Arc::new(ReplayFilter::new()),
            sync_notifier,
            metrics: Arc::new(Metrics::default()),
        })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.database).await
    }
}
