use std::sync::Arc;

use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::broadcast;

use crate::{config::Config, rate_limit::RateLimiter, replay::ReplayFilter};

#[derive(Clone, Debug)]
pub struct SyncNotification {
    pub account_id: Vec<u8>,
    pub seq: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub database: PgPool,
    pub token_hmac_key: [u8; 32],
    pub deployment_epoch: u64,
    pub rate_limiter: RateLimiter,
    pub replay_filter: Arc<ReplayFilter>,
    pub sync_notifier: broadcast::Sender<SyncNotification>,
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
        })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.database).await
    }
}
