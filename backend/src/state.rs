use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub database: PgPool,
}

impl AppState {
    pub async fn connect(config: &Config) -> Result<Self, sqlx::Error> {
        let database = PgPoolOptions::new()
            .max_connections(config.database_max_connections)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&config.database_url)
            .await?;
        Ok(Self { database })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.database).await
    }
}
