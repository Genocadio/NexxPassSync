use std::{env, net::SocketAddr};

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("DATABASE_URL is required")]
    MissingDatabaseUrl,
    #[error("SYNC_BIND_ADDR must be a valid socket address")]
    InvalidBindAddress,
    #[error("SYNC_DATABASE_MAX_CONNECTIONS must be a positive integer")]
    InvalidPoolSize,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = env::var("DATABASE_URL").map_err(|_| ConfigError::MissingDatabaseUrl)?;
        let bind_addr = env::var("SYNC_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
            .parse()
            .map_err(|_| ConfigError::InvalidBindAddress)?;
        let database_max_connections = env::var("SYNC_DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_owned())
            .parse::<u32>()
            .ok()
            .filter(|count| *count > 0)
            .ok_or(ConfigError::InvalidPoolSize)?;

        Ok(Self {
            bind_addr,
            database_url,
            database_max_connections,
        })
    }
}
