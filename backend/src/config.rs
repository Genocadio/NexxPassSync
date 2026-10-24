use std::{env, net::SocketAddr};

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub token_hmac_key: [u8; 32],
    pub deployment_epoch: u64,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("DATABASE_URL is required")]
    MissingDatabaseUrl,
    #[error("SYNC_BIND_ADDR must be a valid socket address")]
    InvalidBindAddress,
    #[error("SYNC_DATABASE_MAX_CONNECTIONS must be a positive integer")]
    InvalidPoolSize,
    #[error("SYNC_TOKEN_KEY_HEX must be a 64-character hex string")]
    InvalidTokenKey,
    #[error("SYNC_DEPLOYMENT_EPOCH must be a positive integer")]
    InvalidDeploymentEpoch,
}

const DEFAULT_TOKEN_KEY_HEX: &str =
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

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

        let token_hex =
            env::var("SYNC_TOKEN_KEY_HEX").unwrap_or_else(|_| DEFAULT_TOKEN_KEY_HEX.to_owned());
        if token_hex.len() != 64 {
            return Err(ConfigError::InvalidTokenKey);
        }
        let mut token_hmac_key = [0u8; 32];
        for i in 0..32 {
            token_hmac_key[i] = u8::from_str_radix(&token_hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| ConfigError::InvalidTokenKey)?;
        }

        let deployment_epoch = env::var("SYNC_DEPLOYMENT_EPOCH")
            .unwrap_or_else(|_| "1".to_owned())
            .parse::<u64>()
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or(ConfigError::InvalidDeploymentEpoch)?;

        Ok(Self {
            bind_addr,
            database_url,
            database_max_connections,
            token_hmac_key,
            deployment_epoch,
        })
    }
}
