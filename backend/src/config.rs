use std::{env, net::SocketAddr};

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub token_hmac_key: [u8; 32],
    pub deployment_epoch: u64,
    pub maintenance_interval_seconds: u64,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("DATABASE_URL is required")]
    MissingDatabaseUrl,
    #[error("SYNC_BIND_ADDR must be a valid socket address")]
    InvalidBindAddress,
    #[error("SYNC_DATABASE_MAX_CONNECTIONS must be a positive integer")]
    InvalidPoolSize,
    #[error("SYNC_TOKEN_KEY_HEX is required in production and must be a 64-character hex string")]
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

        let is_production = env::var("SYNC_ENV")
            .map(|v| v.eq_ignore_ascii_case("production") || v.eq_ignore_ascii_case("prod"))
            .unwrap_or(false);

        let token_hex = match env::var("SYNC_TOKEN_KEY_HEX") {
            Ok(val) => {
                if is_production && val.eq_ignore_ascii_case(DEFAULT_TOKEN_KEY_HEX) {
                    return Err(ConfigError::InvalidTokenKey);
                }
                val
            }
            Err(_) => {
                if is_production {
                    return Err(ConfigError::InvalidTokenKey);
                }
                tracing::warn!(
                    "SYNC_TOKEN_KEY_HEX is not set; using development fallback key. Set SYNC_TOKEN_KEY_HEX in production!"
                );
                DEFAULT_TOKEN_KEY_HEX.to_owned()
            }
        };
        let token_hmac_key = parse_token_key_hex(&token_hex, is_production)?;

        let deployment_epoch = env::var("SYNC_DEPLOYMENT_EPOCH")
            .unwrap_or_else(|_| "1".to_owned())
            .parse::<u64>()
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or(ConfigError::InvalidDeploymentEpoch)?;

        let maintenance_interval_seconds = env::var("SYNC_MAINTENANCE_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "3600".to_owned())
            .parse::<u64>()
            .unwrap_or(3600);

        Ok(Self {
            bind_addr,
            database_url,
            database_max_connections,
            token_hmac_key,
            deployment_epoch,
            maintenance_interval_seconds,
        })
    }
}

pub fn parse_token_key_hex(token_hex: &str, reject_trivial: bool) -> Result<[u8; 32], ConfigError> {
    if token_hex.len() != 64 {
        return Err(ConfigError::InvalidTokenKey);
    }
    let mut token_hmac_key = [0u8; 32];
    for i in 0..32 {
        token_hmac_key[i] = u8::from_str_radix(&token_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ConfigError::InvalidTokenKey)?;
    }
    if reject_trivial {
        let first = token_hmac_key[0];
        if token_hmac_key.iter().all(|&b| b == first) {
            return Err(ConfigError::InvalidTokenKey);
        }
    }
    Ok(token_hmac_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_token_key_hex_rejects_trivial_keys_in_prod() {
        let valid = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00";
        assert!(parse_token_key_hex(valid, true).is_ok());

        let all_zeros = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(parse_token_key_hex(all_zeros, true).is_err());
        assert!(parse_token_key_hex(all_zeros, false).is_ok());

        assert!(parse_token_key_hex("short", false).is_err());
    }
}
