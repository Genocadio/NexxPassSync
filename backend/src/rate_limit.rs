use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::error::AppError;

#[derive(Clone, Default)]
pub struct RateLimiter {
    entries: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Checks if a request for `key` is allowed given `max_requests` within `window`.
    /// If allowed, records the request and returns Ok(()).
    /// If exceeded, returns Err(AppError::RateLimited { retry_after_s }).
    pub fn check_rate_limit(
        &self,
        key: &str,
        max_requests: usize,
        window: Duration,
    ) -> Result<(), AppError> {
        let now = Instant::now();
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        let timestamps = map.entry(key.to_string()).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= max_requests {
            let earliest = timestamps[0];
            let elapsed = now.duration_since(earliest);
            let remaining = window.saturating_sub(elapsed).as_secs() + 1;
            return Err(AppError::RateLimited {
                retry_after_s: remaining as u32,
            });
        }

        timestamps.push(now);

        // Prune empty keys if map grows large
        if map.len() > 10_000 {
            map.retain(|_, v| {
                v.retain(|t| now.duration_since(*t) < window);
                !v.is_empty()
            });
        }

        Ok(())
    }
}
