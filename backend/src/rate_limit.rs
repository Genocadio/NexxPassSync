use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::error::AppError;

const PRUNE_THRESHOLD: usize = 10_000;
const MAX_TRACKED_KEYS: usize = 50_000;
const MIN_PRUNE_INTERVAL: Duration = Duration::from_secs(30);

struct RateLimiterInner {
    entries: HashMap<String, Vec<Instant>>,
    last_pruned: Instant,
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterInner>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner {
                entries: HashMap::new(),
                last_pruned: Instant::now(),
            })),
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
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Periodically prune expired entries at most once per MIN_PRUNE_INTERVAL
        if guard.entries.len() > PRUNE_THRESHOLD
            && now.duration_since(guard.last_pruned) >= MIN_PRUNE_INTERVAL
        {
            guard.entries.retain(|_, v| {
                v.retain(|t| now.duration_since(*t) < window);
                !v.is_empty()
            });
            guard.last_pruned = now;
        }

        // Hard memory cap against random-key floods
        if !guard.entries.contains_key(key) && guard.entries.len() >= MAX_TRACKED_KEYS {
            return Err(AppError::RateLimited { retry_after_s: 30 });
        }

        let timestamps = guard.entries.entry(key.to_string()).or_default();
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_enforces_window_and_recovers() {
        let limiter = RateLimiter::new();
        let window = Duration::from_millis(50);

        assert!(limiter.check_rate_limit("k1", 2, window).is_ok());
        assert!(limiter.check_rate_limit("k1", 2, window).is_ok());
        assert!(limiter.check_rate_limit("k1", 2, window).is_err());

        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check_rate_limit("k1", 2, window).is_ok());
    }
}
