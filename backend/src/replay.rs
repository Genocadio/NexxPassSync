use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, Instant},
};

const MAX_GENERATION_ENTRIES: usize = 250_000;

/// High-throughput in-memory replay filter with sliding two-generation rotation.
/// Retains nonces across two 300-second windows (up to 600 seconds total),
/// providing instantaneous O(1) in-memory rejection of replayed nonces.
#[derive(Debug)]
pub struct ReplayFilter {
    inner: Mutex<ReplayFilterInner>,
}

#[derive(Debug)]
struct ReplayFilterInner {
    current: HashSet<(Vec<u8>, [u8; 16])>,
    previous: HashSet<(Vec<u8>, [u8; 16])>,
    last_rotated: Instant,
    rotation_interval: Duration,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self::with_interval(Duration::from_secs(300))
    }

    pub fn with_interval(rotation_interval: Duration) -> Self {
        Self {
            inner: Mutex::new(ReplayFilterInner {
                current: HashSet::new(),
                previous: HashSet::new(),
                last_rotated: Instant::now(),
                rotation_interval,
            }),
        }
    }

    /// Checks if a nonce was already seen for this principal within the sliding window.
    /// If fresh, records it in the current generation and returns `true`.
    /// If duplicate, returns `false`.
    pub fn check_and_insert(&self, principal_id: &[u8], nonce: &[u8; 16]) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if guard.last_rotated.elapsed() >= guard.rotation_interval {
            guard.previous = std::mem::take(&mut guard.current);
            guard.last_rotated = Instant::now();
        }

        let key = (principal_id.to_vec(), *nonce);
        if guard.current.contains(&key) || guard.previous.contains(&key) {
            return false;
        }

        // Bound in-memory cache size; overflow still falls back to PostgreSQL `request_nonces`
        if guard.current.len() < MAX_GENERATION_ENTRIES {
            guard.current.insert(key);
        }
        true
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_filter_fresh_and_duplicate() {
        let filter = ReplayFilter::new();
        let principal = b"account-123456789012345678901234";
        let nonce = [0x42u8; 16];

        // First attempt is fresh
        assert!(filter.check_and_insert(principal, &nonce));

        // Immediate retry is duplicate
        assert!(!filter.check_and_insert(principal, &nonce));

        // Different nonce for same principal is fresh
        let nonce_2 = [0x43u8; 16];
        assert!(filter.check_and_insert(principal, &nonce_2));

        // Same nonce for different principal is fresh
        let principal_2 = b"account-999999999012345678901234";
        assert!(filter.check_and_insert(principal_2, &nonce));
    }

    #[test]
    fn test_replay_filter_generation_rotation() {
        let filter = ReplayFilter::with_interval(Duration::from_millis(10));
        let principal = b"account-test";
        let nonce = [0x11u8; 16];

        assert!(filter.check_and_insert(principal, &nonce));

        // Sleep to rotate once (nonce moves to previous)
        std::thread::sleep(Duration::from_millis(15));
        assert!(!filter.check_and_insert(principal, &nonce)); // Still in previous

        // Sleep to rotate again (previous is dropped)
        std::thread::sleep(Duration::from_millis(15));
        // Calling check_and_insert will trigger rotation and drop previous
        let nonce_fresh = [0x22u8; 16];
        assert!(filter.check_and_insert(principal, &nonce_fresh));

        // Original nonce should now be expired from memory
        assert!(filter.check_and_insert(principal, &nonce));
    }
}
