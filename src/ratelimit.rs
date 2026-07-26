//! In-memory rate limiting for the DDNS endpoint: 60 updates/hour per record and 600/hour per token
//! (PRD §2). A fixed 1-hour window per key is enough — regular updates are not expected, so the limit
//! is an abuse guard, not a fairness scheduler.
//!
//! The *other* in-memory guard — the brute-force brake on failed credential checks — is not here: it is
//! relativelylight's own attempt limiter, shared through `AppState::attempts` so the console login and
//! our DDNS/API/CF credential checks spend one budget per account (see `principal`, PRD §3.6).

use crate::model::now;
use std::collections::HashMap;
use std::sync::Mutex;

const WINDOW_SECS: i64 = 3600;
pub const PER_RECORD_LIMIT: u32 = 60;
pub const PER_TOKEN_LIMIT: u32 = 600;

#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Counter>>,
}

struct Counter {
    window_start: i64,
    count: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter { inner: Mutex::new(HashMap::new()) }
    }

    /// Record a hit for `key`; returns false if it would exceed `limit` in the current hour window.
    pub fn allow(&self, key: &str, limit: u32) -> bool {
        let t = now();
        let mut map = self.inner.lock().unwrap();
        let c = map.entry(key.to_string()).or_insert(Counter { window_start: t, count: 0 });
        if t - c.window_start >= WINDOW_SECS {
            c.window_start = t;
            c.count = 0;
        }
        if c.count >= limit {
            return false;
        }
        c.count += 1;
        true
    }

    /// Both the per-record and per-token gates for a DDNS update.
    pub fn allow_update(&self, token_key: &str, record_key: &str) -> bool {
        // Check the record gate first, then the token gate; both must pass. (Order chosen so a single
        // record can't burn the whole token budget before its own gate trips.)
        self.allow(record_key, PER_RECORD_LIMIT) && self.allow(token_key, PER_TOKEN_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_key_limit() {
        let rl = RateLimiter::new();
        for _ in 0..PER_RECORD_LIMIT {
            assert!(rl.allow("rec", PER_RECORD_LIMIT));
        }
        assert!(!rl.allow("rec", PER_RECORD_LIMIT));
        // A different key has its own budget.
        assert!(rl.allow("other", PER_RECORD_LIMIT));
    }
}
