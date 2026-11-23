//! Single-use bootstrap tokens: in memory only, 60 s lifetime, at most 16 outstanding.

use super::tokens::{hash_token, is_well_formed, new_token};
use crate::api_error::ApiError;
use crate::clock::Clock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const BOOTSTRAP_TTL_SECS: i64 = 60;
pub const MAX_OUTSTANDING: usize = 16;

pub struct BootstrapStore {
    clock: Arc<dyn Clock>,
    /// digest -> expiry (Unix seconds)
    tokens: Mutex<HashMap<[u8; 32], i64>>,
}

impl BootstrapStore {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a token. When 16 are outstanding the oldest is evicted, so a flood cannot lock the owner out.
    pub fn issue(&self) -> Result<String, ApiError> {
        let token = new_token()?;
        let now = self.clock.now();
        let mut map = self
            .tokens
            .lock()
            .map_err(|_| ApiError::internal("bootstrap store poisoned"))?;
        map.retain(|_, exp| *exp > now);
        while map.len() >= MAX_OUTSTANDING {
            let Some(oldest) = map.iter().min_by_key(|(_, exp)| **exp).map(|(k, _)| *k) else {
                break;
            };
            map.remove(&oldest);
        }
        map.insert(hash_token(&token), now + BOOTSTRAP_TTL_SECS);
        Ok(token)
    }

    /// Consume a token. Returns `true` exactly once per issued, unexpired token.
    pub fn redeem(&self, token: &str) -> bool {
        if !is_well_formed(token) {
            return false;
        }
        let now = self.clock.now();
        let Ok(mut map) = self.tokens.lock() else {
            return false;
        };
        matches!(map.remove(&hash_token(token)), Some(exp) if exp > now)
    }

    pub fn outstanding(&self) -> usize {
        self.tokens.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;

    fn store() -> (BootstrapStore, Arc<FakeClock>) {
        let clock = Arc::new(FakeClock::new(1_000));
        (BootstrapStore::new(clock.clone()), clock)
    }

    #[test]
    fn token_is_single_use() {
        let (s, _) = store();
        let t = s.issue().unwrap();
        assert!(s.redeem(&t));
        assert!(!s.redeem(&t));
    }

    #[test]
    fn token_expires_after_60_seconds() {
        let (s, clock) = store();
        let t = s.issue().unwrap();
        clock.advance(59);
        assert!(s.redeem(&t));
        let t = s.issue().unwrap();
        clock.advance(60);
        assert!(!s.redeem(&t), "expiry is exclusive at exactly 60 s");
        assert_eq!(s.outstanding(), 0, "an expired token is removed on redeem");
    }

    #[test]
    fn unknown_and_malformed_tokens_fail() {
        let (s, _) = store();
        assert!(!s.redeem("nope"));
        assert!(!s.redeem(&new_token().unwrap()));
        assert!(!s.redeem(""));
    }

    #[test]
    fn at_most_sixteen_outstanding_and_oldest_is_evicted() {
        let (s, clock) = store();
        let first = s.issue().unwrap();
        let mut rest = Vec::new();
        for _ in 0..MAX_OUTSTANDING {
            clock.advance(1);
            rest.push(s.issue().unwrap());
        }
        assert_eq!(s.outstanding(), MAX_OUTSTANDING);
        assert!(!s.redeem(&first), "oldest was evicted");
        assert!(s.redeem(rest.last().unwrap()));
    }

    #[test]
    fn expired_tokens_are_purged_on_issue() {
        let (s, clock) = store();
        for _ in 0..5 {
            s.issue().unwrap();
        }
        clock.advance(61);
        s.issue().unwrap();
        assert_eq!(s.outstanding(), 1);
    }
}
