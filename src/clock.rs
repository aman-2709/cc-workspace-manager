//! Injectable time source (Unix seconds) so expiry logic is testable without sleeping.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    fn now(&self) -> i64;

    /// Milliseconds since the epoch (the debug log of hook events orders them more finely than a
    /// second). A clock without a finer source ticks in whole seconds.
    fn now_ms(&self) -> i64 {
        self.now().saturating_mul(1000)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

/// Manually advanced clock for tests.
#[derive(Debug)]
pub struct FakeClock(AtomicI64);

impl FakeClock {
    pub fn new(start: i64) -> Self {
        Self(AtomicI64::new(start))
    }
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_advances() {
        let c = FakeClock::new(100);
        assert_eq!(c.now(), 100);
        c.advance(5);
        assert_eq!(c.now(), 105);
    }

    #[test]
    fn system_clock_is_after_2024() {
        assert!(SystemClock.now() > 1_704_067_200);
        let (s, ms) = (SystemClock.now(), SystemClock.now_ms());
        assert!((ms / 1000 - s).abs() <= 1, "{s} {ms}");
        assert_eq!(FakeClock::new(7).now_ms(), 7000);
    }
}
