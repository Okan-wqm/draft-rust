//! A controllable clock (ARC-04, TST-08).

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use authn_core::ports::Clock;
use time::OffsetDateTime;
use time::macros::datetime;

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<OffsetDateTime>,
}

impl FakeClock {
    /// Default start instant: 2026-01-01T00:00:00Z.
    pub const DEFAULT_START: OffsetDateTime = datetime!(2026-01-01 00:00:00 UTC);

    /// A clock at [`FakeClock::DEFAULT_START`].
    #[must_use]
    pub fn new() -> Self {
        Self::at(Self::DEFAULT_START)
    }

    /// A clock at the given instant.
    #[must_use]
    pub fn at(now: OffsetDateTime) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// Moves time forward.
    pub fn advance(&self, by: Duration) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now += by;
    }

    /// Sets the current instant.
    pub fn set(&self, to: OffsetDateTime) {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner) = to;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_04_fake_clock_advances_only_on_request() {
        let clock = FakeClock::new();
        assert_eq!(clock.now(), FakeClock::DEFAULT_START);
        assert_eq!(clock.now(), FakeClock::DEFAULT_START);
        clock.advance(Duration::from_secs(90));
        assert_eq!(
            clock.now(),
            FakeClock::DEFAULT_START + Duration::from_secs(90)
        );
        clock.set(FakeClock::DEFAULT_START);
        assert_eq!(clock.now(), FakeClock::DEFAULT_START);
    }
}
