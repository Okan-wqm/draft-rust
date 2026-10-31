//! Injected time source (ARC-04). Owner: authn-core.
//!
//! Business logic never calls `OffsetDateTime::now_utc()` directly; it asks
//! a `Clock` so tests can move time (`authn_testkit::FakeClock`).

use time::OffsetDateTime;

/// A source of the current time.
pub trait Clock: Send + Sync + 'static {
    /// The current instant in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The real wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_04_system_clock_is_utc() {
        let now = SystemClock.now();
        assert!(now.offset().is_utc());
    }
}
