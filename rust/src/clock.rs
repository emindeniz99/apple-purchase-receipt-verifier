//! The injectable source of "now".
//!
//! The clock is read in exactly two places in this crate, and nowhere else:
//!
//! 1. the `STALE_PAYLOAD` comparison in [`JwsVerifier`](crate::JwsVerifier);
//! 2. the `request_date` / `_ms` / `_pst` triple in
//!    [`VerifyReceiptEndpoint`](crate::VerifyReceiptEndpoint).
//!
//! **Certificate validity is never judged at an injected clock.** When a
//! payload or receipt states no date of its own, the fallback instant for
//! the chain-validity check reads [`SystemTime::now`] directly. A caller
//! injecting a clock — to test staleness, or to work around skew — must not
//! thereby be able to accept an expired chain or expire a live one.
//! [`ReceiptVerifier`](crate::ReceiptVerifier) therefore takes no clock at
//! all.

use core::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A source of the current instant.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current instant.
    fn now(&self) -> SystemTime;
}

/// The default clock: the system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that always answers the same instant — for tests and for the
/// conformance vectors that pin one.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(SystemTime);

impl FixedClock {
    /// A clock pinned to `at`.
    #[must_use]
    pub const fn new(at: SystemTime) -> Self {
        FixedClock(at)
    }

    /// A clock pinned to `millis` milliseconds after the Unix epoch.
    #[must_use]
    pub fn from_unix_millis(millis: i64) -> Self {
        FixedClock(crate::datetime::system_time_from_millis(millis))
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

impl<F> Clock for F
where
    F: Fn() -> SystemTime + Send + Sync + fmt::Debug,
{
    fn now(&self) -> SystemTime {
        self()
    }
}

/// The default clock, shared.
pub(crate) fn default_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Milliseconds since the Unix epoch, for a clock reading.
pub(crate) fn unix_millis(at: SystemTime) -> i64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_millis()).unwrap_or(i64::MAX),
        Err(err) => {
            let before: Duration = err.duration();
            i64::try_from(before.as_millis()).map_or(i64::MIN, i64::wrapping_neg)
        }
    }
}
