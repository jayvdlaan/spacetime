#![no_std]

//! Spacetime core: no_std-first traits and types for modules and runtimes.
//!
//! This crate defines the minimal, portable API surface shared across
//! runtimes (embedded, std, wasm). It purposefully avoids picking concrete
//! runtime/executor implementations and focuses on typed capabilities and
//! lifecycle contracts.

#[cfg(feature = "std")]
extern crate std as core_std;

// Basic version type (semver-like, compact)
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

// Compact status codes appropriate for no_std environments
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Status {
    Ok,
    Unsupported,
    Unavailable,
    Denied,
    Invalid,
    Failed,
}

// Time primitives (thin wrappers to avoid binding to a specific clock)
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Duration {
    pub millis: u64,
}

impl Duration {
    pub const fn from_millis(ms: u64) -> Self {
        Self { millis: ms }
    }
    pub const fn zero() -> Self {
        Self { millis: 0 }
    }
    pub const fn from_secs(secs: u64) -> Self {
        Self {
            millis: secs.saturating_mul(1000),
        }
    }
    pub const fn as_millis(&self) -> u64 {
        self.millis
    }
    pub const fn as_secs(&self) -> u64 {
        self.millis / 1000
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Instant {
    pub millis_since_epoch: u64,
}

impl Instant {
    pub const fn from_millis_since_epoch(ms: u64) -> Self {
        Self {
            millis_since_epoch: ms,
        }
    }

    /// Returns a new Instant that is `self + dur`, saturating on overflow.
    pub const fn saturating_add(self, dur: Duration) -> Self {
        let (res, overflowed) = self.millis_since_epoch.overflowing_add(dur.millis);
        if overflowed {
            Self {
                millis_since_epoch: u64::MAX,
            }
        } else {
            Self {
                millis_since_epoch: res,
            }
        }
    }

    /// Returns the duration between `self` and `other`, saturating at zero.
    pub const fn saturating_duration_since(self, earlier: Instant) -> Duration {
        if self.millis_since_epoch >= earlier.millis_since_epoch {
            Duration {
                millis: self.millis_since_epoch - earlier.millis_since_epoch,
            }
        } else {
            Duration::zero()
        }
    }

    /// Returns `self - dur`, saturating at zero epoch on underflow.
    pub const fn saturating_sub(self, dur: Duration) -> Self {
        let (res, overflowed) = self.millis_since_epoch.overflowing_sub(dur.millis);
        if overflowed {
            Self {
                millis_since_epoch: 0,
            }
        } else {
            Self {
                millis_since_epoch: res,
            }
        }
    }
}

// Monotonic time primitive — opaque tick counter unrelated to wall-clock epoch.
//
// Unlike `Instant` (which tracks milliseconds since the Unix epoch and can
// jump when the system clock is adjusted), `MonotonicInstant` represents a
// point on a strictly non-decreasing timeline suitable for measuring elapsed
// durations, timeouts, and intervals.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct MonotonicInstant {
    pub ticks_ms: u64,
}

impl MonotonicInstant {
    /// Create a `MonotonicInstant` from a raw tick count in milliseconds.
    pub const fn from_ticks_ms(ms: u64) -> Self {
        Self { ticks_ms: ms }
    }

    /// Returns a new instant that is `self + dur`, saturating on overflow.
    pub const fn saturating_add(self, dur: Duration) -> Self {
        let (res, overflowed) = self.ticks_ms.overflowing_add(dur.millis);
        if overflowed {
            Self { ticks_ms: u64::MAX }
        } else {
            Self { ticks_ms: res }
        }
    }

    /// Returns the duration between `self` and `earlier`, saturating at zero.
    pub const fn saturating_duration_since(self, earlier: MonotonicInstant) -> Duration {
        if self.ticks_ms >= earlier.ticks_ms {
            Duration {
                millis: self.ticks_ms - earlier.ticks_ms,
            }
        } else {
            Duration::zero()
        }
    }

    /// Returns `self - dur`, saturating at zero on underflow.
    pub const fn saturating_sub(self, dur: Duration) -> Self {
        let (res, overflowed) = self.ticks_ms.overflowing_sub(dur.millis);
        if overflowed {
            Self { ticks_ms: 0 }
        } else {
            Self { ticks_ms: res }
        }
    }
}

// Core capability traits

/// Wall-clock time source. May jump forwards or backwards when the system
/// clock is adjusted. Use for timestamps and calendar-related operations.
pub trait Clock {
    fn now(&self) -> Instant;
}

/// Monotonic time source. Guaranteed to be non-decreasing — suitable for
/// measuring elapsed time, timeouts, and intervals.
pub trait MonotonicClock {
    /// Returns the current monotonic instant.
    fn now_monotonic(&self) -> MonotonicInstant;

    /// Returns the elapsed duration since `earlier`.
    ///
    /// Default implementation calls `now_monotonic()` and computes the
    /// difference; implementors may override for platform-specific
    /// optimisations.
    fn elapsed_since(&self, earlier: MonotonicInstant) -> Duration {
        self.now_monotonic().saturating_duration_since(earlier)
    }
}

pub trait Timer {
    fn sleep(&self, dur: Duration);
}

// Runtime abstraction: access to platform services
pub trait Runtime {
    fn clock(&self) -> &dyn Clock;
    fn timer(&self) -> &dyn Timer;
}

// Module lifecycle
pub trait Module {
    const NAME: &'static str;
    const VERSION: Version;

    type Deps<'a>
    where
        Self: 'a;

    fn init(ctx: &mut InitCtx, deps: Self::Deps<'_>) -> Result<Self, InitError>
    where
        Self: Sized;

    fn start(&mut self, _rt: &dyn Runtime) -> Result<(), StartError> {
        Ok(())
    }

    fn shutdown(&mut self) {}
}

// Init/Start contexts and errors (kept minimal for now)
/// Initialization context supplied to `Module::init`.
///
/// This is intentionally minimal for now; additional fields will be added
/// in a backward-compatible way as more capabilities are standardized.
pub struct InitCtx;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum InitError {
    Unsupported,
    Denied,
    Invalid,
    Failed,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StartError {
    Unavailable,
    Failed,
}

// Lightweight conversions between generic status and specific errors
impl From<Status> for InitError {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok => InitError::Invalid,
            Status::Unsupported => InitError::Unsupported,
            Status::Unavailable => InitError::Failed,
            Status::Denied => InitError::Denied,
            Status::Invalid => InitError::Invalid,
            Status::Failed => InitError::Failed,
        }
    }
}

impl From<Status> for StartError {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok => StartError::Failed,
            Status::Unsupported => StartError::Failed,
            Status::Unavailable => StartError::Unavailable,
            Status::Denied => StartError::Failed,
            Status::Invalid => StartError::Failed,
            Status::Failed => StartError::Failed,
        }
    }
}

/// Shared test utilities (dummy runtime, etc.) for use across spacetime crates.
///
/// Available only when the `std` feature is enabled.
#[cfg(feature = "std")]
#[doc(hidden)]
pub mod testutil;

#[cfg(all(test, feature = "std"))]
mod tests;
