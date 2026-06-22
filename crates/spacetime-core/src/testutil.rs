//! Shared test utilities for spacetime crates.
//!
//! This module is gated on `feature = "std"` and hidden from documentation.
//! It provides common test doubles used across the spacetime workspace to
//! avoid duplicating trivial runtime/clock/timer stubs in every test file.

use crate::{Clock, Duration, Instant, Runtime, Timer};

/// A no-op runtime suitable for tests that need a `Runtime` but don't care
/// about real time.  All clock queries return epoch-zero; sleep is a no-op.
pub struct DummyRuntime;

impl Clock for DummyRuntime {
    fn now(&self) -> Instant {
        Instant {
            millis_since_epoch: 0,
        }
    }
}

impl Timer for DummyRuntime {
    fn sleep(&self, _dur: Duration) {}
}

impl Runtime for DummyRuntime {
    fn clock(&self) -> &dyn Clock {
        self
    }
    fn timer(&self) -> &dyn Timer {
        self
    }
}
