//! Std-backed implementations of spacetime_core::Clock, ::Timer, and ::Runtime.
//!
//! This crate lives under the Spacetime workspace so any runtime can reuse
//! the same std adapters without depending on Airframe.
#![cfg_attr(test, deny(warnings))]

use spacetime_core::{
    Clock as StClock, Duration as StDuration, Instant as StInstant,
    MonotonicClock as StMonotonicClock, MonotonicInstant as StMonotonicInstant,
    Runtime as StRuntime, Timer as StTimer,
};

/// A simple std-backed clock using std::time::SystemTime.
pub struct StdClock;

impl StClock for StdClock {
    fn now(&self) -> StInstant {
        // Use UNIX_EPOCH as reference; saturate on conversion errors.
        let millis = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64,
            Err(_) => 0,
        };
        StInstant {
            millis_since_epoch: millis,
        }
    }
}

/// A std-backed monotonic clock using `std::time::Instant`.
///
/// Unlike `StdClock` (wall-clock / `SystemTime`), this clock never jumps
/// backwards and is suitable for measuring elapsed time, timeouts, and
/// intervals.
pub struct StdMonotonicClock {
    /// The reference point captured at construction time. All
    /// `MonotonicInstant` values are expressed as millisecond offsets from
    /// this origin, ensuring they fit in a `u64` for a very long time.
    origin: std::time::Instant,
}

impl Default for StdMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl StdMonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl StMonotonicClock for StdMonotonicClock {
    fn now_monotonic(&self) -> StMonotonicInstant {
        let elapsed = self.origin.elapsed();
        StMonotonicInstant::from_ticks_ms(elapsed.as_millis() as u64)
    }
}

/// Returns the current wall-clock time as whole seconds since the Unix epoch.
///
/// Convenience wrapper around [`StdClock`] for call sites that need a quick
/// timestamp without threading a `Clock` instance through DI.
pub fn now_secs() -> u64 {
    StdClock.now().millis_since_epoch / 1000
}

/// Returns the current wall-clock time as milliseconds since the Unix epoch.
///
/// Convenience wrapper around [`StdClock`] for call sites that need a quick
/// timestamp without threading a `Clock` instance through DI.
pub fn now_millis() -> u64 {
    StdClock.now().millis_since_epoch
}

/// A simple std-backed timer using std::thread::sleep.
pub struct StdTimer;

impl StTimer for StdTimer {
    fn sleep(&self, dur: StDuration) {
        let ms = dur.as_millis();
        // Best-effort sleep; if ms is large, std handles conversion.
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// A minimal Runtime that exposes the std-backed clock, monotonic clock, and timer.
pub struct StdRuntime {
    clock: StdClock,
    monotonic_clock: StdMonotonicClock,
    timer: StdTimer,
}

impl Default for StdRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl StdRuntime {
    pub fn new() -> Self {
        Self {
            clock: StdClock,
            monotonic_clock: StdMonotonicClock::new(),
            timer: StdTimer,
        }
    }

    /// Returns a reference to the monotonic clock.
    pub fn monotonic_clock(&self) -> &StdMonotonicClock {
        &self.monotonic_clock
    }
}

impl StRuntime for StdRuntime {
    fn clock(&self) -> &dyn StClock {
        &self.clock
    }
    fn timer(&self) -> &dyn StTimer {
        &self.timer
    }
}

#[cfg(feature = "logging")]
pub mod logging {
    use spacetime_logging::std_adapter::TracingLogger;

    /// Initialize a default tracing subscriber (env-filter aware) and
    /// set the spacetime logger to forward events to tracing.
    pub fn init_tracing_logging() {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        spacetime_logging::set_logger(&TracingLogger);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacetime_core::{
        Duration as StDuration, InitCtx as StInitCtx, InitError as StInitError, Module as StModule,
        StartError as StStartError, Version as StVersion,
    };

    struct Dummy;

    impl StModule for Dummy {
        const NAME: &'static str = "dummy";
        const VERSION: StVersion = StVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };

        type Deps<'a> = ();

        fn init(_ctx: &mut StInitCtx, _deps: Self::Deps<'_>) -> Result<Self, StInitError>
        where
            Self: Sized,
        {
            Ok(Dummy)
        }

        fn start(&mut self, rt: &dyn spacetime_core::Runtime) -> Result<(), StStartError> {
            // Exercise clock + timer
            let t0 = rt.clock().now();
            rt.timer().sleep(StDuration::from_millis(1));
            let t1 = rt.clock().now();
            assert!(t1.millis_since_epoch >= t0.millis_since_epoch);
            Ok(())
        }
    }

    #[test]
    fn std_runtime_can_start_dummy_module() {
        let rt = StdRuntime::new();
        let mut ctx = StInitCtx;
        let mut m = Dummy::init(&mut ctx, ()).unwrap();
        m.start(&rt).unwrap();
    }

    #[test]
    fn sleep_has_minimal_tolerance() {
        let rt = StdRuntime::new();
        let before = std::time::Instant::now();
        rt.timer().sleep(StDuration::from_millis(5));
        let elapsed = before.elapsed();
        // We expect at least ~5ms elapsed; allow timers to overshoot on coarse systems.
        assert!(elapsed >= std::time::Duration::from_millis(5));
    }

    #[test]
    fn monotonic_clock_advances() {
        use spacetime_core::MonotonicClock;

        let rt = StdRuntime::new();
        let mono = rt.monotonic_clock();

        let t0 = mono.now_monotonic();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t1 = mono.now_monotonic();

        // Monotonic clock must not go backwards.
        assert!(t1.ticks_ms >= t0.ticks_ms);

        // Elapsed should be at least 5ms.
        let elapsed = mono.elapsed_since(t0);
        assert!(elapsed.millis >= 5);
    }

    #[test]
    fn monotonic_clock_never_negative() {
        use spacetime_core::MonotonicClock;

        let mono = StdMonotonicClock::new();
        let t0 = mono.now_monotonic();
        // First reading should be very close to 0 (just created the clock).
        // It must not be a wild value.
        assert!(
            t0.ticks_ms < 1000,
            "first monotonic reading unexpectedly large"
        );
    }
}
