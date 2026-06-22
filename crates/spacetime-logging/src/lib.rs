#![no_std]

//! Spacetime logging facade: minimal, no_std-friendly API.
//!
//! Goals:
//! - Tiny surface: Level enum, Logger trait, global setter, and macros.
//! - Works in no_std (no allocations required).
//! - Formatting via core::fmt::Arguments (usable without std).
//!
//! Thread-safety: the global logger is stored using atomic operations, making
//! it safe for concurrent access. The logger reference is decomposed into its
//! data pointer and vtable pointer, each stored in a separate `AtomicPtr`.
//! The max level is stored as an `AtomicU8`. All accesses use `SeqCst`
//! ordering to guarantee visibility across threads.
//!
//! Using a platform logger
//! - Call `set_logger(&YourLogger)` once during startup. YourLogger implements
//!   `Logger` and can forward into platform facilities (e.g., `tracing` or `log`).
//! - In std builds with the `std` feature, you can use the provided
//!   `std_adapter::TracingLogger` to bridge directly to the `tracing` crate.
//!   See `examples/std_tracing.rs` for a minimal setup.

use core::fmt;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

/// Log level severity.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn to_u8(self) -> u8 {
        match self {
            Level::Trace => 0,
            Level::Debug => 1,
            Level::Info => 2,
            Level::Warn => 3,
            Level::Error => 4,
        }
    }

    fn from_u8(v: u8) -> Level {
        match v {
            0 => Level::Trace,
            1 => Level::Debug,
            2 => Level::Info,
            3 => Level::Warn,
            4 => Level::Error,
            _ => Level::Info, // fallback
        }
    }
}

/// Logger interface.
pub trait Logger {
    /// Returns true if a message at `level` for `target` would be logged.
    fn enabled(&self, _level: Level, _target: &str) -> bool {
        true
    }

    /// Emit a formatted log record.
    fn log(&self, level: Level, target: &str, args: fmt::Arguments<'_>);
}

// The global logger is stored as a fat pointer decomposed into two atomic
// pointer-sized values: the data pointer and the vtable pointer.
// This avoids `static mut` and is safe for concurrent access.
//
// A null data pointer means no logger is installed.
static LOGGER_DATA: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static LOGGER_VTABLE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

// The global max level is stored as an AtomicU8.
// Default is Level::Info (== 2).
static MAX_LEVEL: AtomicU8 = AtomicU8::new(2);

/// Install a global logger. Should be called once at startup.
pub fn set_logger(logger: &'static dyn Logger) {
    // Decompose the fat pointer into (data, vtable).
    let raw: *const dyn Logger = logger;
    let [data, vtable] = decompose_fat_ptr(raw);
    // Store vtable first, then data, so that a reader who sees a non-null
    // data pointer is guaranteed to also see the corresponding vtable.
    LOGGER_VTABLE.store(vtable, Ordering::SeqCst);
    LOGGER_DATA.store(data, Ordering::SeqCst);
}

/// Returns the currently installed global logger, if any.
pub fn get_logger() -> Option<&'static dyn Logger> {
    load_logger()
}

/// Set a global max level filter. Messages below this level are dropped
/// before reaching the logger. Default is `Level::Info`.
pub fn set_max_level(level: Level) {
    MAX_LEVEL.store(level.to_u8(), Ordering::SeqCst);
}

/// Get the current global max level filter.
pub fn max_level() -> Level {
    Level::from_u8(MAX_LEVEL.load(Ordering::SeqCst))
}

/// Internal helper used by macros.
#[doc(hidden)]
pub fn __log(level: Level, target: &str, args: fmt::Arguments<'_>) {
    let current_max = Level::from_u8(MAX_LEVEL.load(Ordering::SeqCst));
    if let Some(l) = load_logger() {
        if level >= current_max && l.enabled(level, target) {
            l.log(level, target, args);
        }
    }
}

/// Load the global logger from atomic storage.
fn load_logger() -> Option<&'static dyn Logger> {
    let data = LOGGER_DATA.load(Ordering::SeqCst);
    if data.is_null() {
        return None;
    }
    let vtable = LOGGER_VTABLE.load(Ordering::SeqCst);
    // Safety: `data` and `vtable` were originally obtained from a valid
    // `&'static dyn Logger` in `set_logger`, so reconstructing the fat
    // pointer yields a valid reference with 'static lifetime.
    let raw = compose_fat_ptr(data, vtable);
    Some(unsafe { &*raw })
}

// Compile-time guard: the decompose/compose pair below relies on a `*const dyn
// Logger` being exactly two pointer-sized words. The trait-object pointer layout
// is *not* a guaranteed part of the Rust ABI, but it is stable in practice on
// every current target. This assertion fails the build (rather than silently
// corrupting memory) if that ever stops holding. The fully-guaranteed
// implementation will use `core::ptr::metadata`/`from_raw_parts` once stable.
const _: () = assert!(
    core::mem::size_of::<*const dyn Logger>() == 2 * core::mem::size_of::<*mut ()>(),
    "trait-object pointer is not two words wide on this target; \
     the AtomicPtr-based global logger storage is unsound here"
);

/// Decompose a `*const dyn Logger` fat pointer into `[data, vtable]` as
/// `*mut ()` values suitable for storing in `AtomicPtr<()>`.
fn decompose_fat_ptr(ptr: *const dyn Logger) -> [*mut (); 2] {
    // Safety: relies on the (unspecified-but-stable-in-practice) two-word layout
    // of trait-object pointers, guarded by the compile-time size assertion above.
    let [data, vtable]: [*mut (); 2] = unsafe { core::mem::transmute(ptr) };
    [data, vtable]
}

/// Reconstruct a `*const dyn Logger` fat pointer from data and vtable
/// pointers previously obtained via `decompose_fat_ptr`.
fn compose_fat_ptr(data: *mut (), vtable: *mut ()) -> *const dyn Logger {
    // Safety: reconstructs the exact pair of pointers originally decomposed from a
    // valid `*const dyn Logger`; same layout assumption as `decompose_fat_ptr`.
    unsafe { core::mem::transmute([data, vtable]) }
}

/// Core logging macro; prefer using level-specific macros.
#[macro_export]
macro_rules! log {
    (level: $level:expr, target: $target:expr, $($arg:tt)*) => {{
        $crate::__log($level, $target, core::format_args!($($arg)*));
    }};
    (level: $level:expr, $($arg:tt)*) => {{
        $crate::__log($level, core::module_path!(), core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! trace { ($($arg:tt)*) => { $crate::log!(level: $crate::Level::Trace, $($arg)* ) } }
#[macro_export]
macro_rules! debug { ($($arg:tt)*) => { $crate::log!(level: $crate::Level::Debug, $($arg)* ) } }
#[macro_export]
macro_rules! info  { ($($arg:tt)*) => { $crate::log!(level: $crate::Level::Info,  $($arg)* ) } }
#[macro_export]
macro_rules! warn  { ($($arg:tt)*) => { $crate::log!(level: $crate::Level::Warn,  $($arg)* ) } }
#[macro_export]
macro_rules! error { ($($arg:tt)*) => { $crate::log!(level: $crate::Level::Error, $($arg)* ) } }

/// Std adapter(s) and utilities.
#[cfg(feature = "std")]
pub mod std_adapter {
    use super::{Level, Logger};
    use core::fmt;

    /// A Logger implementation that forwards events to the `tracing` crate.
    ///
    /// Level mapping:
    /// - Trace -> tracing::Level::TRACE
    /// - Debug -> tracing::Level::DEBUG
    /// - Info  -> tracing::Level::INFO
    /// - Warn  -> tracing::Level::WARN
    /// - Error -> tracing::Level::ERROR
    pub struct TracingLogger;

    impl Logger for TracingLogger {
        fn enabled(&self, _level: Level, _target: &str) -> bool {
            true
        }

        fn log(&self, level: Level, target: &str, args: fmt::Arguments<'_>) {
            // Use a static callsite target and include the original target as a field
            match level {
                Level::Trace => {
                    tracing::event!(target: "spacetime", tracing::Level::TRACE, target = target, message = %args)
                }
                Level::Debug => {
                    tracing::event!(target: "spacetime", tracing::Level::DEBUG, target = target, message = %args)
                }
                Level::Info => {
                    tracing::event!(target: "spacetime", tracing::Level::INFO,  target = target, message = %args)
                }
                Level::Warn => {
                    tracing::event!(target: "spacetime", tracing::Level::WARN,  target = target, message = %args)
                }
                Level::Error => {
                    tracing::event!(target: "spacetime", tracing::Level::ERROR, target = target, message = %args)
                }
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std as rust_std;
    use super::*;
    use rust_std::format;
    use rust_std::sync::atomic::{AtomicU32, Ordering};

    struct TestLogger;
    impl Logger for TestLogger {
        fn log(&self, level: Level, target: &str, args: fmt::Arguments<'_>) {
            // Just ensure formatting path runs; print to stdout
            rust_std::println!("[{level:?}] {target}: {args}");
        }
    }

    #[test]
    fn logging_macros_run() {
        set_logger(&TestLogger);
        trace!("trace {}", 1);
        debug!("debug {}", 2);
        info!("hello {}", "world");
        warn!(target: "custom", "warn {}", 3);
        error!("oops");
    }

    #[test]
    fn level_ordering() {
        assert!(Level::Trace < Level::Debug);
        assert!(Level::Debug < Level::Info);
        assert!(Level::Info < Level::Warn);
        assert!(Level::Warn < Level::Error);
        assert_eq!(Level::Info, Level::Info);
    }

    #[test]
    fn set_and_get_max_level() {
        set_max_level(Level::Warn);
        assert_eq!(max_level(), Level::Warn);
        set_max_level(Level::Trace);
        assert_eq!(max_level(), Level::Trace);
        // Reset to default
        set_max_level(Level::Info);
    }

    #[test]
    fn get_logger_returns_installed() {
        set_logger(&TestLogger);
        assert!(get_logger().is_some());
    }

    static LOG_COUNT: AtomicU32 = AtomicU32::new(0);

    struct CountingLogger;
    impl Logger for CountingLogger {
        fn enabled(&self, level: Level, _target: &str) -> bool {
            level >= Level::Warn
        }
        fn log(&self, _level: Level, _target: &str, _args: fmt::Arguments<'_>) {
            LOG_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn logger_enabled_filters_messages() {
        set_logger(&CountingLogger);
        set_max_level(Level::Trace);
        LOG_COUNT.store(0, Ordering::SeqCst);

        // These should be filtered by enabled() returning false for levels below Warn
        __log(Level::Debug, "test", format_args!("debug message"));
        __log(Level::Info, "test", format_args!("info message"));

        // These should pass through enabled() returning true
        __log(Level::Warn, "test", format_args!("warn message"));
        __log(Level::Error, "test", format_args!("error message"));

        assert_eq!(LOG_COUNT.load(Ordering::SeqCst), 2);

        // Reset
        set_max_level(Level::Info);
        set_logger(&TestLogger);
    }

    #[test]
    fn max_level_filters_before_logger() {
        set_logger(&CountingLogger);
        set_max_level(Level::Error);
        LOG_COUNT.store(0, Ordering::SeqCst);

        // All below Error should be dropped by max level check
        __log(Level::Trace, "test", format_args!("trace"));
        __log(Level::Debug, "test", format_args!("debug"));
        __log(Level::Info, "test", format_args!("info"));
        __log(Level::Warn, "test", format_args!("warn"));

        // Only Error should pass
        __log(Level::Error, "test", format_args!("error"));

        assert_eq!(LOG_COUNT.load(Ordering::SeqCst), 1);

        // Reset
        set_max_level(Level::Info);
        set_logger(&TestLogger);
    }

    #[test]
    fn level_debug_and_clone() {
        let level = Level::Info;
        let cloned = level;
        assert_eq!(level, cloned);
        assert_eq!(format!("{:?}", level), "Info");
    }
}
