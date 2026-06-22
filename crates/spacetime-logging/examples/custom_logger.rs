// Run with: cargo run -p spacetime-logging --example custom_logger --features std

#[cfg(feature = "std")]
fn main() {
    use spacetime_logging::{debug, error, info, set_logger, set_max_level, warn, Level, Logger};

    struct StdoutLogger;
    impl Logger for StdoutLogger {
        fn enabled(&self, _level: Level, _target: &str) -> bool {
            true
        }
        fn log(&self, level: Level, target: &str, args: core::fmt::Arguments<'_>) {
            println!("[{level:?}] {target}: {args}");
        }
    }

    // Install a minimal logger that prints to stdout (no tracing involved)
    set_logger(&StdoutLogger);

    // Default max level is Info; lower to Debug to see debug messages
    set_max_level(Level::Debug);
    debug!("debug is visible now");
    info!("info is visible");
    warn!("warn is visible");
    error!("error is visible");

    // Raise the filter to Warn; Debug/Info will be dropped
    set_max_level(Level::Warn);
    debug!("this will be filtered out: {}", 123);
    info!("this too will be filtered");
    warn!("but warn shows");
    error!("and error shows");
}

#[cfg(not(feature = "std"))]
fn main() {
    eprintln!(
        "This example requires the `std` feature: cargo run --example custom_logger --features std"
    );
}
