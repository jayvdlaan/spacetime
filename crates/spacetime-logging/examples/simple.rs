// Run with: cargo run -p spacetime-logging --example simple --features std

use spacetime_logging as slog;

struct StdoutLogger;

impl slog::Logger for StdoutLogger {
    fn enabled(&self, _level: slog::Level, _target: &str) -> bool {
        true
    }
    fn log(&self, level: slog::Level, target: &str, args: core::fmt::Arguments<'_>) {
        println!("[{level:?}] {target}: {args}");
    }
}

fn main() {
    slog::set_logger(&StdoutLogger);
    slog::trace!("trace {}", 1);
    slog::debug!("debug {}", 2);
    slog::info!("hello {}", "world");
    slog::warn!(target: "demo", "warn!");
    slog::error!("error!");
}
