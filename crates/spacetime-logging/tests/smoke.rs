use spacetime_logging as slog;

struct NopLogger;
impl slog::Logger for NopLogger {
    fn log(&self, _level: slog::Level, _target: &str, _args: core::fmt::Arguments<'_>) {
        // no-op
    }
}

#[test]
fn macros_and_globals_work() {
    slog::set_logger(&NopLogger);
    slog::set_max_level(slog::Level::Trace);
    slog::trace!("trace");
    slog::debug!("debug");
    slog::info!("info {}", 1);
    slog::warn!(target: "t", "warn");
    slog::error!("error");
    assert!(matches!(
        slog::max_level(),
        slog::Level::Trace
            | slog::Level::Debug
            | slog::Level::Info
            | slog::Level::Warn
            | slog::Level::Error
    ));
}
