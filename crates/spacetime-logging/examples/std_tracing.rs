// Run with: cargo run -p spacetime-logging --example std_tracing --features std

#[cfg(feature = "std")]
fn main() {
    use spacetime_logging::std_adapter::TracingLogger;
    use spacetime_logging::{error, info, warn};

    // Install a simple tracing subscriber for stdout logging.
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("set global tracing subscriber");

    // Bridge spacetime-logging macros to tracing via the adapter.
    spacetime_logging::set_logger(&TracingLogger);

    info!("hello from spacetime-logging via tracing");
    warn!(target: "demo", "this is a warning: {}", 42);
    error!("and an error");
}

#[cfg(not(feature = "std"))]
fn main() {
    eprintln!(
        "This example requires the `std` feature: cargo run --example std_tracing --features std"
    );
}
