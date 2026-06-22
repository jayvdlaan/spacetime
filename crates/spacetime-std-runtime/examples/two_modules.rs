// Run with: cargo run -p spacetime-std-runtime --features logging --example two_modules

use spacetime_core::{
    Duration as StDuration, InitCtx as StInitCtx, InitError as StInitError, Module as StModule,
    Runtime as StRuntime, StartError as StStartError, Version as StVersion,
};
use spacetime_std_runtime::StdRuntime;

#[cfg(feature = "logging")]
fn init_logging() {
    spacetime_std_runtime::logging::init_tracing_logging();
}
#[cfg(not(feature = "logging"))]
fn init_logging() {}

struct A;
struct B;

impl StModule for A {
    const NAME: &'static str = "A";
    const VERSION: StVersion = StVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    type Deps<'a> = ();
    fn init(_ctx: &mut StInitCtx, _deps: Self::Deps<'_>) -> Result<Self, StInitError> {
        Ok(A)
    }
    fn start(&mut self, rt: &dyn StRuntime) -> Result<(), StStartError> {
        spacetime_logging::info!("A starting at {} ms", rt.clock().now().millis_since_epoch);
        rt.timer().sleep(StDuration::from_millis(5));
        Ok(())
    }
}

impl StModule for B {
    const NAME: &'static str = "B";
    const VERSION: StVersion = StVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    type Deps<'a> = ();
    fn init(_ctx: &mut StInitCtx, _deps: Self::Deps<'_>) -> Result<Self, StInitError> {
        Ok(B)
    }
    fn start(&mut self, rt: &dyn StRuntime) -> Result<(), StStartError> {
        spacetime_logging::info!(
            "B starting after A; now {} ms",
            rt.clock().now().millis_since_epoch
        );
        Ok(())
    }
}

fn main() {
    init_logging();
    let rt = StdRuntime::new();
    let mut ctx = StInitCtx;

    // Initialize and start modules in dependency order: A then B.
    let mut a = A::init(&mut ctx, ()).expect("A init");
    let mut b = B::init(&mut ctx, ()).expect("B init");
    a.start(&rt).expect("A start");
    b.start(&rt).expect("B start");
}
