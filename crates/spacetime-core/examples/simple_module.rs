// Run with: cargo run -p spacetime-core --example simple_module --features std

use sc::{Clock, Duration, InitCtx, Module, Runtime, Timer, Version};
use spacetime_core as sc;

// A simple std-backed clock using SystemTime
struct StdClock;
impl Clock for StdClock {
    fn now(&self) -> sc::Instant {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        sc::Instant::from_millis_since_epoch(now.as_millis() as u64)
    }
}

// A simple std-backed timer using thread::sleep
struct StdTimer;
impl Timer for StdTimer {
    fn sleep(&self, dur: Duration) {
        std::thread::sleep(std::time::Duration::from_millis(dur.millis));
    }
}

struct StdRuntime {
    clock: StdClock,
    timer: StdTimer,
}

impl StdRuntime {
    fn new() -> Self {
        Self {
            clock: StdClock,
            timer: StdTimer,
        }
    }
}

impl Runtime for StdRuntime {
    fn clock(&self) -> &dyn Clock {
        &self.clock
    }
    fn timer(&self) -> &dyn Timer {
        &self.timer
    }
}

struct MyModule;

impl Module for MyModule {
    const NAME: &'static str = "my-module";
    const VERSION: Version = Version {
        major: 0,
        minor: 1,
        patch: 0,
    };

    type Deps<'a> = ();

    fn init(_ctx: &mut InitCtx, _deps: Self::Deps<'_>) -> Result<Self, sc::InitError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn start(&mut self, rt: &dyn Runtime) -> Result<(), sc::StartError> {
        let t0 = rt.clock().now();
        println!(
            "{} v{}.{}.{} starting at {:?}",
            Self::NAME,
            Self::VERSION.major,
            Self::VERSION.minor,
            Self::VERSION.patch,
            t0
        );
        rt.timer().sleep(Duration::from_millis(10));
        let t1 = rt.clock().now();
        let dt = t1.saturating_duration_since(t0);
        println!("{} ran for ~{} ms", Self::NAME, dt.millis);
        Ok(())
    }
}

fn main() {
    let rt = StdRuntime::new();
    let mut ctx = InitCtx;
    let mut m = MyModule::init(&mut ctx, ()).expect("init");
    m.start(&rt).expect("start");
}
