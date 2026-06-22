spacetime-std-runtime
=====================

Std-backed implementations of the Spacetime core runtime traits. This crate provides:

- StdClock: implements spacetime_core::Clock using std::time::SystemTime
- StdTimer: implements spacetime_core::Timer using std::thread::sleep
- StdRuntime: a tiny runtime that exposes StdClock and StdTimer

Scope and notes
- This crate is std-only by design. It adapts the no_std-first primitives from spacetime-core to standard library types. There is no no_std mode here.
- Feature flags: default = ["std"].

Examples
```rust
use spacetime_core::{Module as StModule, Version as StVersion, InitCtx as StInitCtx, InitError as StInitError, StartError as StStartError, Duration as StDuration};
use spacetime_std_runtime::StdRuntime;

struct Dummy;

impl StModule for Dummy {
    const NAME: &'static str = "dummy";
    const VERSION: StVersion = StVersion { major: 0, minor: 1, patch: 0 };
    type Deps<'a> = ();

    fn init(_ctx: &mut StInitCtx, _deps: Self::Deps<'_>) -> Result<Self, StInitError> { Ok(Dummy) }

    fn start(&mut self, rt: &dyn spacetime_core::Runtime) -> Result<(), StStartError> {
        let t0 = rt.clock().now();
        rt.timer().sleep(StDuration::from_millis(1));
        let _t1 = rt.clock().now();
        Ok(())
    }
}

fn main() {
    let rt = StdRuntime::new();
    let mut ctx = StInitCtx;
    let mut m = Dummy::init(&mut ctx, ()).unwrap();
    m.start(&rt).unwrap();
}
```

Airframe re-export
- Airframe re-exports these types under `airframe_core::spacetime_adapter::*` to preserve existing import paths during migration.

License
Licensed under MIT.
