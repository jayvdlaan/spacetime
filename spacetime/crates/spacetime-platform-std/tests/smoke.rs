use spacetime_platform_std::StdRuntime;
use spacetime_core::{Duration, Runtime};

#[test]
fn std_runtime_clock_and_timer() {
    let rt = StdRuntime::new();
    let t0 = rt.clock().now();
    rt.timer().sleep(Duration::from_millis(1));
    let t1 = rt.clock().now();
    assert!(t1.millis_since_epoch >= t0.millis_since_epoch);
}
