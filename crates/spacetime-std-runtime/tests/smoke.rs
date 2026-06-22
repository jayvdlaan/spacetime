use spacetime_core::{Duration, Runtime};
use spacetime_std_runtime::StdRuntime;

#[test]
fn clock_and_timer_smoke() {
    let rt = StdRuntime::new();
    let t0 = rt.clock().now();
    rt.timer().sleep(Duration::from_millis(1));
    let t1 = rt.clock().now();
    assert!(t1.millis_since_epoch >= t0.millis_since_epoch);
}
