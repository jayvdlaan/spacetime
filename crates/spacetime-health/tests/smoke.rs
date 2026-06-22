use spacetime_core::{Duration, Instant};
use spacetime_health::{HealthSnapshot, HealthStatus};

#[test]
fn construct_snapshots() {
    let t0 = Instant::from_millis_since_epoch(10);
    let up = Duration::from_millis(20);
    let h = HealthSnapshot::healthy(t0, up);
    assert!(matches!(h.status, HealthStatus::Healthy));
    let d = HealthSnapshot::degraded(t0, up);
    assert!(matches!(d.status, HealthStatus::Degraded));
    let u = HealthSnapshot::unhealthy(t0, up);
    assert!(matches!(u.status, HealthStatus::Unhealthy));
}
