use spacetime_core::{Duration, Instant, Version};

#[test]
fn duration_instant_version_basics() {
    let v = Version::new(1, 2, 3);
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);

    let t0 = Instant::from_millis_since_epoch(100);
    let d = Duration::from_millis(50);
    let t1 = t0.saturating_add(d);
    assert_eq!(t1.millis_since_epoch, 150);
    assert_eq!(t1.saturating_duration_since(t0).millis, 50);
}
