extern crate std as rust_std;
use super::*;

#[test]
fn duration_and_instant_ops() {
    let t0 = Instant::from_millis_since_epoch(1000);
    let t1 = t0.saturating_add(Duration::from_millis(500));
    assert_eq!(t1.millis_since_epoch, 1500);
    assert_eq!(t1.saturating_duration_since(t0).millis, 500);
    // from_secs / as_secs
    let d = Duration::from_secs(2);
    assert_eq!(d.as_millis(), 2000);
    assert_eq!(d.as_secs(), 2);
    // saturating_sub
    let t2 = t0.saturating_sub(Duration::from_millis(1500));
    assert_eq!(t2.millis_since_epoch, 0);
}

// Version tests

#[test]
fn version_new() {
    let v = Version::new(1, 2, 3);
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
}

#[test]
fn version_ord() {
    let v1 = Version::new(1, 0, 0);
    let v2 = Version::new(1, 1, 0);
    let v3 = Version::new(1, 1, 1);
    let v4 = Version::new(2, 0, 0);

    assert!(v1 < v2);
    assert!(v2 < v3);
    assert!(v3 < v4);
    assert!(v1 < v4);
    assert_eq!(v1, v1);
}

#[test]
fn version_hash() {
    use rust_std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(Version::new(1, 0, 0));
    set.insert(Version::new(1, 0, 0)); // duplicate
    assert_eq!(set.len(), 1);
}

// Duration tests

#[test]
fn duration_zero() {
    let d = Duration::zero();
    assert_eq!(d.millis, 0);
    assert_eq!(d.as_millis(), 0);
    assert_eq!(d.as_secs(), 0);
}

#[test]
fn duration_from_millis() {
    let d = Duration::from_millis(1500);
    assert_eq!(d.millis, 1500);
    assert_eq!(d.as_millis(), 1500);
    assert_eq!(d.as_secs(), 1);
}

#[test]
fn duration_from_secs_overflow() {
    // Large value that might overflow
    let d = Duration::from_secs(u64::MAX / 1000);
    assert!(d.millis > 0);
}

#[test]
fn duration_from_secs_saturating() {
    // This should saturate on multiplication
    let d = Duration::from_secs(u64::MAX);
    assert_eq!(d.millis, u64::MAX);
}

#[test]
fn duration_ord() {
    let d1 = Duration::from_millis(100);
    let d2 = Duration::from_millis(200);
    assert!(d1 < d2);
    assert!(d2 > d1);
    assert_eq!(d1, Duration::from_millis(100));
}

// Instant tests

#[test]
fn instant_from_millis() {
    let i = Instant::from_millis_since_epoch(5000);
    assert_eq!(i.millis_since_epoch, 5000);
}

#[test]
fn instant_saturating_add() {
    let i = Instant::from_millis_since_epoch(1000);
    let i2 = i.saturating_add(Duration::from_millis(500));
    assert_eq!(i2.millis_since_epoch, 1500);
}

#[test]
fn instant_saturating_add_overflow() {
    let i = Instant::from_millis_since_epoch(u64::MAX - 10);
    let i2 = i.saturating_add(Duration::from_millis(100));
    assert_eq!(i2.millis_since_epoch, u64::MAX);
}

#[test]
fn instant_saturating_sub() {
    let i = Instant::from_millis_since_epoch(1000);
    let i2 = i.saturating_sub(Duration::from_millis(300));
    assert_eq!(i2.millis_since_epoch, 700);
}

#[test]
fn instant_saturating_sub_underflow() {
    let i = Instant::from_millis_since_epoch(100);
    let i2 = i.saturating_sub(Duration::from_millis(500));
    assert_eq!(i2.millis_since_epoch, 0);
}

#[test]
fn instant_saturating_duration_since() {
    let i1 = Instant::from_millis_since_epoch(1000);
    let i2 = Instant::from_millis_since_epoch(1500);
    let d = i2.saturating_duration_since(i1);
    assert_eq!(d.millis, 500);
}

#[test]
fn instant_saturating_duration_since_reverse() {
    // If earlier is after self, should return zero
    let i1 = Instant::from_millis_since_epoch(1500);
    let i2 = Instant::from_millis_since_epoch(1000);
    let d = i2.saturating_duration_since(i1);
    assert_eq!(d.millis, 0);
}

#[test]
fn instant_ord() {
    let i1 = Instant::from_millis_since_epoch(100);
    let i2 = Instant::from_millis_since_epoch(200);
    assert!(i1 < i2);
    assert!(i2 > i1);
}

// Status tests

#[test]
fn status_variants() {
    // Just ensure all variants exist
    let _ = Status::Ok;
    let _ = Status::Unsupported;
    let _ = Status::Unavailable;
    let _ = Status::Denied;
    let _ = Status::Invalid;
    let _ = Status::Failed;
}

#[test]
fn status_eq() {
    assert_eq!(Status::Ok, Status::Ok);
    assert_ne!(Status::Ok, Status::Failed);
}

// Error conversion tests

#[test]
fn status_to_init_error() {
    assert_eq!(InitError::from(Status::Unsupported), InitError::Unsupported);
    assert_eq!(InitError::from(Status::Denied), InitError::Denied);
    assert_eq!(InitError::from(Status::Invalid), InitError::Invalid);
    assert_eq!(InitError::from(Status::Failed), InitError::Failed);
    assert_eq!(InitError::from(Status::Unavailable), InitError::Failed);
    assert_eq!(InitError::from(Status::Ok), InitError::Invalid);
}

#[test]
fn status_to_start_error() {
    assert_eq!(
        StartError::from(Status::Unavailable),
        StartError::Unavailable
    );
    assert_eq!(StartError::from(Status::Failed), StartError::Failed);
    assert_eq!(StartError::from(Status::Ok), StartError::Failed);
    assert_eq!(StartError::from(Status::Unsupported), StartError::Failed);
    assert_eq!(StartError::from(Status::Denied), StartError::Failed);
    assert_eq!(StartError::from(Status::Invalid), StartError::Failed);
}

// InitError/StartError tests

#[test]
fn init_error_variants() {
    let _ = InitError::Unsupported;
    let _ = InitError::Denied;
    let _ = InitError::Invalid;
    let _ = InitError::Failed;
}

#[test]
fn start_error_variants() {
    let _ = StartError::Unavailable;
    let _ = StartError::Failed;
}

#[test]
fn init_error_debug() {
    let e = InitError::Failed;
    let s = rust_std::format!("{:?}", e);
    assert!(s.contains("Failed"));
}

#[test]
fn start_error_debug() {
    let e = StartError::Failed;
    let s = rust_std::format!("{:?}", e);
    assert!(s.contains("Failed"));
}

// MonotonicInstant tests

#[test]
fn monotonic_instant_from_ticks() {
    let m = MonotonicInstant::from_ticks_ms(42);
    assert_eq!(m.ticks_ms, 42);
}

#[test]
fn monotonic_instant_saturating_add() {
    let m = MonotonicInstant::from_ticks_ms(1000);
    let m2 = m.saturating_add(Duration::from_millis(500));
    assert_eq!(m2.ticks_ms, 1500);
}

#[test]
fn monotonic_instant_saturating_add_overflow() {
    let m = MonotonicInstant::from_ticks_ms(u64::MAX - 10);
    let m2 = m.saturating_add(Duration::from_millis(100));
    assert_eq!(m2.ticks_ms, u64::MAX);
}

#[test]
fn monotonic_instant_saturating_sub() {
    let m = MonotonicInstant::from_ticks_ms(1000);
    let m2 = m.saturating_sub(Duration::from_millis(300));
    assert_eq!(m2.ticks_ms, 700);
}

#[test]
fn monotonic_instant_saturating_sub_underflow() {
    let m = MonotonicInstant::from_ticks_ms(100);
    let m2 = m.saturating_sub(Duration::from_millis(500));
    assert_eq!(m2.ticks_ms, 0);
}

#[test]
fn monotonic_instant_saturating_duration_since() {
    let m1 = MonotonicInstant::from_ticks_ms(1000);
    let m2 = MonotonicInstant::from_ticks_ms(1500);
    let d = m2.saturating_duration_since(m1);
    assert_eq!(d.millis, 500);
}

#[test]
fn monotonic_instant_saturating_duration_since_reverse() {
    let m1 = MonotonicInstant::from_ticks_ms(1500);
    let m2 = MonotonicInstant::from_ticks_ms(1000);
    let d = m2.saturating_duration_since(m1);
    assert_eq!(d.millis, 0);
}

#[test]
fn monotonic_instant_ord() {
    let m1 = MonotonicInstant::from_ticks_ms(100);
    let m2 = MonotonicInstant::from_ticks_ms(200);
    assert!(m1 < m2);
    assert!(m2 > m1);
    assert_eq!(m1, MonotonicInstant::from_ticks_ms(100));
}

// MonotonicClock trait test (with a simple fake impl)

#[test]
fn monotonic_clock_elapsed_since_default() {
    struct FakeMono(MonotonicInstant);
    impl MonotonicClock for FakeMono {
        fn now_monotonic(&self) -> MonotonicInstant {
            self.0
        }
    }

    let clock = FakeMono(MonotonicInstant::from_ticks_ms(2000));
    let earlier = MonotonicInstant::from_ticks_ms(1500);
    let elapsed = clock.elapsed_since(earlier);
    assert_eq!(elapsed.millis, 500);
}
