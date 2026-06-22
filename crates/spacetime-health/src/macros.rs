//! Declarative macros for health snapshot construction.

/// Create a `HealthSnapshot` with a given status, since instant, and uptime duration.
///
/// # Examples
///
/// ```ignore
/// use spacetime_health::health_snapshot;
/// use spacetime_core::{Duration, Instant};
///
/// let since = Instant::from_millis_since_epoch(1000);
/// let uptime = Duration::from_secs(60);
///
/// let healthy = health_snapshot!(healthy, since, uptime);
/// let degraded = health_snapshot!(degraded, since, uptime);
/// let unhealthy = health_snapshot!(unhealthy, since, uptime);
/// ```
#[macro_export]
macro_rules! health_snapshot {
    (healthy, $since:expr, $uptime:expr) => {
        $crate::HealthSnapshot::healthy($since, $uptime)
    };
    (degraded, $since:expr, $uptime:expr) => {
        $crate::HealthSnapshot::degraded($since, $uptime)
    };
    (unhealthy, $since:expr, $uptime:expr) => {
        $crate::HealthSnapshot::unhealthy($since, $uptime)
    };
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::{HealthSnapshot, HealthStatus};
    use spacetime_core::{Duration, Instant};

    #[test]
    fn health_snapshot_macro_healthy() {
        let since = Instant::from_millis_since_epoch(100);
        let uptime = Duration::from_millis(500);
        let snap: HealthSnapshot = health_snapshot!(healthy, since, uptime);
        assert_eq!(snap.status, HealthStatus::Healthy);
        assert_eq!(snap.since.millis_since_epoch, 100);
        assert_eq!(snap.uptime.millis, 500);
    }

    #[test]
    fn health_snapshot_macro_degraded() {
        let since = Instant::from_millis_since_epoch(200);
        let uptime = Duration::from_secs(10);
        let snap: HealthSnapshot = health_snapshot!(degraded, since, uptime);
        assert_eq!(snap.status, HealthStatus::Degraded);
    }

    #[test]
    fn health_snapshot_macro_unhealthy() {
        let since = Instant::from_millis_since_epoch(300);
        let uptime = Duration::from_millis(0);
        let snap: HealthSnapshot = health_snapshot!(unhealthy, since, uptime);
        assert_eq!(snap.status, HealthStatus::Unhealthy);
    }
}
