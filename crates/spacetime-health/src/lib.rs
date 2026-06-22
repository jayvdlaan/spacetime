#![no_std]

//! Portable health snapshot types shared across runtimes.
//! - no_std-first
//! - optional `alloc` for notes Vec
//! - optional `serde` for serialization

// Declarative macros are exported via #[macro_export] and available at crate root
mod macros;

#[cfg(feature = "alloc")]
extern crate alloc;

use core::marker::PhantomData;
use spacetime_core::{Duration, Instant, Status};

#[cfg(all(feature = "alloc", feature = "serde"))]
use alloc::borrow::Cow;

// Note element type for notes vector (alloc only)
#[cfg(all(feature = "alloc", feature = "serde"))]
type Note<'a> = Cow<'a, str>;
#[cfg(all(feature = "alloc", not(feature = "serde")))]
type Note<'a> = &'a str;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct HealthSnapshot<'a> {
    pub status: HealthStatus,
    #[cfg_attr(feature = "serde", serde(with = "instant_millis"))]
    pub since: Instant,
    #[cfg_attr(feature = "serde", serde(with = "duration_millis"))]
    pub uptime: Duration,
    #[cfg(feature = "alloc")]
    pub notes: alloc::vec::Vec<Note<'a>>,
    #[cfg_attr(feature = "serde", serde(skip))]
    phantom: PhantomData<&'a ()>,
}

impl<'a> HealthSnapshot<'a> {
    pub const fn healthy(since: Instant, uptime: Duration) -> Self {
        Self {
            status: HealthStatus::Healthy,
            since,
            uptime,
            #[cfg(feature = "alloc")]
            notes: alloc::vec::Vec::new(),
            phantom: PhantomData,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn degraded_with_notes(
        since: Instant,
        uptime: Duration,
        notes: alloc::vec::Vec<Note<'a>>,
    ) -> Self {
        Self {
            status: HealthStatus::Degraded,
            since,
            uptime,
            notes,
            phantom: PhantomData,
        }
    }

    pub const fn degraded(since: Instant, uptime: Duration) -> Self {
        Self {
            status: HealthStatus::Degraded,
            since,
            uptime,
            #[cfg(feature = "alloc")]
            notes: alloc::vec::Vec::new(),
            phantom: PhantomData,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn unhealthy_with_notes(
        since: Instant,
        uptime: Duration,
        notes: alloc::vec::Vec<Note<'a>>,
    ) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            since,
            uptime,
            notes,
            phantom: PhantomData,
        }
    }

    pub const fn unhealthy(since: Instant, uptime: Duration) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            since,
            uptime,
            #[cfg(feature = "alloc")]
            notes: alloc::vec::Vec::new(),
            phantom: PhantomData,
        }
    }
}

// Convenience conversion from core Status to HealthStatus
impl From<Status> for HealthStatus {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok => HealthStatus::Healthy,
            Status::Unsupported
            | Status::Unavailable
            | Status::Denied
            | Status::Invalid
            | Status::Failed => HealthStatus::Unhealthy,
        }
    }
}

// serde helpers to encode Instant/Duration as u64 millis
#[cfg(feature = "serde")]
mod instant_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use spacetime_core::Instant;

    pub fn serialize<S: Serializer>(v: &Instant, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(v.millis_since_epoch)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Instant, D::Error> {
        let ms = u64::deserialize(d)?;
        Ok(Instant {
            millis_since_epoch: ms,
        })
    }
}

#[cfg(feature = "serde")]
mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use spacetime_core::Duration;

    pub fn serialize<S: Serializer>(v: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(v.millis)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = u64::deserialize(d)?;
        Ok(Duration { millis: ms })
    }
}

// No manual serde impls needed; derive handles it, with custom (de)serializers for Instant/Duration

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;

    #[test]
    fn constructors_work() {
        let t0 = Instant::from_millis_since_epoch(1);
        let up = Duration::from_millis(2);
        let h = HealthSnapshot::healthy(t0, up);
        assert!(matches!(h.status, HealthStatus::Healthy));
        let d = HealthSnapshot::degraded(t0, up);
        assert!(matches!(d.status, HealthStatus::Degraded));
        let u = HealthSnapshot::unhealthy(t0, up);
        assert!(matches!(u.status, HealthStatus::Unhealthy));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn notes_lifetime_and_contents() {
        let t0 = Instant::from_millis_since_epoch(10);
        let up = Duration::from_millis(20);
        let mut notes: alloc::vec::Vec<Note<'static>> =
            alloc::vec![Note::from("a"), Note::from("b")];
        notes.push(Note::from("c"));
        let snap = HealthSnapshot::degraded_with_notes(t0, up, notes);
        assert_eq!(snap.uptime.as_millis(), 20);
        assert_eq!(snap.since.millis_since_epoch, 10);
        assert!(matches!(snap.status, HealthStatus::Degraded));
        assert_eq!(snap.notes.len(), 3);
    }

    #[test]
    fn status_to_health_status_conversion() {
        use spacetime_core::Status;
        assert_eq!(HealthStatus::from(Status::Ok), HealthStatus::Healthy);
        assert_eq!(
            HealthStatus::from(Status::Unsupported),
            HealthStatus::Unhealthy
        );
        assert_eq!(
            HealthStatus::from(Status::Unavailable),
            HealthStatus::Unhealthy
        );
        assert_eq!(HealthStatus::from(Status::Denied), HealthStatus::Unhealthy);
        assert_eq!(HealthStatus::from(Status::Invalid), HealthStatus::Unhealthy);
        assert_eq!(HealthStatus::from(Status::Failed), HealthStatus::Unhealthy);
    }

    #[test]
    fn health_status_equality_and_debug() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Degraded);
        assert_ne!(HealthStatus::Degraded, HealthStatus::Unhealthy);
        assert_eq!(format!("{:?}", HealthStatus::Degraded), "Degraded");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn unhealthy_with_notes_constructor() {
        let t0 = Instant::from_millis_since_epoch(100);
        let up = Duration::from_millis(50);
        let notes = alloc::vec![Note::from("disk full"), Note::from("oom")];
        let snap = HealthSnapshot::unhealthy_with_notes(t0, up, notes);
        assert!(matches!(snap.status, HealthStatus::Unhealthy));
        assert_eq!(snap.notes.len(), 2);
    }

    #[cfg(all(feature = "serde", feature = "alloc"))]
    #[test]
    fn serde_roundtrip() {
        let t0 = Instant::from_millis_since_epoch(42);
        let up = Duration::from_secs(5);
        #[cfg(feature = "serde")]
        let snap = HealthSnapshot::unhealthy_with_notes(
            t0,
            up,
            alloc::vec![Note::from("x"), Note::from("y")],
        );
        let s = serde_json::to_string(&snap).unwrap();
        let de: HealthSnapshot = serde_json::from_str(&s).unwrap();
        assert!(matches!(de.status, HealthStatus::Unhealthy));
        assert_eq!(de.uptime.as_secs(), 5);
        assert_eq!(de.since.millis_since_epoch, 42);
        assert_eq!(de.notes.len(), 2);
    }
}
