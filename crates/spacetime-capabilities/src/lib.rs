#![no_std]

//! Minimal capability identity and metadata types for Spacetime.
//!
//! Scope:
//! - Identity-only: capability identifiers and simple descriptors.
//! - No resolver/semver range logic; Airframe (or other runtimes) can own that.
//! - no_std-first; optional `alloc` for owned metadata and `serde` for serialization.

#[cfg(feature = "alloc")]
extern crate alloc;

// Link std for tests/examples when requested
#[cfg(feature = "std")]
extern crate std;

use spacetime_core::Version;

/// Stable identity for a capability, typically a reverse-DNS or namespaced string.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub struct CapabilityId(pub &'static str);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub id: CapabilityId,
    pub provider_name: &'static str,
    pub provider_version: Version,
}

// Manual Serialize to avoid requiring serde on spacetime_core::Version
#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use serde::ser::{Serialize, SerializeStruct, Serializer};

    struct VersionSer<'a>(&'a Version);
    impl<'a> Serialize for VersionSer<'a> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut st = serializer.serialize_struct("Version", 3)?;
            st.serialize_field("major", &self.0.major)?;
            st.serialize_field("minor", &self.0.minor)?;
            st.serialize_field("patch", &self.0.patch)?;
            st.end()
        }
    }

    impl Serialize for Capability {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut st = serializer.serialize_struct("Capability", 3)?;
            st.serialize_field("id", &self.id)?;
            st.serialize_field("provider_name", &self.provider_name)?;
            st.serialize_field("provider_version", &VersionSer(&self.provider_version))?;
            st.end()
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMeta {
    pub key: alloc::borrow::Cow<'static, str>,
    pub value: alloc::borrow::Cow<'static, str>,
}

/// Optional descriptor a module can expose for its provided/required capabilities.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleCapabilities<'a> {
    pub provides: &'a [CapabilityId],
    pub requires: &'a [CapabilityId],
}

impl CapabilityId {
    /// Convenience constructor.
    pub const fn new(s: &'static str) -> Self {
        Self(s)
    }
}

impl Capability {
    pub const fn new(
        id: CapabilityId,
        provider_name: &'static str,
        provider_version: Version,
    ) -> Self {
        Self {
            id,
            provider_name,
            provider_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_const_works() {
        const CAP: CapabilityId = CapabilityId::new("airframe:scheduler");
        assert_eq!(CAP.0, "airframe:scheduler");
    }

    #[test]
    fn module_caps_lifetimes() {
        const A: CapabilityId = CapabilityId("a");
        const B: CapabilityId = CapabilityId("b");
        let caps = ModuleCapabilities {
            provides: &[A],
            requires: &[B],
        };
        assert_eq!(caps.provides.len(), 1);
        assert_eq!(caps.requires.len(), 1);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_serialize_capability() {
        let cap = Capability::new(CapabilityId("x"), "prov", Version::new(1, 2, 3));
        let s = serde_json::to_string(&cap).unwrap();
        assert!(s.contains("\"prov\""));
    }

    #[cfg(all(feature = "serde", feature = "alloc"))]
    #[test]
    fn serde_roundtrip_meta() {
        let m = CapabilityMeta {
            key: alloc::borrow::Cow::from("k"),
            value: alloc::borrow::Cow::from("v"),
        };
        let s = serde_json::to_string(&m).unwrap();
        let de: CapabilityMeta = serde_json::from_str(&s).unwrap();
        assert_eq!(m, de);
    }
}
