use spacetime_capabilities as scaps;
use spacetime_core::Version;

#[test]
fn capability_id_and_module_caps() {
    const A: scaps::CapabilityId = scaps::CapabilityId::new("a:b");
    const B: scaps::CapabilityId = scaps::CapabilityId("c:d");
    let caps = scaps::ModuleCapabilities {
        provides: &[A],
        requires: &[B],
    };
    assert_eq!(caps.provides.len(), 1);
    assert_eq!(caps.requires[0].0, "c:d");

    let cap = scaps::Capability::new(A, "prov", Version::new(0, 1, 0));
    assert_eq!(cap.provider_name, "prov");
}
