// Simple integration test for the spacetime_module attribute macro.
// Uses spacetime-module types at test time only.

use spacetime_macros::spacetime_module;
use spacetime_module::core::{InitCtx, InitError, Runtime, StartError};

#[spacetime_module(name = "demo", version = "0.1.2", deps("a", "b"))]
struct MyMod;

#[test]
fn macro_generates_constants() {
    // Constants are added as inherent impl on the struct
    assert_eq!(MyMod::ST_NAME, "demo");
    assert_eq!(MyMod::ST_VERSION.major, 0);
    assert_eq!(MyMod::ST_VERSION.minor, 1);
    assert_eq!(MyMod::ST_VERSION.patch, 2);
    assert_eq!(MyMod::ST_DEPS.len(), 2);
    assert_eq!(MyMod::ST_DEPS[0], "a");
    assert_eq!(MyMod::ST_DEPS[1], "b");
}

fn test_init(_ctx: &mut InitCtx) -> Result<(), InitError> {
    Ok(())
}

fn test_start(_rt: &dyn Runtime) -> Result<(), StartError> {
    Ok(())
}

#[test]
fn to_node_without_start() {
    let node = MyMod::to_node(test_init);
    assert_eq!(node.descriptor.name, "demo");
    assert_eq!(node.descriptor.version.major, 0);
    assert_eq!(node.descriptor.version.minor, 1);
    assert_eq!(node.descriptor.version.patch, 2);
    assert_eq!(node.deps, &["a", "b"]);
    assert!(node.start.is_none());
}

#[test]
fn to_node_with_start() {
    let node = MyMod::to_node_with_start(test_init, test_start);
    assert_eq!(node.descriptor.name, "demo");
    assert_eq!(node.deps, &["a", "b"]);
    assert!(node.start.is_some());
}
