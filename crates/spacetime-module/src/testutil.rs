//! Shared test utilities for spacetime-module tests.
//!
//! This module is gated on `feature = "std"` and hidden from documentation.
//! It provides helpers used by both unit tests and integration tests to avoid
//! duplicating `mk_node` and `noop` stubs everywhere.

use crate::{ModuleDescriptor, ModuleNode};
use spacetime_core::{InitCtx, InitError, Version};

/// No-op init function for test module nodes.
pub fn noop(_ctx: &mut InitCtx) -> Result<(), InitError> {
    Ok(())
}

/// Create a [`ModuleNode`] with the given name and dependency list, using a
/// no-op init function and no start hook.  Useful for graph-algorithm tests
/// that only care about topology.
pub fn mk_node(name: &'static str, deps: &'static [&'static str]) -> ModuleNode {
    ModuleNode {
        descriptor: ModuleDescriptor::new(name, Version::new(0, 1, 0)),
        init: noop,
        deps,
        start: None,
    }
}
