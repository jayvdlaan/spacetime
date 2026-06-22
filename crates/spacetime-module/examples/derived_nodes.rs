// Run with: cargo run -p spacetime-module --example derived_nodes --features std

#![cfg(feature = "std")]

use spacetime_macros::spacetime_module;
use spacetime_module::core::{InitCtx as CoreInitCtx, InitError as CoreInitError, Version};
use spacetime_module::{topo_sort_indices, ModuleDescriptor, ModuleGraph, ModuleNode, SortedNodes};

fn noop(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
    Ok(())
}

#[spacetime_module(name = "A", version = "0.1.0")]
struct A;

#[spacetime_module(name = "B", version = "0.1.0", deps("A"))]
struct B;

fn main() {
    // Build nodes using macro-generated constants on A/B
    let a = ModuleNode {
        descriptor: ModuleDescriptor::new(
            A::ST_NAME,
            Version::new(
                A::ST_VERSION.major,
                A::ST_VERSION.minor,
                A::ST_VERSION.patch,
            ),
        ),
        init: noop,
        deps: A::ST_DEPS,
        start: None,
    };
    let b = ModuleNode {
        descriptor: ModuleDescriptor::new(
            B::ST_NAME,
            Version::new(
                B::ST_VERSION.major,
                B::ST_VERSION.minor,
                B::ST_VERSION.patch,
            ),
        ),
        init: noop,
        deps: B::ST_DEPS,
        start: None,
    };
    let nodes = [a, b];
    let g = ModuleGraph::new(&nodes);
    let mut idx = [0usize; 8];
    let n = topo_sort_indices(&g, &mut idx).unwrap();
    let it = SortedNodes::new(&g, &idx[..n]);
    for node in it {
        println!("{}", node.descriptor.name);
    }
}
