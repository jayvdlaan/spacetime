// Run with: cargo run -p spacetime-module --example order_print --features std

#![cfg(feature = "std")]

use spacetime_module::core::Version;
use spacetime_module::core::{InitCtx as CoreInitCtx, InitError as CoreInitError};
use spacetime_module::{topo_sort_indices, ModuleDescriptor, ModuleGraph, ModuleNode};

fn noop(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
    Ok(())
}

fn main() {
    // Build a small graph: A -> B, A -> C, B -> D, C -> D
    let nodes = [
        ModuleNode {
            descriptor: ModuleDescriptor::new("A", Version::new(0, 1, 0)),
            init: noop,
            deps: &[],
            start: None,
        },
        ModuleNode {
            descriptor: ModuleDescriptor::new("B", Version::new(0, 1, 0)),
            init: noop,
            deps: &["A"],
            start: None,
        },
        ModuleNode {
            descriptor: ModuleDescriptor::new("C", Version::new(0, 1, 0)),
            init: noop,
            deps: &["A"],
            start: None,
        },
        ModuleNode {
            descriptor: ModuleDescriptor::new("D", Version::new(0, 1, 0)),
            init: noop,
            deps: &["B", "C"],
            start: None,
        },
    ];
    let g = ModuleGraph::new(&nodes);
    let mut out = [0usize; 8];
    let n = topo_sort_indices(&g, &mut out).expect("topo sort succeeds");
    println!("Order:");
    for &idx in &out[..n] {
        println!("  {}", nodes[idx].descriptor.name);
    }
}
