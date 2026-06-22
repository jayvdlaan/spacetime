// Run with: cargo run -p spacetime-module --example order_iter --features std

#![cfg(feature = "std")]

use spacetime_module::core::Version;
use spacetime_module::core::{InitCtx as CoreInitCtx, InitError as CoreInitError};
use spacetime_module::{topo_sort_indices, ModuleDescriptor, ModuleGraph, ModuleNode, SortedNodes};

fn noop(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
    Ok(())
}

fn main() {
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
    let mut idx = [0usize; 8];
    let n = topo_sort_indices(&g, &mut idx).unwrap();
    let view = SortedNodes::new(&g, &idx[..n]);
    println!("Order (via iterator):");
    for node in view {
        println!("  {}", node.descriptor.name);
    }
}
