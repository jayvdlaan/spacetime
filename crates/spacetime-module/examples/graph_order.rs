// Run with: cargo run -p spacetime-module --example graph_order --features std

use sm::core::{InitCtx as CoreInitCtx, InitError as CoreInitError, Version};
use spacetime_module as sm;

fn init_a(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
    println!("init A");
    Ok(())
}

fn init_b(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
    println!("init B");
    Ok(())
}

fn main() {
    let nodes = [
        sm::ModuleNode {
            descriptor: sm::ModuleDescriptor::new("A", Version::new(0, 1, 0)),
            init: init_a,
            deps: &[],
            start: None,
        },
        sm::ModuleNode {
            descriptor: sm::ModuleDescriptor::new("B", Version::new(0, 1, 0)),
            init: init_b,
            deps: &["A"],
            start: None,
        },
    ];

    let graph = sm::ModuleGraph::new(&nodes);
    let ordered = sm::topo_order(&graph).expect("order");
    let mut ctx = CoreInitCtx;
    for n in ordered {
        println!(
            "initializing {} v{}.{}.{}",
            n.descriptor.name,
            n.descriptor.version.major,
            n.descriptor.version.minor,
            n.descriptor.version.patch
        );
        (n.init)(&mut ctx).expect("init node");
    }
}
