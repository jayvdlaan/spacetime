//!
//! This crate builds on spacetime-core to provide lightweight descriptors
//! and a minimal API surface for constructing module graphs. Deterministic
//! ordering APIs are declared but intentionally left with placeholder
//! implementations for now.

#![cfg_attr(not(feature = "std"), no_std)]

// Declarative macros are exported via #[macro_export] and available at crate root
mod macros;

// Internal modules
mod graph;
mod runner;
mod types;

// Link alloc for richer diagnostics and helpers
#[cfg(feature = "alloc")]
extern crate alloc;

// Link std when feature enabled (for tests/examples)
#[cfg(feature = "std")]
extern crate std;

// Re-export core items for convenience
pub use spacetime_core as core;

// Re-export all public types
pub use types::{
    Describe, GraphError, ModuleDescriptor, ModuleGraph, ModuleNode, RunError, SortedNodes,
    StartCtx,
};

// Re-export graph algorithms
#[cfg(feature = "alloc")]
pub use graph::{find_cycle, topo_check_with_report};
pub use graph::{topo_order, topo_sort_indices};

// Re-export runner
pub use runner::run_init_start;

/// Shared test utilities (`mk_node`, `noop`, etc.) for module-graph tests.
///
/// Available only when the `std` feature is enabled.
#[cfg(feature = "std")]
#[doc(hidden)]
pub mod testutil;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::testutil::mk_node;
    use spacetime_core::{
        InitCtx as CoreInitCtx, InitError as CoreInitError, Runtime as CoreRuntime,
        StartError as CoreStartError, Version,
    };

    #[test]
    fn topo_order_validates_declared_order() {
        let nodes = [
            mk_node("A", &[]),
            mk_node("B", &["A"]),
            mk_node("C", &["A", "B"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let ordered = topo_order(&g).unwrap();
        assert_eq!(ordered[0].descriptor.name, "A");
        assert_eq!(ordered[1].descriptor.name, "B");
        assert_eq!(ordered[2].descriptor.name, "C");
    }

    #[test]
    fn topo_order_detects_cycle_in_declared_order() {
        let nodes = [
            mk_node("B", &["A"]), // B depends on A but appears before A
            mk_node("A", &[]),
        ];
        let g = ModuleGraph::new(&nodes);
        let err = topo_order(&g).unwrap_err();
        #[cfg(feature = "alloc")]
        {
            assert!(matches!(err, GraphError::Cyclic { .. }));
        }
        #[cfg(not(feature = "alloc"))]
        {
            assert!(matches!(err, GraphError::Cyclic));
        }
    }

    #[test]
    fn topo_order_unknown_dependency() {
        let nodes = [mk_node("A", &["Z"])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_order(&g).unwrap_err();
        assert!(matches!(err, GraphError::UnknownDependency));
    }

    #[test]
    fn topo_sort_indices_handles_diamond() {
        // A -> B, A -> C, B -> D, C -> D
        let nodes = [
            mk_node("A", &[]),
            mk_node("B", &["A"]),
            mk_node("C", &["A"]),
            mk_node("D", &["B", "C"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 8];
        let n = topo_sort_indices(&g, &mut out).unwrap();
        assert_eq!(n, 4);
        // Validate order respects deps
        let pos = |name: &str| -> usize {
            (0..n)
                .find(|&k| nodes[out[k]].descriptor.name == name)
                .unwrap()
        };
        assert!(pos("A") < pos("B"));
        assert!(pos("A") < pos("C"));
        assert!(pos("B") < pos("D"));
        assert!(pos("C") < pos("D"));
    }

    #[test]
    fn topo_sort_indices_multiple_roots() {
        // A and X are roots; both go into Y
        let nodes = [
            mk_node("A", &[]),
            mk_node("X", &[]),
            mk_node("Y", &["A", "X"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 8];
        let n = topo_sort_indices(&g, &mut out).unwrap();
        assert_eq!(n, 3);
        let pos = |name: &str| -> usize {
            (0..n)
                .find(|&k| nodes[out[k]].descriptor.name == name)
                .unwrap()
        };
        assert!(pos("A") < pos("Y"));
        assert!(pos("X") < pos("Y"));
    }

    #[test]
    fn topo_sort_indices_detects_cycle() {
        // A -> B, B -> A (cycle)
        let nodes = [mk_node("A", &["B"]), mk_node("B", &["A"])];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 8];
        let err = topo_sort_indices(&g, &mut out).unwrap_err();
        #[cfg(not(feature = "alloc"))]
        assert!(matches!(err, GraphError::Cyclic));
        #[cfg(feature = "alloc")]
        assert!(matches!(err, GraphError::Cyclic { .. }));
    }

    #[test]
    fn topo_sort_indices_unknown_dep() {
        let nodes = [mk_node("A", &["Z"])];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 4];
        let err = topo_sort_indices(&g, &mut out).unwrap_err();
        assert!(matches!(err, GraphError::UnknownDependency));
    }

    #[test]
    fn topo_sort_detects_duplicate_names() {
        let nodes = [mk_node("A", &[]), mk_node("A", &[])];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 4];
        let err = topo_sort_indices(&g, &mut out).unwrap_err();
        assert!(matches!(err, GraphError::DuplicateName));
    }

    #[test]
    fn sorted_nodes_empty_graph() {
        let nodes: [ModuleNode; 0] = [];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 1];
        let n = topo_sort_indices(&g, &mut out).unwrap();
        assert_eq!(n, 0);
        let mut it = SortedNodes::new(&g, &out[..n]);
        assert!(it.next().is_none());
    }

    #[test]
    fn sorted_nodes_iterates_in_order() {
        let nodes = [
            mk_node("A", &[]),
            mk_node("B", &["A"]),
            mk_node("C", &["B"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 4];
        let n = topo_sort_indices(&g, &mut out).unwrap();
        let mut it = SortedNodes::new(&g, &out[..n]);

        // Should iterate in topological order
        let first = it.next().unwrap();
        assert_eq!(first.descriptor.name, "A");

        let second = it.next().unwrap();
        assert_eq!(second.descriptor.name, "B");

        let third = it.next().unwrap();
        assert_eq!(third.descriptor.name, "C");

        assert!(it.next().is_none());
    }

    #[test]
    fn sorted_nodes_with_out_of_bounds_index() {
        let nodes = [mk_node("A", &[])];
        let g = ModuleGraph::new(&nodes);
        // Manually create indices with an out-of-bounds index
        let bad_indices = [0, 5, 10];
        let mut it = SortedNodes::new(&g, &bad_indices);

        // First should work
        assert!(it.next().is_some());
        // Out-of-bounds indices should return None from .get()
        assert!(it.next().is_none());
        assert!(it.next().is_none());
    }

    #[test]
    fn topo_sort_indices_buffer_too_small() {
        let nodes = [
            mk_node("A", &[]),
            mk_node("B", &["A"]),
            mk_node("C", &["B"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let mut out = [0usize; 2]; // Too small for 3 nodes
        let err = topo_sort_indices(&g, &mut out).unwrap_err();
        // Should error (treated as cyclic due to implementation)
        #[cfg(feature = "alloc")]
        assert!(matches!(err, GraphError::Cyclic { .. }));
        #[cfg(not(feature = "alloc"))]
        assert!(matches!(err, GraphError::Cyclic));
    }

    #[test]
    fn module_descriptor_new() {
        let desc = ModuleDescriptor::new("test_mod", Version::new(1, 2, 3));
        assert_eq!(desc.name, "test_mod");
        assert_eq!(desc.version.major, 1);
        assert_eq!(desc.version.minor, 2);
        assert_eq!(desc.version.patch, 3);
    }

    #[test]
    fn graph_error_debug() {
        let err = GraphError::DuplicateName;
        assert_eq!(format!("{:?}", err), "DuplicateName");

        let err2 = GraphError::UnknownDependency;
        assert_eq!(format!("{:?}", err2), "UnknownDependency");
    }

    #[test]
    fn run_error_debug() {
        let err = RunError::InitFailed { count: 2 };
        assert!(format!("{:?}", err).contains("InitFailed"));

        let err2 = RunError::StartFailed { index: 1 };
        assert!(format!("{:?}", err2).contains("StartFailed"));

        let err3 = RunError::Graph(GraphError::DuplicateName);
        assert!(format!("{:?}", err3).contains("Graph"));
    }

    #[test]
    fn topo_order_detects_duplicate_names() {
        let nodes = [mk_node("A", &[]), mk_node("A", &[])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_order(&g).unwrap_err();
        assert!(matches!(err, GraphError::DuplicateName));
    }

    #[test]
    fn graph_error_equality() {
        assert_eq!(GraphError::DuplicateName, GraphError::DuplicateName);
        assert_eq!(GraphError::UnknownDependency, GraphError::UnknownDependency);
        assert_ne!(GraphError::DuplicateName, GraphError::UnknownDependency);
    }

    #[test]
    fn run_error_equality() {
        assert_eq!(
            RunError::InitFailed { count: 1 },
            RunError::InitFailed { count: 1 }
        );
        assert_ne!(
            RunError::InitFailed { count: 1 },
            RunError::InitFailed { count: 2 }
        );
        assert_eq!(
            RunError::StartFailed { index: 0 },
            RunError::StartFailed { index: 0 }
        );
    }

    #[test]
    fn very_long_chain() {
        const N: usize = 64;
        fn noop(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
            Ok(())
        }
        let mut v: alloc::vec::Vec<ModuleNode> = alloc::vec::Vec::with_capacity(N);
        // Build nodes A0..A63 with linear deps
        for i in 0..N {
            let name = alloc::format!("A{}", i);
            let name_static: &'static str = Box::leak(name.into_boxed_str());
            let deps_vec: alloc::vec::Vec<&'static str> = if i == 0 {
                alloc::vec![]
            } else {
                alloc::vec![Box::leak(alloc::format!("A{}", i - 1).into_boxed_str())]
            };
            let deps_slice: &'static [&'static str] = Box::leak(deps_vec.into_boxed_slice());
            v.push(ModuleNode {
                descriptor: ModuleDescriptor::new(name_static, Version::new(0, 1, 0)),
                init: noop,
                deps: deps_slice,
                start: None,
            });
        }
        let g = ModuleGraph::new(&v);
        let mut out = [0usize; N];
        let n = topo_sort_indices(&g, &mut out).unwrap();
        assert_eq!(n, N);
        // Ensure each dep precedes its node
        for i in 1..N {
            let name = alloc::format!("A{}", i);
            let dep = alloc::format!("A{}", i - 1);
            let pos = |s: &str| -> usize {
                (0..N)
                    .find(|&k| g.nodes[out[k]].descriptor.name == s)
                    .unwrap()
            };
            assert!(pos(&dep) < pos(&name));
        }
    }

    #[test]
    fn run_init_start_paths() {
        use spacetime_core::testutil::DummyRuntime;

        fn ok(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
            Ok(())
        }
        fn fail(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
            Err(CoreInitError::Failed)
        }
        fn start_ok(_rt: &dyn CoreRuntime) -> Result<(), CoreStartError> {
            Ok(())
        }
        fn start_fail(_rt: &dyn CoreRuntime) -> Result<(), CoreStartError> {
            Err(CoreStartError::Failed)
        }

        // Case 1: init failure aggregates
        let nodes1 = [
            ModuleNode {
                descriptor: ModuleDescriptor::new("A", Version::new(0, 1, 0)),
                init: fail,
                deps: &[],
                start: Some(start_ok),
            },
            ModuleNode {
                descriptor: ModuleDescriptor::new("B", Version::new(0, 1, 0)),
                init: ok,
                deps: &[],
                start: Some(start_ok),
            },
        ];
        let g1 = ModuleGraph::new(&nodes1);
        let mut idx = [0usize; 4];
        let mut ctx = CoreInitCtx;
        let rt = DummyRuntime;
        let err = run_init_start(&g1, &mut ctx, &rt, &mut idx).unwrap_err();
        assert!(matches!(err, RunError::InitFailed { count: 1 }));

        // Case 2: start failure returns first failing index
        let nodes2 = [
            ModuleNode {
                descriptor: ModuleDescriptor::new("A", Version::new(0, 1, 0)),
                init: ok,
                deps: &[],
                start: Some(start_ok),
            },
            ModuleNode {
                descriptor: ModuleDescriptor::new("B", Version::new(0, 1, 0)),
                init: ok,
                deps: &["A"],
                start: Some(start_fail),
            },
        ];
        let g2 = ModuleGraph::new(&nodes2);
        let res = run_init_start(&g2, &mut ctx, &rt, &mut idx);
        match res {
            Err(RunError::StartFailed { index }) => assert!(index <= 1),
            _ => panic!("expected start failure"),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod report_tests {
    use super::*;
    use crate::testutil::mk_node;
    use spacetime_core::{
        InitCtx as CoreInitCtx, InitError as CoreInitError, Runtime as CoreRuntime,
        StartError as CoreStartError, Version,
    };

    #[test]
    fn report_success_order() {
        let nodes = [
            mk_node("A", &[]),
            mk_node("B", &["A"]),
            mk_node("C", &["A", "B"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let order = topo_check_with_report(&g).unwrap();
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn report_missing_dep_payload() {
        let nodes = [mk_node("A", &["ZZ"])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_check_with_report(&g).unwrap_err();
        match err {
            #[cfg(feature = "alloc")]
            GraphError::MissingDependency { module, missing } => {
                assert_eq!(module, "A");
                assert_eq!(missing, "ZZ");
            }
            _ => panic!("expected MissingDependency"),
        }
    }

    #[test]
    fn report_cycle_with_names() {
        let nodes = [mk_node("A", &["B"]), mk_node("B", &["A"])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_check_with_report(&g).unwrap_err();
        #[cfg(feature = "alloc")]
        {
            match err {
                GraphError::Cyclic { cycle } => {
                    assert!(!cycle.is_empty());
                    let s = cycle.join(",");
                    assert!(s.contains("A"));
                    assert!(s.contains("B"));
                }
                _ => panic!("expected cyclic with cycle"),
            }
        }
        #[cfg(not(feature = "alloc"))]
        {
            assert!(matches!(err, GraphError::Cyclic));
        }
    }

    #[test]
    fn find_cycle_no_cycle_returns_none() {
        let nodes = [
            mk_node("A", &[]),
            mk_node("B", &["A"]),
            mk_node("C", &["A", "B"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let cycle = find_cycle(&g);
        assert!(cycle.is_none());
    }

    #[test]
    fn find_cycle_detects_simple_cycle() {
        let nodes = [mk_node("A", &["B"]), mk_node("B", &["A"])];
        let g = ModuleGraph::new(&nodes);
        let cycle = find_cycle(&g);
        assert!(cycle.is_some());
        let cycle = cycle.unwrap();
        assert!(!cycle.is_empty());
    }

    #[test]
    fn find_cycle_detects_longer_cycle() {
        let nodes = [
            mk_node("A", &["C"]),
            mk_node("B", &["A"]),
            mk_node("C", &["B"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let cycle = find_cycle(&g);
        assert!(cycle.is_some());
    }

    #[test]
    fn find_cycle_with_missing_dep_ignores_it() {
        // If a dependency doesn't exist, find_cycle should skip it
        let nodes = [mk_node("A", &["MISSING"])];
        let g = ModuleGraph::new(&nodes);
        let cycle = find_cycle(&g);
        assert!(cycle.is_none());
    }

    #[test]
    fn report_duplicate_name() {
        let nodes = [mk_node("A", &[]), mk_node("A", &[])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_check_with_report(&g).unwrap_err();
        assert!(matches!(err, GraphError::DuplicateName));
    }

    #[test]
    fn run_init_start_graph_error() {
        use spacetime_core::testutil::DummyRuntime;

        let nodes = [mk_node("A", &["Z"])]; // Z doesn't exist
        let g = ModuleGraph::new(&nodes);
        let mut ctx = CoreInitCtx;
        let rt = DummyRuntime;
        let mut idx = [0usize; 4];
        let err = run_init_start(&g, &mut ctx, &rt, &mut idx).unwrap_err();
        assert!(matches!(err, RunError::Graph(_)));
    }

    #[test]
    fn run_init_start_success() {
        use spacetime_core::testutil::DummyRuntime;

        fn ok(_ctx: &mut CoreInitCtx) -> Result<(), CoreInitError> {
            Ok(())
        }
        fn start_ok(_rt: &dyn CoreRuntime) -> Result<(), CoreStartError> {
            Ok(())
        }

        let nodes = [
            ModuleNode {
                descriptor: ModuleDescriptor::new("A", Version::new(0, 1, 0)),
                init: ok,
                deps: &[],
                start: Some(start_ok),
            },
            ModuleNode {
                descriptor: ModuleDescriptor::new("B", Version::new(0, 1, 0)),
                init: ok,
                deps: &["A"],
                start: None, // No start hook
            },
        ];
        let g = ModuleGraph::new(&nodes);
        let mut ctx = CoreInitCtx;
        let rt = DummyRuntime;
        let mut idx = [0usize; 4];
        let result = run_init_start(&g, &mut ctx, &rt, &mut idx);
        assert!(result.is_ok());
    }

    #[test]
    fn graph_error_clone() {
        let err = GraphError::DuplicateName;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn run_error_clone() {
        let err = RunError::InitFailed { count: 3 };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn cyclic_error_alloc() {
        let err = GraphError::Cyclic {
            cycle: alloc::vec!["A", "B", "A"],
        };
        match err {
            GraphError::Cyclic { ref cycle } => {
                assert_eq!(cycle.len(), 3);
            }
            _ => panic!("expected Cyclic"),
        }
    }

    #[test]
    fn missing_dependency_error() {
        let err = GraphError::MissingDependency {
            module: "A",
            missing: "Z",
        };
        match err {
            GraphError::MissingDependency { module, missing } => {
                assert_eq!(module, "A");
                assert_eq!(missing, "Z");
            }
            _ => panic!("expected MissingDependency"),
        }
    }
}
