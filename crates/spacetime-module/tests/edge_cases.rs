//! Additional edge case tests for spacetime-module.
//!
//! These tests cover boundary conditions and error scenarios for the module graph.

#![cfg(feature = "std")]

use spacetime_core::{InitCtx, InitError, Version};
use spacetime_module as sm;
use spacetime_module::{
    testutil::mk_node, topo_order, topo_sort_indices, GraphError, ModuleDescriptor, ModuleGraph,
    ModuleNode, RunError, SortedNodes,
};

// Tests for topo_order validation

#[test]
fn topo_order_single_node_no_deps() {
    let nodes = [mk_node("A", &[])];
    let g = ModuleGraph::new(&nodes);
    let ordered = topo_order(&g).unwrap();
    assert_eq!(ordered.len(), 1);
    assert_eq!(ordered[0].descriptor.name, "A");
}

#[test]
fn topo_order_two_nodes_correct_order() {
    let nodes = [mk_node("A", &[]), mk_node("B", &["A"])];
    let g = ModuleGraph::new(&nodes);
    let ordered = topo_order(&g).unwrap();
    assert_eq!(ordered.len(), 2);
    assert_eq!(ordered[0].descriptor.name, "A");
    assert_eq!(ordered[1].descriptor.name, "B");
}

#[test]
fn topo_order_rejects_wrong_order() {
    // B depends on A but appears before A
    let nodes = [mk_node("B", &["A"]), mk_node("A", &[])];
    let g = ModuleGraph::new(&nodes);
    let err = topo_order(&g).unwrap_err();
    #[cfg(feature = "alloc")]
    assert!(matches!(err, GraphError::Cyclic { .. }));
    #[cfg(not(feature = "alloc"))]
    assert!(matches!(err, GraphError::Cyclic));
}

#[test]
fn topo_order_duplicate_names_rejected() {
    let nodes = [mk_node("A", &[]), mk_node("A", &[])];
    let g = ModuleGraph::new(&nodes);
    let err = topo_order(&g).unwrap_err();
    assert!(matches!(err, GraphError::DuplicateName));
}

// Tests for topo_sort_indices

#[test]
fn topo_sort_indices_empty_graph() {
    let nodes: [ModuleNode; 0] = [];
    let g = ModuleGraph::new(&nodes);
    let mut out = [0usize; 4];
    let n = topo_sort_indices(&g, &mut out).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn topo_sort_indices_single_node() {
    let nodes = [mk_node("A", &[])];
    let g = ModuleGraph::new(&nodes);
    let mut out = [0usize; 4];
    let n = topo_sort_indices(&g, &mut out).unwrap();
    assert_eq!(n, 1);
    assert_eq!(out[0], 0);
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
    #[cfg(feature = "alloc")]
    assert!(matches!(err, GraphError::Cyclic { .. }));
    #[cfg(not(feature = "alloc"))]
    assert!(matches!(err, GraphError::Cyclic));
}

#[test]
fn topo_sort_indices_self_cycle() {
    // Node depends on itself
    let nodes = [mk_node("A", &["A"])];
    let g = ModuleGraph::new(&nodes);
    let mut out = [0usize; 4];
    let err = topo_sort_indices(&g, &mut out).unwrap_err();
    #[cfg(feature = "alloc")]
    assert!(matches!(err, GraphError::Cyclic { .. }));
    #[cfg(not(feature = "alloc"))]
    assert!(matches!(err, GraphError::Cyclic));
}

#[test]
fn topo_sort_indices_three_way_cycle() {
    // A -> B -> C -> A
    let nodes = [
        mk_node("A", &["C"]),
        mk_node("B", &["A"]),
        mk_node("C", &["B"]),
    ];
    let g = ModuleGraph::new(&nodes);
    let mut out = [0usize; 4];
    let err = topo_sort_indices(&g, &mut out).unwrap_err();
    #[cfg(feature = "alloc")]
    assert!(matches!(err, GraphError::Cyclic { .. }));
    #[cfg(not(feature = "alloc"))]
    assert!(matches!(err, GraphError::Cyclic));
}

// Tests for SortedNodes iterator

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
    let names: Vec<&str> = it.by_ref().map(|n| n.descriptor.name).collect();

    assert_eq!(names.len(), 3);
    // A must come before B, B before C
    let pos_a = names.iter().position(|&n| n == "A").unwrap();
    let pos_b = names.iter().position(|&n| n == "B").unwrap();
    let pos_c = names.iter().position(|&n| n == "C").unwrap();
    assert!(pos_a < pos_b);
    assert!(pos_b < pos_c);
}

#[test]
fn sorted_nodes_empty_indices() {
    let nodes: [ModuleNode; 0] = [];
    let g = ModuleGraph::new(&nodes);
    let indices: [usize; 0] = [];
    let mut it = SortedNodes::new(&g, &indices);
    assert!(it.next().is_none());
}

#[test]
fn sorted_nodes_out_of_bounds_index_returns_none() {
    let nodes = [mk_node("A", &[])];
    let g = ModuleGraph::new(&nodes);
    // Provide an index that's out of bounds
    let indices = [5]; // Only one node exists at index 0
    let mut it = SortedNodes::new(&g, &indices);
    assert!(it.next().is_none());
}

// Tests for find_cycle (alloc only)

#[cfg(feature = "alloc")]
mod alloc_tests {
    use super::*;
    use spacetime_module::{find_cycle, topo_check_with_report};

    #[test]
    fn find_cycle_detects_simple_cycle() {
        let nodes = [mk_node("A", &["B"]), mk_node("B", &["A"])];
        let g = ModuleGraph::new(&nodes);
        let cycle = find_cycle(&g);
        assert!(cycle.is_some());
        let c = cycle.unwrap();
        assert!(c.contains(&"A"));
        assert!(c.contains(&"B"));
    }

    #[test]
    fn find_cycle_no_cycle_returns_none() {
        let nodes = [mk_node("A", &[]), mk_node("B", &["A"])];
        let g = ModuleGraph::new(&nodes);
        let cycle = find_cycle(&g);
        assert!(cycle.is_none());
    }

    #[test]
    fn find_cycle_detects_complex_cycle() {
        // A -> B -> C -> D -> B (cycle B -> C -> D -> B)
        let nodes = [
            mk_node("A", &[]),
            mk_node("B", &["A", "D"]),
            mk_node("C", &["B"]),
            mk_node("D", &["C"]),
        ];
        let g = ModuleGraph::new(&nodes);
        let cycle = find_cycle(&g);
        assert!(cycle.is_some());
    }

    #[test]
    fn topo_check_with_report_success() {
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
    fn topo_check_with_report_missing_dependency() {
        let nodes = [mk_node("A", &["NonExistent"])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_check_with_report(&g).unwrap_err();
        match err {
            GraphError::MissingDependency { module, missing } => {
                assert_eq!(module, "A");
                assert_eq!(missing, "NonExistent");
            }
            _ => panic!("expected MissingDependency error"),
        }
    }

    #[test]
    fn topo_check_with_report_duplicate() {
        let nodes = [mk_node("A", &[]), mk_node("A", &[])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_check_with_report(&g).unwrap_err();
        assert!(matches!(err, GraphError::DuplicateName));
    }

    #[test]
    fn topo_check_with_report_cycle() {
        let nodes = [mk_node("A", &["B"]), mk_node("B", &["A"])];
        let g = ModuleGraph::new(&nodes);
        let err = topo_check_with_report(&g).unwrap_err();
        match err {
            GraphError::Cyclic { cycle } => {
                assert!(!cycle.is_empty());
            }
            _ => panic!("expected Cyclic error"),
        }
    }
}

// Tests for run_init_start

#[test]
fn run_init_start_all_success() {
    use spacetime_core::testutil::DummyRuntime;

    let nodes = [mk_node("A", &[]), mk_node("B", &["A"])];
    let g = ModuleGraph::new(&nodes);
    let mut ctx = InitCtx;
    let rt = DummyRuntime;
    let mut idx = [0usize; 4];

    let result = sm::run_init_start(&g, &mut ctx, &rt, &mut idx);
    assert!(result.is_ok());
}

#[test]
fn run_init_start_init_failure() {
    use spacetime_core::testutil::DummyRuntime;

    fn fail(_ctx: &mut InitCtx) -> Result<(), InitError> {
        Err(InitError::Failed)
    }

    let nodes = [ModuleNode {
        descriptor: ModuleDescriptor::new("A", Version::new(0, 1, 0)),
        init: fail,
        deps: &[],
        start: None,
    }];
    let g = ModuleGraph::new(&nodes);
    let mut ctx = InitCtx;
    let rt = DummyRuntime;
    let mut idx = [0usize; 4];

    let result = sm::run_init_start(&g, &mut ctx, &rt, &mut idx);
    assert!(matches!(result, Err(RunError::InitFailed { count: 1 })));
}

#[test]
fn run_init_start_graph_error() {
    use spacetime_core::testutil::DummyRuntime;

    // Cyclic graph
    let nodes = [mk_node("A", &["B"]), mk_node("B", &["A"])];
    let g = ModuleGraph::new(&nodes);
    let mut ctx = InitCtx;
    let rt = DummyRuntime;
    let mut idx = [0usize; 4];

    let result = sm::run_init_start(&g, &mut ctx, &rt, &mut idx);
    assert!(matches!(result, Err(RunError::Graph(_))));
}
