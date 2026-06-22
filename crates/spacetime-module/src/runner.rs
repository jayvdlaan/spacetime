//! Module lifecycle runner.
//!
//! Provides `run_init_start` which initializes all modules in topological order
//! and then invokes their optional start hooks.

use spacetime_core::{InitCtx as CoreInitCtx, Runtime as CoreRuntime};

use crate::graph::topo_sort_indices;
use crate::types::{ModuleGraph, RunError};

/// Initialize all nodes (in topological order) and then invoke optional start hooks.
///
/// This helper is no_alloc: it uses a caller-provided index buffer to hold the
/// topological order. If any init fails, all inits are attempted and an error with
/// the failure count is returned; start hooks will be skipped in that case. If inits
/// succeed, starts are invoked in order until a failure occurs, which is returned
/// with the index of the failing node in the sorted order.
pub fn run_init_start(
    graph: &ModuleGraph<'_>,
    ctx: &mut CoreInitCtx,
    rt: &dyn CoreRuntime,
    idx_buf: &mut [usize],
) -> Result<(), RunError> {
    let n = graph.nodes.len();
    let count = topo_sort_indices(graph, idx_buf).map_err(RunError::Graph)?;
    debug_assert_eq!(count, n);

    // Run all inits
    let mut failures = 0usize;
    #[allow(clippy::needless_range_loop)]
    for k in 0..count {
        let i = idx_buf[k];
        let node = &graph.nodes[i];
        if let Err(_e) = (node.init)(ctx) {
            failures += 1;
        }
    }
    if failures > 0 {
        return Err(RunError::InitFailed { count: failures });
    }

    // Run starts until first failure
    #[allow(clippy::needless_range_loop)]
    for k in 0..count {
        let i = idx_buf[k];
        let node = &graph.nodes[i];
        if let Some(start) = node.start {
            if let Err(_e) = start(rt) {
                return Err(RunError::StartFailed { index: k });
            }
        }
    }
    Ok(())
}
