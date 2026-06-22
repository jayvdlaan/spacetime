//! Graph algorithms for module dependency resolution.
//!
//! Contains topological sorting (validation and computation), cycle detection,
//! and helper functions for working with `ModuleGraph`.

use crate::types::{GraphError, ModuleGraph, ModuleNode};

// Helper to construct a cyclic error in both alloc and no-alloc modes.
#[inline]
pub(crate) fn cyclic() -> GraphError {
    #[cfg(feature = "alloc")]
    {
        GraphError::Cyclic {
            cycle: alloc::vec::Vec::new(),
        }
    }
    #[cfg(not(feature = "alloc"))]
    {
        GraphError::Cyclic
    }
}

/// Find the index of a node by name via linear scan.
#[inline]
pub(crate) fn find_node_index(nodes: &[ModuleNode], name: &str) -> Option<usize> {
    for (i, node) in nodes.iter().enumerate() {
        if node.descriptor.name == name {
            return Some(i);
        }
    }
    None
}

/// Check that no two nodes share the same name.
pub(crate) fn check_no_duplicates(nodes: &[ModuleNode]) -> Result<(), GraphError> {
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            if nodes[i].descriptor.name == nodes[j].descriptor.name {
                return Err(GraphError::DuplicateName);
            }
        }
    }
    Ok(())
}

/// Compute a deterministic initialization order for the given graph.
///
/// Validates that the declared order is a valid topological order.
///
/// This no_alloc implementation checks that, for every node, all of its
/// dependencies appear earlier in the slice. If so, it returns the original
/// ordering. Otherwise returns `GraphError::Cyclic` (or `UnknownDependency`
/// if a referenced dependency is missing).
pub fn topo_order<'a>(graph: &'a ModuleGraph<'a>) -> Result<&'a [ModuleNode], GraphError> {
    let nodes = graph.nodes;
    // Ensure unique names
    check_no_duplicates(nodes)?;
    // For each node at position i, ensure all deps appear at some j < i
    for (i, node) in nodes.iter().enumerate() {
        for &dep_name in node.deps.iter() {
            let j = match find_node_index(nodes, dep_name) {
                Some(p) => p,
                None => return Err(GraphError::UnknownDependency),
            };
            if j >= i {
                // A dependency comes after the node => not a valid topo order
                return Err(cyclic());
            }
        }
    }
    Ok(nodes)
}

/// Compute a topological sort of the graph into a caller-provided output buffer of indices.
///
/// This function is no_alloc: it uses only stack variables and the user-provided `out` buffer
/// to return the order as indices into `graph.nodes`.
///
/// Returns the number of indices written on success. Errors on cycles or unknown deps.
pub fn topo_sort_indices(graph: &ModuleGraph<'_>, out: &mut [usize]) -> Result<usize, GraphError> {
    let nodes = graph.nodes;
    let n = nodes.len();
    if out.len() < n {
        return Err(cyclic());
    }

    let mut remaining = n;
    let mut out_len = 0usize;

    // Check for duplicate names
    check_no_duplicates(nodes)?;

    // Pre-validate dependencies exist
    for node in nodes.iter() {
        for &dep in node.deps.iter() {
            if find_node_index(nodes, dep).is_none() {
                return Err(GraphError::UnknownDependency);
            }
        }
    }

    // Repeatedly scan to find any node whose deps are all emitted
    while remaining > 0 {
        let mut progressed = false;
        'outer: for i in 0..n {
            // skip if already emitted
            let already_emitted = (0..out_len).any(|k| out[k] == i);
            if already_emitted {
                continue;
            }
            let node = &nodes[i];
            for &dep in node.deps.iter() {
                // find dep index
                let dep_idx = match find_node_index(nodes, dep) {
                    Some(x) => x,
                    None => return Err(GraphError::UnknownDependency),
                };
                // dependency must already be emitted
                let dep_emitted = (0..out_len).any(|k| out[k] == dep_idx);
                if !dep_emitted {
                    continue 'outer;
                }
            }
            // All deps emitted; emit this node
            out[out_len] = i;
            out_len += 1;
            remaining -= 1;
            progressed = true;
        }
        if !progressed {
            // No node could be emitted => cycle
            return Err(cyclic());
        }
    }

    Ok(out_len)
}

/// Find one dependency cycle in the graph if it exists (alloc only).
#[cfg(feature = "alloc")]
pub fn find_cycle(g: &ModuleGraph) -> Option<alloc::vec::Vec<&'static str>> {
    let n = g.nodes.len();
    // 0 = unvisited, 1 = visiting, 2 = done
    let mut color = alloc::vec![0u8; n];
    let mut stack: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(n);

    fn dfs(
        i: usize,
        g: &ModuleGraph,
        color: &mut [u8],
        stack: &mut alloc::vec::Vec<usize>,
    ) -> Option<alloc::vec::Vec<&'static str>> {
        color[i] = 1;
        stack.push(i);
        for &dep_name in g.nodes[i].deps {
            let j = match find_node_index(g.nodes, dep_name) {
                Some(v) => v,
                None => continue,
            };
            match color[j] {
                0 => {
                    if let Some(cyc) = dfs(j, g, color, stack) {
                        return Some(cyc);
                    }
                }
                1 => {
                    // Found back-edge; collect cycle from j to end
                    let pos = stack.iter().position(|&x| x == j).unwrap_or(0);
                    let mut cyc = alloc::vec::Vec::new();
                    for &idx in &stack[pos..] {
                        cyc.push(g.nodes[idx].descriptor.name);
                    }
                    // close the cycle by repeating the start node
                    cyc.push(g.nodes[j].descriptor.name);
                    return Some(cyc);
                }
                _ => {}
            }
        }
        stack.pop();
        color[i] = 2;
        None
    }

    for i in 0..n {
        if color[i] == 0 {
            if let Some(cyc) = dfs(i, g, &mut color, &mut stack) {
                return Some(cyc);
            }
        }
    }
    None
}

/// Validate the graph and return a topological order with richer diagnostics (alloc only).
#[cfg(feature = "alloc")]
pub fn topo_check_with_report(g: &ModuleGraph) -> Result<alloc::vec::Vec<usize>, GraphError> {
    let n = g.nodes.len();
    // Check duplicates
    check_no_duplicates(g.nodes)?;

    // Validate deps exist, return first missing with payload
    for i in 0..n {
        for &dep in g.nodes[i].deps {
            if find_node_index(g.nodes, dep).is_none() {
                return Err(GraphError::MissingDependency {
                    module: g.nodes[i].descriptor.name,
                    missing: dep,
                });
            }
        }
    }

    // Kahn's algorithm
    let mut indeg = alloc::vec![0usize; n];
    for (i, node) in g.nodes.iter().enumerate() {
        for &dep in node.deps {
            // map dep to idx; we already validated all deps exist above
            if find_node_index(g.nodes, dep).is_some() {
                indeg[i] += 1;
            }
        }
    }

    let mut queue: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    for (i, deg) in indeg.iter().enumerate() {
        if *deg == 0 {
            queue.push(i);
        }
    }

    let mut out: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(n);
    while let Some(i) = queue.pop() {
        out.push(i);
        // Decrease indegree of neighbors that depend on i
        for (j, node) in g.nodes.iter().enumerate() {
            if node.deps.iter().any(|&d| d == g.nodes[i].descriptor.name) {
                indeg[j] -= 1;
                if indeg[j] == 0 {
                    queue.push(j);
                }
            }
        }
    }

    if out.len() != n {
        let cycle = find_cycle(g).unwrap_or_default();
        return Err(GraphError::Cyclic { cycle });
    }
    Ok(out)
}
