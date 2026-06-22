//! Core types for the spacetime-module crate.
//!
//! Contains module descriptors, graph structures, error types, and the
//! `Describe` trait blanket implementation.

use spacetime_core::{
    InitCtx as CoreInitCtx, InitError as CoreInitError, Module as CoreModule,
    Runtime as CoreRuntime, StartError as CoreStartError, Version,
};

// A lightweight descriptor that can be produced by a derive macro (future)
#[derive(Debug)]
pub struct ModuleDescriptor {
    pub name: &'static str,
    pub version: Version,
}

impl ModuleDescriptor {
    pub const fn new(name: &'static str, version: Version) -> Self {
        Self { name, version }
    }
}

// Placeholder graph/node types for future dependency wiring
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct ModuleNode {
    pub descriptor: ModuleDescriptor,
    pub init: fn(&mut CoreInitCtx) -> Result<(), CoreInitError>,
    /// Names of modules this node depends on. All dependencies must
    /// appear earlier in the final initialization order.
    pub deps: &'static [&'static str],
    /// Optional start hook executed after successful initialization of all modules.
    /// If None, start is skipped for this node.
    pub start: Option<fn(&dyn CoreRuntime) -> Result<(), CoreStartError>>,
}

pub struct ModuleGraph<'a> {
    pub nodes: &'a [ModuleNode],
}

impl<'a> ModuleGraph<'a> {
    pub const fn new(nodes: &'a [ModuleNode]) -> Self {
        Self { nodes }
    }
}

// Trait blanket impl helper: allow any CoreModule to produce its descriptor
pub trait Describe: CoreModule {
    fn descriptor() -> ModuleDescriptor {
        ModuleDescriptor {
            name: Self::NAME,
            version: Self::VERSION,
        }
    }
}

impl<T: CoreModule> Describe for T {}

/// Start context supplied to modules at start time.
///
/// This intentionally mirrors spacetime-core's minimal approach. Additional
/// fields may be added in a backward-compatible way.
pub struct StartCtx;

/// Errors that can occur while computing a module initialization order.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(not(feature = "alloc"), derive(Copy))]
pub enum GraphError {
    /// The graph contains a cycle and cannot be initialized deterministically.
    #[cfg(not(feature = "alloc"))]
    Cyclic,
    /// A node references a dependency by name that is not present in the graph.
    UnknownDependency,
    /// Two or more nodes share the same name.
    DuplicateName,
    /// Alloc-enabled: the graph contains a cycle; includes one detected cycle.
    #[cfg(feature = "alloc")]
    Cyclic {
        cycle: alloc::vec::Vec<&'static str>,
    },
    /// Alloc-enabled: richer missing dependency payload (module -> missing dep).
    #[cfg(feature = "alloc")]
    MissingDependency {
        module: &'static str,
        missing: &'static str,
    },
}

/// Zero-alloc view over a sequence of indices, yielding `&ModuleNode`.
///
/// This is useful together with `topo_sort_indices`: store the indices in a
/// caller-provided buffer, then iterate nodes in that order without allocating.
pub struct SortedNodes<'a> {
    graph: &'a ModuleGraph<'a>,
    indices: &'a [usize],
    pos: usize,
}

impl<'a> SortedNodes<'a> {
    pub fn new(graph: &'a ModuleGraph<'a>, indices: &'a [usize]) -> Self {
        Self {
            graph,
            indices,
            pos: 0,
        }
    }
}

impl<'a> Iterator for SortedNodes<'a> {
    type Item = &'a ModuleNode;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.indices.len() {
            return None;
        }
        let idx = self.indices[self.pos];
        self.pos += 1;
        self.graph.nodes.get(idx)
    }
}

/// Errors that can happen while running a module graph via `run_init_start`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RunError {
    /// One or more init functions failed; contains the number of failures observed.
    InitFailed { count: usize },
    /// Start failed for the node at the given sorted index.
    StartFailed { index: usize },
    /// Graph validation failed; propagate the underlying error.
    Graph(GraphError),
}
