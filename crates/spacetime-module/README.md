spacetime-module
================

Lightweight module descriptors and graph helpers built on spacetime-core.

Badges
- Docs: https://docs.rs/spacetime-module

Highlights
- ModuleDescriptor and ModuleNode for assembling graphs
- Topological order validation and no-alloc sorting iterator
- Works with spacetime-macros to derive descriptor constants

Features
- default: no_std
- std: enable examples/tests (printing and sorting orders)

Quickstart
- Graph check example: cargo run -p spacetime-module --example graph_order --features std
- Print order example: cargo run -p spacetime-module --example order_print --features std
- Sorted iterator example: cargo run -p spacetime-module --example order_iter --features std
- Macro-derived nodes example: cargo run -p spacetime-module --example derived_nodes --features std

License
- MIT
