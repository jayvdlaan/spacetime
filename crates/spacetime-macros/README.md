spacetime-macros
================

Procedural macros to improve ergonomics when declaring Spacetime modules.

Badges
- Docs: https://docs.rs/spacetime-macros

Highlights
- `#[spacetime_module(...)]` attribute macro generates `ST_NAME`, `ST_VERSION`, and `ST_DEPS` constants on the annotated struct
- Designed to remain lightweight and explicit about contracts

Features
- Requires std (proc-macro crate)

Quickstart
- See usage in spacetime-module example: cargo run -p spacetime-module --example derived_nodes --features std

License
- MIT
