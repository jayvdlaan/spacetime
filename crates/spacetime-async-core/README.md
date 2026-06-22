spacetime-async-core
====================

Minimal async primitives/contracts for cooperative async in no_std contexts.

Badges
- Docs: https://docs.rs/spacetime-async-core

Highlights
- Contracts for spawning/yielding without tying to a specific executor
- Examples demonstrating cooperative yield under std

Features
- default: no_std
- std: enable std-gated examples

Quickstart
- Tokio spawner example (std): cargo run -p spacetime-async-core --example tokio_spawner --features std
- Cooperative yield example (std): cargo run -p spacetime-async-core --example yield_coop --features std

License
- MIT
