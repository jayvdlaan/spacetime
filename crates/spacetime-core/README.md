spacetime-core
==============

Minimal, no_std-first core traits and types for Spacetime modules and runtimes.

Badges
- Docs: https://docs.rs/spacetime-core

Highlights
- Version, Status, Duration, Instant types with saturating ops
- Core capability traits: Clock, Timer, Runtime
- Module lifecycle trait with init/start/shutdown
- no_std by default; std only needed for examples/tests

Features
- default: no_std
- std: enable std-gated examples and tests

Quickstart
- Run example (std): cargo run -p spacetime-core --example simple_module --features std
- Run tests (std): cargo test -p spacetime-core --features std

License
- MIT
