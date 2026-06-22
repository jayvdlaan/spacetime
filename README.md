Spacetime
=========

Spacetime is a minimal, no_std-first core layer that standardizes module semantics and abstracts over platform/runtime differences (embedded, std, wasm). It is designed to be reused by Airframe and other runtimes.

Badges
- Workspace status: CI runs on pushes/PRs to main/master
- Docs: see per-crate docs on docs.rs

Useful links
- Implementation plan: IMPLEMENTATION_PLAN.md
- Dev guide: dev.md (feature matrix + publishing checklist)
- Architecture overview: docs/spacetime_arch.md

See IMPLEMENTATION_PLAN.md for the current roadmap and Airframe integration plan. For local development details (dual workspaces, feature-gated builds, and [patch.crates-io]), see dev.md.

Quickstart examples (std feature)
- spacetime-core example: `cargo run -p spacetime-core --example simple_module --features std`
- spacetime-module example (graph check): `cargo run -p spacetime-module --example graph_order --features std`
- spacetime-module example (print order): `cargo run -p spacetime-module --example order_print --features std`
- spacetime-module example (sorted iterator): `cargo run -p spacetime-module --example order_iter --features std`
- spacetime-logging example: `cargo run -p spacetime-logging --example simple --features std`
- spacetime-logging example (tracing bridge): `cargo run -p spacetime-logging --example std_tracing --features std`
- spacetime-logging example (custom logger + level filter): `cargo run -p spacetime-logging --example custom_logger --features std`
- spacetime-io example: `cargo run -p spacetime-io --example std_stdout --features std`
- spacetime-storage example: `cargo run -p spacetime-storage --example memstore_basic --features std,alloc`
- spacetime-storage example (prefix scan): `cargo run -p spacetime-storage --example prefix_scan --features std`
- spacetime-async-core example (Tokio spawner): `cargo run -p spacetime-async-core --example tokio_spawner --features std`
 - spacetime-async-core example (cooperative yield): `cargo run -p spacetime-async-core --example yield_coop --features std`
 - spacetime-std-runtime example (end-to-end two modules): `cargo run -p spacetime-std-runtime --features logging --example two_modules`
