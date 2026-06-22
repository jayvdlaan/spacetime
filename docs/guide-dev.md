Spacetime development guide
===========================

This repository hosts the Spacetime workspace under spacetime/ alongside other top‑level projects (e.g., Airframe). The Spacetime crates are designed no_std‑first and use feature flags to opt into std and examples.

Workspaces
- Spacetime has its own Cargo workspace at spacetime/Cargo.toml. Build and test it from the spacetime/ directory for a clean, self‑contained workflow.
- Airframe has a separate workspace under airframe/. During local development, Airframe can depend on Spacetime crates using a workspace‑level patch (see below).

Feature‑gated builds
- Default builds are no_std where possible. Enable std for examples/tests that require it.
- Examples:
  - Default: cd spacetime && cargo check
  - Std/examples: cd spacetime && cargo check --features std -p spacetime-core -p spacetime-module -p spacetime-async-core -p spacetime-logging -p spacetime-io -p spacetime-storage -p spacetime-crypto -p spacetime-std-runtime
  - Run examples (selection):
    - cargo run -p spacetime-core --example simple_module --features std
    - cargo run -p spacetime-module --example graph_order --features std
    - cargo run -p spacetime-module --example order_iter --features std
    - cargo run -p spacetime-logging --example std_tracing --features std
    - cargo run -p spacetime-io --example std_stdout --features std
    - cargo run -p spacetime-storage --example memstore_basic --features std,alloc
    - cargo run -p spacetime-storage --example prefix_scan --features std
    - cargo run -p spacetime-async-core --example tokio_spawner --features std
    - cargo run -p spacetime-std-runtime --features logging --example two_modules

Using [patch.crates-io] during monorepo development
- Airframe optionally depends on spacetime-core. To make this robust regardless of CWD or symlinks, Airframe’s workspace Cargo.toml includes:

```
[patch.crates-io]
spacetime-core = { path = "../spacetime/crates/spacetime-core" }
```

This causes any crates depending on spacetime-core to resolve to the local path when building the Airframe workspace, while keeping manifests simple in individual crates.

Conventions
- Keep core traits allocator‑agnostic; add convenience helpers behind the alloc feature.
- Prefer no‑alloc APIs that use caller‑provided buffers and iterators.
- Document std‑gated examples and tests with clear run commands.

Publishing checklist
- Ensure workspace builds cleanly:
  - cargo check --workspace
  - cargo check --workspace --features std
  - cargo test --workspace --features std
- Update versions across all crates to keep them in sync where needed.
- Update CHANGELOG (top-level and per-crate if maintained) with notable changes.
- Verify README.md files per crate include quickstart and docs.rs links.
- Verify Cargo.toml metadata (description, repository, license, readme, categories/keywords if publishing to crates.io).
- Tag the release in VCS: git tag -s spacetime-vX.Y.Z && git push --tags
- Perform a dry run:
  - cargo publish -p <crate> --dry-run
- Publish crates respecting dependency order (core first, then dependents):
  1) spacetime-core
  2) spacetime-logging, spacetime-io, spacetime-storage, spacetime-crypto, spacetime-async-core
  3) spacetime-module
  4) spacetime-macros
  5) spacetime-std-runtime

Feature matrix (no_std/std/alloc)

| Crate                   | no_std (default) | alloc | std |
|-------------------------|------------------|-------|-----|
| spacetime-core          | yes              | n/a   | yes |
| spacetime-module        | yes              | n/a   | yes |
| spacetime-logging       | yes              | n/a   | yes |
| spacetime-io            | yes              | n/a   | yes |
| spacetime-storage       | yes              | yes   | yes |
| spacetime-crypto        | yes              | yes   | yes |
| spacetime-async-core    | yes              | n/a   | yes |
| spacetime-macros        | n/a (proc-macro) | n/a   | yes |
| spacetime-std-runtime   | no               | n/a   | yes |

Notes
- "n/a" means the feature does not apply to this crate.
- Under std, additional examples/tests may be compiled and run.
