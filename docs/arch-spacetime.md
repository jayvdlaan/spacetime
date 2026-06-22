Spacetime architecture overview
===============================

Spacetime is a set of no_std-first facade crates providing portable traits for modules, runtime capabilities, logging, async helpers, storage, crypto, and platform adapters. Most functionality is defined in small, dependency-light crates and composed by adapters under std or embedded/wasm targets.

Key ideas
- no_std by default, opt into std via feature flags
- Stable, allocation-agnostic traits with caller-provided buffers where practical
- Platform adapters provide concrete behavior for specific targets
- Optional macros improve ergonomics without hiding contracts

Crates and relationships

```mermaid
flowchart TD
  core[spacetime-core\n(no_std)]
  logging[spacetime-logging\n(no_std)]
  io[spacetime-io\n(no_std)]
  storage[spacetime-storage\n(no_std)]
  crypto[spacetime-crypto\n(no_std)]
  asyncc[spacetime-async-core\n(no_std)]
  module[spacetime-module\n(no_std; builds on core)]
  macros[spacetime-macros\n(proc-macro, std)]
  stdrt[spacetime-std-runtime\n(std adapter)]

  module --> core
  stdrt --> core
  stdrt --> logging
  stdrt --> io
  stdrt --> storage
  stdrt --> crypto
  stdrt --> asyncc
  macros --> module
```

Usage pattern
- Libraries and apps depend on the facade crates (core/module/logging/etc.).
- The target platform selects an adapter crate (e.g., spacetime-std-runtime) to provide concrete implementations.
- Optional macros assist in declaring module metadata and dependencies.

Examples
- See the per-crate READMEs for quickstart commands to run examples on std.
