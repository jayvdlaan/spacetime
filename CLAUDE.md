# Spacetime

A minimal, `no_std`-first platform abstraction layer for portable Rust code across embedded, std, and WASM targets.

## Purpose

Spacetime standardizes module semantics and abstracts platform/runtime differences. It enables Airframe modules to compile for embedded and WASM targets without modification.

## Crate Structure

```
spacetime/
└── crates/
    ├── spacetime-core/           # Duration, Instant, Version (no_std)
    ├── spacetime-module/         # Module trait, dependency graph
    ├── spacetime-macros/         # Procedural macros
    ├── spacetime-logging/        # Logging facade
    ├── spacetime-io/             # I/O traits
    ├── spacetime-storage/        # Storage abstraction
    ├── spacetime-crypto/         # Crypto traits
    ├── spacetime-health/         # Health check traits
    ├── spacetime-capabilities/   # Capability system
    ├── spacetime-async-core/     # Async primitives
    └── spacetime-std-runtime/    # Std runtime adapter (+ optional logging bridge)
```

## Key Traits

- `Module` — Lifecycle and dependency management
- `Runtime` — Platform runtime abstraction
- `Clock`, `Timer` — Time abstractions
- `Spawner` — Task spawning (async)
- Logging, I/O, storage, crypto facades

## Feature Flags

Most crates support:
- `std` — Standard library support
- `alloc` — Heap allocation (for no_std with allocator)
- No features — Pure no_std

## Build & Run Examples

```bash
# Core example
cargo run -p spacetime-core --example simple_module --features std

# Module graph ordering
cargo run -p spacetime-module --example graph_order --features std

# Logging
cargo run -p spacetime-logging --example simple --features std

# Storage
cargo run -p spacetime-storage --example memstore_basic --features std,alloc

# Async (Tokio)
cargo run -p spacetime-async-core --example tokio_spawner --features std

# Full platform example (with logging)
cargo run -p spacetime-std-runtime --features logging --example two_modules
```

## no_std Development

When targeting no_std:
- Avoid std imports; use `core` and `alloc` where needed
- Use feature flags to gate std-dependent code
- Test both std and no_std builds

## Key Files

- `IMPLEMENTATION_PLAN.md` — Roadmap and status
- `docs/guide-dev.md` — Development guide, feature matrix
- `docs/arch-spacetime.md` — Architecture overview

## Relationship to Airframe

Spacetime is layer L-1 (below Airframe). Airframe's module system builds on Spacetime's abstractions, enabling cross-platform compatibility.
