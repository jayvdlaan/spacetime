# Spacetime

Spacetime is a minimal, `no_std`-first platform-abstraction layer. It
standardizes module semantics and abstracts over platform and runtime
differences — embedded, `std`, and WASM — so the same module code can target a
microcontroller or a server. It is the foundation that
[Airframe](https://github.com/jayvdlaan/airframe) builds on, and is usable on its
own.

## Crates

- `spacetime-core` — `Duration`, `Instant`, `Version`, and core error/status types (`no_std`)
- `spacetime-module` — the `Module` trait and dependency-graph ordering
- `spacetime-capabilities` — capability identifiers and module capability sets
- `spacetime-io` / `spacetime-storage` / `spacetime-crypto` / `spacetime-health` / `spacetime-logging` — platform facades (I/O, storage, crypto, health, logging)
- `spacetime-async-core` — async runtime / spawner primitives
- `spacetime-std-runtime` — a `std`-backed Clock/Timer/Runtime implementation
- `spacetime-macros` — supporting macros
- `spacetime-ipc` — IPC primitives

## Installation

```toml
[dependencies]
spacetime-core = "1.0"
spacetime-module = "1.0"
```

## Feature flags

Most crates support three build axes:

- *(no features)* — pure `no_std`
- `alloc` — `no_std` with an allocator
- `std` — full standard library

This is verified on a bare-metal target (`riscv32imac-unknown-none-elf`) as well
as on `std`.

## Examples

```bash
cargo run -p spacetime-core        --example simple_module  --features std
cargo run -p spacetime-module      --example graph_order    --features std
cargo run -p spacetime-logging     --example simple         --features std
cargo run -p spacetime-storage     --example memstore_basic --features std,alloc
cargo run -p spacetime-async-core  --example tokio_spawner  --features std
cargo run -p spacetime-std-runtime --example two_modules    --features logging
```

## Documentation

- [docs/arch-spacetime.md](docs/arch-spacetime.md) — architecture overview
- [docs/guide-dev.md](docs/guide-dev.md) — development guide and feature matrix
- Per-crate API docs on [docs.rs](https://docs.rs)

## Contributing

Contributions — including AI-assisted ones — are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md). If you use an LLM or agent, point it at
[AGENTS.md](AGENTS.md): it covers the gates, the `no_std` discipline, macro
hygiene, and the verification a pull request must meet.

## License

Licensed under the [MIT License](LICENSE).
