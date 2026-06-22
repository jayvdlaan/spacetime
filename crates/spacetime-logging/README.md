spacetime-logging
=================

Tiny logging facade for no_std with optional std adapters.

Badges
- Docs: https://docs.rs/spacetime-logging

Highlights
- Minimal global logger with level filtering (documented and exampled)
- Optional adapter to bridge to `tracing` under std

Features
- default: no_std
- std: enable std-gated examples

Quickstart
- Simple example: cargo run -p spacetime-logging --example simple --features std
- Tracing bridge example: cargo run -p spacetime-logging --example std_tracing --features std
- Custom logger example: cargo run -p spacetime-logging --example custom_logger --features std

License
- MIT
