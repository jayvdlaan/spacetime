# Spacetime — platform abstraction layer
# Usage: just <recipe> [args]

set shell := ["bash", "-euo", "pipefail", "-c"]

# List available recipes
default:
    @just --list

# Build all crates
build:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Run clippy lints
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Apply formatting
fmt:
    cargo fmt --all

# Generate workspace documentation
doc:
    cargo doc --workspace --no-deps

# Full pre-publish gate — run manually. This project has NO CI by design
# (supply-chain risk reduction); this recipe is the gate. Must be fully green
# before publishing or merging a contribution.
release-check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    # crate-specific feature that the workspace default does not enable
    cargo test -p spacetime-crypto --features std,conformance
    cargo test -p spacetime-sshsig --features std
    cargo test -p spacetime-age --features std
    cargo test -p spacetime-storage --features std
    cargo build --workspace
    # no_std discipline: pure no_std builds of the core crates
    cargo build -p spacetime-core --no-default-features
    cargo build -p spacetime-module --no-default-features
    cargo build -p spacetime-io --no-default-features
    cargo build -p spacetime-crypto --no-default-features
    cargo build -p spacetime-sshsig --no-default-features
    cargo build -p spacetime-sshsig --no-default-features --features alloc
    cargo build -p spacetime-age --no-default-features
    cargo build -p spacetime-age --no-default-features --features alloc
    cargo build -p spacetime-storage --no-default-features
    cargo build -p spacetime-storage --no-default-features --features alloc
    # embedded target (proves no_std end-to-end)
    cargo build -p spacetime-module --target riscv32imac-unknown-none-elf
    cargo build -p spacetime-sshsig --no-default-features --target riscv32imac-unknown-none-elf
    cargo build -p spacetime-age --no-default-features --target riscv32imac-unknown-none-elf
    cargo build -p spacetime-storage --no-default-features --target riscv32imac-unknown-none-elf
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
    # default features hide the blob stores; docs.rs builds all-features, so gate that surface too
    RUSTDOCFLAGS="-D warnings" cargo doc -p spacetime-storage --no-deps --all-features
    # RustSec advisories
    cargo audit

# Publish every crate to crates.io in dependency order.
# IRREVERSIBLE: crates.io versions and names are permanent (yank != delete).
# Run `just release-check` first. cargo blocks until each crate is indexed
# before publishing the next. Publish spacetime BEFORE airframe (airframe
# depends on these). If interrupted, comment out the crates already published
# and re-run.
publish:
    cargo publish -p spacetime-core
    cargo publish -p spacetime-async-core
    cargo publish -p spacetime-capabilities
    cargo publish -p spacetime-crypto
    cargo publish -p spacetime-sshsig
    cargo publish -p spacetime-age
    cargo publish -p spacetime-health
    cargo publish -p spacetime-io
    cargo publish -p spacetime-ipc
    cargo publish -p spacetime-logging
    cargo publish -p spacetime-macros
    cargo publish -p spacetime-module
    cargo publish -p spacetime-std-runtime
    cargo publish -p spacetime-storage
