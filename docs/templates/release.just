# Release recipes for a spacetime-based workspace.
# Append these to the project's justfile (adjust the feature-combo / no_std lines).
# This ecosystem runs NO CI by design — `release-check` IS the gate, run by hand
# and re-run by the maintainer before merge or publish.

# Full pre-publish / pre-PR gate. Must be green with ZERO warnings.
# Never suppress a lint or delete a test to pass.
release-check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo build --workspace
    # --- advertised non-default feature combinations: one line each, e.g. ---
    # cargo build -p <crate> --features <combo>
    # --- no_std-first crates: prove the axes + the embedded target, e.g. ---
    # cargo build -p <core-crate> --no-default-features
    # cargo build -p <module-crate> --target riscv32imac-unknown-none-elf
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Publish every crate to crates.io in dependency order. IRREVERSIBLE — versions
# and names are permanent (yank != delete). Prerequisites:
#   1. `just release-check` is green.
#   2. `cargo login <crates.io-token>`.
#   3. crates.io prep done (private registry decoupled, repository + description set).
# For a CROSS-repo release, publish foundation repos BEFORE dependent ones.
publish:
    CRATES="$(python3 docs/templates/topo-order.py)" bash docs/templates/publish.sh
