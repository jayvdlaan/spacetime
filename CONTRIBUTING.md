# Contributing to Spacetime

Thanks for your interest. Spacetime is the `no_std`-first platform-abstraction
layer beneath Airframe. It was largely built with AI assistance and is designed
to be worked on the same way.

## AI-assisted contributions are welcome

You may use an LLM or coding agent to prepare your contribution — it's
encouraged. **If you do, point your agent at [`AGENTS.md`](AGENTS.md) first.**
That file is the strict, machine-readable playbook: the gates, the
no_std/`alloc`/`std` discipline, macro hygiene, the layering and security rules,
and the honesty requirements. A PR from an agent that followed `AGENTS.md` is
what we want; one that skipped it is usually obvious and usually bounced.

Whether human- or AI-authored, every contribution meets the same bar.

## Quick start

```bash
git clone <this-repo> && cd spacetime
just build && just test
```

Run the full gate — **all must be green**:

```bash
just fmt-check    # formatting
just clippy       # cargo clippy --workspace --all-targets -- -D warnings
just test         # cargo test --workspace
just build        # cargo build --workspace
```

And the `no_std` builds that define this project — for any crate you touch:

```bash
cargo build -p <crate>                  # pure no_std
cargo build -p <crate> --features alloc # no_std + allocator
cargo build -p <crate> --features std   # std
cargo build -p spacetime-module --target riscv32imac-unknown-none-elf
```

Or run the whole thing — gates, the no_std axes, the embedded target, and docs —
with one recipe:

```bash
just release-check
```

**This project has no CI, on purpose** — a supply-chain–risk decision (no
third-party runners or marketplace actions). The gate is run manually, and the
maintainer re-runs `just release-check` before merging. Paste its real output
into your PR; an honest red result beats a green claim that doesn't reproduce.

## The hard rules (summary — see [`AGENTS.md`](AGENTS.md) for detail)

1. **Gates green, no suppression.**
2. **no_std hygiene.** Don't add `std`-only code to a `no_std` path; build all
   feature axes and the embedded target.
3. **Macro hygiene.** `#[macro_export]` macros must be `$crate::`-clean.
4. **Layering downward-only; crypto stays a facade here.** No secrets logged.
5. **Follow the conventions** in
   [`docs/ref-project-conventions.md`](docs/ref-project-conventions.md).
6. **Be honest** — back claims with output; state what you couldn't verify.
7. **Keep scope tight.**

## Opening a pull request

- Conventional-commit messages (`fix(scope): …`).
- Fill out the PR template honestly.
- **Disclose AI use** and add a `Co-Authored-By:` trailer if AI-authored.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Disclose it privately to the
maintainer first.

## Licence

Spacetime is licensed under the [MIT License](LICENSE). By contributing, you
agree your contributions are licensed under the same MIT terms.
