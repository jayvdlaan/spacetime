# AGENTS.md — Contributor playbook for AI agents

**If you are an LLM or coding agent preparing a contribution to Spacetime, this
file is your contract. Read it in full before editing anything.** A human asked
you to open a pull request here; your job is to produce a change a maintainer can
merge *without rework*.

Spacetime is the `no_std`-first platform-abstraction layer beneath Airframe. It
was largely built with AI and is meant to be worked on with AI — AI-assisted PRs
are **welcome and expected**. The bar is high precisely because an agent moves
fast: speed without verification is the failure mode we reject.

---

## TL;DR — the gates (all must be green, no exceptions)

**This project has no CI, by design** (a deliberate supply-chain–risk decision:
no third-party runners, marketplace actions, or stored tokens). The gate is run
**manually** — run it all with one recipe and paste the real output into your PR:

```bash
just release-check    # fmt-check + clippy(-D warnings,--all-targets) + test + build
                      # + the no_std / alloc / std axes + the riscv embedded target + docs
```

The individual steps still exist if you want to iterate on one:

```bash
just fmt-check                                   # cargo fmt --all -- --check
just clippy                                      # cargo clippy --workspace --all-targets -- -D warnings
just test                                        # cargo test --workspace
just build                                       # cargo build --workspace
```

The maintainer re-runs `just release-check` before merging, so a green paste
that doesn't reproduce is worse than an honest red one.

**Plus — the no_std discipline that defines this project:** a crate that
advertises `no_std` must actually build without `std`. For any crate you touch,
build the feature axes it supports:

```bash
cargo build -p <crate>                           # pure no_std (no features)
cargo build -p <crate> --features alloc          # no_std + allocator
cargo build -p <crate> --features std            # std
# and the real embedded target for the core/module crates:
cargo build -p spacetime-module --target riscv32imac-unknown-none-elf
```

If any gate or target is red, the change is not done. Never suppress a lint,
delete a failing test, or weaken an assertion to make a gate pass.

---

## 1. Before you change anything

Read, in this order:

1. **`docs/ref-project-conventions.md`** — the authoritative reference for crate
   naming, file layout, `Cargo.toml` conventions, versioning, documentation
   naming, and the Release-Readiness checklist. (This file lives here in
   Spacetime and governs the whole Airspace ecosystem.)
2. **`docs/arch-spacetime.md`** and **`docs/guide-dev.md`** — architecture and the
   feature matrix.
3. **The `README.md` of the crate you are modifying.**

---

## 2. Non-negotiable rules

### no_std / alloc / std hygiene
This is the rule most agents get wrong:

- Default to `core` and `alloc`; reach for `std` only behind a `std` feature
  gate. Do not add a `std`-only import (`std::collections::HashMap`,
  `std::error::Error`, `std::time::Instant`, …) to a `no_std` code path.
- Use `alloc` collections (`BTreeMap`/`BTreeSet`/`Vec`/`String`) where you'd
  reach for `std` ones in `no_std`; pull them in with explicit
  `use alloc::{...}` (including in `#[cfg(test)]` modules).
- `core::fmt::Display` works in `no_std`; `std::error::Error` does not — gate it.
- After any change, build **all three** axes (no-features / `alloc` / `std`) and
  the embedded target. A change that only builds with `std` has regressed the
  project's reason to exist.

### Macro hygiene
`#[macro_export]` macros expand in the *caller's* crate, so:

- Reference every type through `$crate::` — never assume the caller has the
  symbol in scope.
- For types from transitive dependencies, re-export them as
  `#[doc(hidden)] pub use … as __Type;` and reference `$crate::__Type` from the
  macro.
- The same applies to `alloc` types (`$crate::__Rc`, etc.) — callers may not
  have `extern crate alloc`.

### Layering & security
- Spacetime sits at **L-1**, below Airframe. `spacetime-core` depends on nothing
  in this workspace. Dependencies point **downward only**.
- The crypto crates (`spacetime-crypto`, …) are **trait facades**. Do not put a
  concrete cryptographic implementation or cryptographic randomness behind them
  in this layer; the boundary's job is to define the seam, not to be the backend.
- Never log or persist plaintext secrets; fail closed on security-relevant
  errors.

### Conventions
Follow `docs/ref-project-conventions.md` exactly: `spacetime-*` kebab-case crate
names (Rust imports use underscores: `spacetime_core`); one concern per file;
`version`/`edition`/`license`/`repository` inherited via `*.workspace = true`;
features additive; every new crate gets a `README.md`. Match the surrounding
code's style.

### Honesty (the rule we care about most)
Every factual claim in your PR must be backed by a command you actually ran —
paste the `test result:` line, the clippy output, the cross-target `Finished`.
If you **could not** verify something (a target you can't build, hardware), say
so explicitly and mark it for maintainer verification. Never present an
unverified change as verified.

### Scope discipline
Smallest coherent change. No unrelated reformatting, no drive-by dependency
bumps. Note separate problems in the PR; don't fold them in.

---

## 3. The workflow

1. Understand the task against the actual code.
2. Make the change, honouring no_std/macro/layer/security rules.
3. Run the full gate **and** the no_std/`alloc`/`std`/embedded builds.
4. Re-read your diff; remove debug prints and stray TODOs.
5. Write the commit and PR (section 4), backing every claim with output.

---

## 4. Commits & pull requests

- **Conventional commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`,
  `test:`, with a scope (`fix(spacetime-module): …`).
- **Declare AI authorship** with a trailer and a note in the PR description:

  ```
  Co-Authored-By: <Your Agent/Model> <noreply@example.com>
  ```

- Fill out `.github/PULL_REQUEST_TEMPLATE.md` honestly. Unchecked boxes are fine;
  falsely-checked ones are grounds for rejection.

## 5. What gets a PR rejected

- A red gate, or one "passed" by suppression.
- `std` leaking into a `no_std` path; an unbuilt feature axis or target.
- A `#[macro_export]` macro that isn't `$crate::`-hygienic.
- A concrete crypto implementation pushed into the facade layer.
- Claims not backed by output, or unverifiable changes presented as verified.
- Unrelated reformatting mixed into the diff.

## 6. Licence

Spacetime is MIT-licensed. By contributing you agree your contribution is
provided under the same MIT terms.
