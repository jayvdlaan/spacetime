<!-- TEMPLATE — copy to the repo root as AGENTS.md and replace every <PLACEHOLDER>.
     Delete this comment and any rules that don't apply to your crate. -->

# AGENTS.md — Contributor playbook for AI agents

**If you are an LLM or coding agent preparing a contribution to `<PROJECT>`, this
file is your contract. Read it in full before editing anything.** A human asked
you to open a pull request; your job is to produce a change a maintainer can
merge *without rework*.

`<PROJECT>` was largely built with AI and is meant to be worked on with AI —
AI-assisted PRs are **welcome and expected**. The bar is high precisely because
an agent moves fast: speed without verification is the failure mode we reject.

---

## TL;DR — the gate (all green, no exceptions)

**This project has no CI, by design** (a deliberate supply-chain decision: no
third-party runners, marketplace actions, or stored tokens). The gate is run
**manually**, and a contribution is only as trustworthy as the output you paste:

```bash
just release-check   # fmt + clippy(-D warnings,--all-targets) + test + build
                     # + every advertised feature combination + rustdoc
                     # (+ for no_std-first crates: the no_std/alloc/std axes + embedded target)
```

The maintainer re-runs `just release-check` before merging — so a green paste
that doesn't reproduce is worse than an honest red one. Never suppress a lint,
delete a failing test, or weaken an assertion to make it pass.

## 1. Before you change anything

Read: **`<conventions-doc>`** (the authoritative structure/naming reference),
the project's **architecture/layering doc**, and the **README of the crate you
are modifying**. If you can't state which layer your change lives in and why its
dependencies only point *downward*, work that out first.

## 2. Non-negotiable rules

- **Layering** — dependencies point **downward only**; the foundation crate
  depends on nothing in-workspace. No upward/lateral edges for convenience; wire
  cross-cutting things through the runtime registry, not a module edge.
- **Security model** — *all cryptography and cryptographic randomness for
  security decisions go through the crypto boundary.* Do **not** hand-roll
  crypto, reach for `rand` for a security decision, or leak a backend type
  (e.g. a concrete OpenSSL/RustCrypto type) in a public signature. Never log or
  persist plaintext secrets; secret-bearing structs zeroize. **Fail closed.**
- **`no_std` discipline** (for `no_std`-first crates) — default to `core`/`alloc`;
  gate `std` behind a feature; build the no_std/`alloc`/`std` axes and the
  embedded target. `#[macro_export]` macros must be `$crate::`-hygienic.
- **Conventions** — follow `<conventions-doc>` exactly (naming, one-concern-per-file,
  `*.workspace = true` inheritance, additive features, a README per crate). Match
  the surrounding code's style; your diff should be indistinguishable from the
  existing author's.
- **Honesty (the rule we care about most)** — every "it works" claim is backed by
  a command you actually ran (paste the output). If you **could not** verify
  something (a platform-gated path, a target you can't build), say so explicitly
  and mark it for maintainer verification. Never present unverified work as verified.
- **Scope** — smallest coherent change; no drive-by reformatting or dependency bumps.

## 3. Workflow

Understand the task against the actual code → make the change honoring the rules →
run the full gate and fix anything red *for real* → re-read your diff (drop debug
prints / stray TODOs) → write the commit and PR backing every claim with output.

## 4. Commits & pull requests

- Conventional commits (`fix(scope): …`).
- **Declare AI authorship**: add a `Co-Authored-By: <Agent/Model> <email>` trailer
  and note in the PR description that AI was used and to what extent. Expected, not penalized.
- Fill out `.github/PULL_REQUEST_TEMPLATE.md` honestly — unchecked boxes are fine,
  falsely-checked ones are grounds for rejection.

## 5. What gets a PR rejected

A red gate (or one "passed" by suppression); an upward/lateral layer dep; crypto
or randomness for a security decision outside the boundary; a backend type leaked
into a public signature; plaintext secrets logged/persisted; claims not backed by
output; unrelated reformatting mixed in.

## 6. Licence

`<PROJECT>` is `<LICENSE>`-licensed. By contributing you agree your contribution
is provided under the same terms.
