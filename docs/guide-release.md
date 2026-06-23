# Release Runbook — taking a spacetime-based project to public release

This is an **agent-executable runbook**. An LLM/coding agent can drive most of
it end to end; steps marked **[GATE]** are decisions only a human makes — at a
gate, stop and ask. It distills the process used to take the reference project
(airframe + spacetime) from private development to a clean public `1.0` on
crates.io + a GitHub mirror, with a private canonical remote retained.

It assumes the project follows [`ref-project-conventions.md`](ref-project-conventions.md)
(the authoritative structural/naming reference) and the security model: **all
cryptography and cryptographic randomness for security decisions go through the
crypto boundary; applications never roll their own**.

> How to use: hand this file to an agent — *"Take `<project>` to public release
> following `docs/guide-release.md`."* The agent works the phases in order and
> pauses at each **[GATE]**. Reusable artifacts referenced below live in
> [`docs/templates/`](templates/).

---

## Phase 0 — Decision gates **[GATE]**

Settle these before any work; they shape everything after.

| Decision | Notes |
|---|---|
| **License** | The reference release used **MIT** (permissive — anyone, including downstream products, can use it). Pick deliberately; relicensing after publish is painful. |
| **Version target** | `0.x` → soak → `1.0` (**recommended**) vs. straight to `1.0`. **`1.0` is a permanent API-stability promise** — the next breaking change forces `2.0`. If *any* breaking change is queued (e.g. a capability/API redesign), do it **under `0.x` first**, then freeze. Re-verify honestly rather than assuming "we're at 1.0." |
| **Public history** | Full history, or **orphan-root truncation** (the public mirror starts at a single `1.0` commit, no pre-release history). Truncation also structurally guarantees no pre-1.0 secret/WIP leaks. |
| **Hosting topology** | Which remote is **canonical** (keeps full history) and which is a **mirror**. Ensure *nothing lives only on the mirror* (see Phase 9). |
| **CI** | On, or **off-by-design**. The reference project chose **off** — a deliberate supply-chain decision (no third-party runners, marketplace actions, or stored tokens). With CI off, `just release-check` *is* the gate, run by hand and re-run by the maintainer before merge. |

---

## Phase 1 — Readiness audit

Assess the workspace against `ref-project-conventions.md` and the security model;
produce a prioritized **must-fix** list. Cover: code quality/readability,
separation of concerns/reuse, security, and conventions conformance.

- For breadth, parallel read-only agents per subsystem are fine. For
  **security-critical** code, work **single-threaded and grounded in the code** —
  no multi-agent fan-out.
- Verdict to reach: is it *publishable beta* vs *stable 1.0*? Be honest; the
  common real gaps are mechanical (red lint gate, feature combos that don't
  compile, docs that mislead), not the crypto core.

## Phase 2 — Green the gates

Establish and pass the full gate. Nothing ships until every check is green with
**zero warnings** — never suppress a lint or delete a test to pass.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
# every advertised feature combination (a crate that builds by default can fail under another)
# no_std-first crates: pure no_std / alloc / std axes + the embedded target, e.g.
cargo build -p <core-crate> --no-default-features
cargo build -p <module-crate> --target riscv32imac-unknown-none-elf
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Capture all of this in a single **`just release-check`** recipe (template:
[`templates/release.just`](templates/release.just)). This recipe is the project's
gate for the rest of its life.

## Phase 3 — Conventions conformance

- `[workspace.package]` inheritance for `version`/`edition`/`license`/`repository`
  (`*.workspace = true` in each crate).
- A `README.md` per crate.
- A **crate-level `//!` doc** on every crate (overview + key types with intra-doc
  links + a short example). Bare crates render an empty docs.rs front page — fill
  them. Mark examples `ignore` unless they truly compile under default features
  (a `//!` ```` ```rust ```` block is a doctest that `cargo test` runs).
- Naming/layout per the conventions (one concern per file; no god-files).

## Phase 4 — Security pass

Single-threaded, grounded. Verify:
- Crypto + cryptographic randomness for security decisions go through the
  boundary; backends are not leaked in public signatures.
- No plaintext secrets logged or persisted; secret-bearing structs zeroize.
- **Fail closed** on security-relevant errors; reject malformed input
  (path traversal, decompression bombs, low-order curve points, …).
- No reachable panics on attacker-controlled data in request paths (`unwrap`/
  `expect` should be init/lock-poisoning/validated-input only).

## Phase 5 — License sweep

Set the chosen license everywhere, consistently:
- `[workspace.package] license = "<SPDX>"`; fix any crate hardcoding it.
- Replace the `LICENSE` file text.
- Sweep crate READMEs + the conventions doc.
- Verify: `cargo metadata --no-deps` shows the new license; build stays green.

## Phase 6 — Contributor setup

Drop in (templates in [`templates/`](templates/)):
- **`AGENTS.md`** — the strict LLM-contributor playbook (gates, layering rules,
  security model, honesty/verification, AI disclosure). This is what a contributor
  hands their agent.
- **`CONTRIBUTING.md`** — human-facing, routes agents to `AGENTS.md`.
- **`.github/PULL_REQUEST_TEMPLATE.md`** — gates + rules + AI-disclosure checklist.
- If CI is off, document the manual `just release-check` posture in all three.

## Phase 7 — crates.io prep (reversible)

1. **Decouple from any private registry**: drop `registry = "<private>"` from
   inter-crate deps; keep `version` + `path` (path for local dev, version for the
   published artifact). Cross-super-project deps become plain crates.io version
   reqs.
2. **`repository`** → the public URL.
3. **`description`** on every crate (crates.io requires it).
4. **Version sweep** to the target (bump `[workspace.package].version`; `^`
   semantics mean a `1.0.1` patch only needs the package-version line bumped — the
   `"1.0.0"` dep reqs already accept it).
5. **Confirm names are free**: query `https://crates.io/api/v1/crates/<name>`
   (404 = free). crates.io is one flat namespace and treats `-`/`_` as equivalent.
6. **Dry-run** a true leaf: `cargo publish -p <leaf> --dry-run`. Dependent crates
   can't fully dry-run until their deps are on crates.io — that's expected.
7. **Compute the topological publish order** with
   [`templates/topo-order.py`](templates/topo-order.py).
8. Mark internal-only crates `publish = false`.

## Phase 8 — Publish (irreversible)

crates.io versions/names are **permanent** (yank ≠ delete). Publish **bottom-up**
in dependency order (leaves first; cross-repo: foundation crates before the crates
that depend on them). Use the self-pacing publisher
([`templates/publish.sh`](templates/publish.sh)) — it parses each rate-limit reset
and sleeps exactly until then, skips already-published crates, and stops on any
real error.

**Rate limits (the big gotcha):**
- **New crate** (new name): **1 per 10 minutes, burst of 5.** Publishing N new
  crates ≈ `N × 10 min` after the burst — a many-crate first release runs for
  *hours*. The publisher handles it unattended.
- **New version** of an existing crate: a **much more lenient** limit (~1/min,
  large burst). A patch refresh of an existing workspace publishes in *minutes*.

## Phase 9 — Public mirror

If truncating history (Phase 0):

```bash
git checkout --orphan release-public      # single root commit = the release snapshot
git add -A && git commit -m "<Project> 1.0.0 — initial public release"
git remote add github git@github.com:<org>/<repo>.git
git push github release-public:main
git tag v1.0.0 && git push github v1.0.0
git checkout <dev-branch>                 # canonical history untouched
```

**Don't rely on one host.** Push the orphan branch + tags to the *canonical*
remote too, so the public lineage isn't GitHub-only and the mirror is disposable.
Future public releases: re-snapshot from the new release commit, push to both.

## Phase 10 — Post-release polish

Docs.rs builds from the **published** crate, so doc/README improvements only reach
the public pages on a **re-publish**. Because new *versions* are cheap (Phase 8),
a patch (`1.0.1`) to refresh docs.rs is a few minutes — batch doc/README/API
cleanups and ship one. crates.io renders each crate's `README.md`, so keep them
free of stale status/maturity notes once you're at `1.0`.

---

## Gotchas checklist (read before Phase 8)

- [ ] **Rate limits**: new-crate (1/10min, burst 5) vs new-version (lenient). Size the publish window accordingly.
- [ ] **Topological order**, deps before dependents; **path-only dev-deps are stripped** on publish (don't need versions), but versioned inter-crate deps must resolve.
- [ ] **`^` version semantics**: `"1.0.0"` accepts `1.0.x` — patch bumps only touch `[workspace.package].version`.
- [ ] **Registry decoupling** done; `repository` + `description` present on all crates.
- [ ] **Orphan-root** mirror + the lineage pushed to the canonical remote too.
- [ ] **Names verified free** before the first publish (permanent).
- [ ] Gate **green with zero warnings**; no suppressed lints / deleted tests.

## Templates

[`docs/templates/`](templates/):
`AGENTS.md` · `CONTRIBUTING.md` · `PULL_REQUEST_TEMPLATE.md` ·
`release.just` (the `release-check` / `publish` recipes) ·
`publish.sh` (self-pacing, rate-limit-aware publisher) ·
`topo-order.py` (dependency-ordered publish list from `cargo metadata`).
