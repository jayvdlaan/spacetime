<!--
Before opening: read AGENTS.md (the contributor playbook) and CONTRIBUTING.md.
Check only the boxes that are genuinely true. An unchecked box is fine and
informative; a falsely-checked one is grounds for rejection.
-->

## What & why

<!-- What does this change do, and why? Link any issue. -->

## Gates (paste the real output, don't just check)

- [ ] `just fmt-check` passes
- [ ] `just clippy` is clean (`--workspace --all-targets -- -D warnings`)
- [ ] `just test` passes
- [ ] `just build` passes

```
<paste test result: / clippy Finished lines here>
```

## no_std discipline (for every crate you touched)

- [ ] Builds with **no features** (pure no_std)
- [ ] Builds with `--features alloc`
- [ ] Builds with `--features std`
- [ ] `spacetime-module` builds for `riscv32imac-unknown-none-elf` (if affected)

## Rules checklist

- [ ] No `std`-only code added to a `no_std` path
- [ ] Any `#[macro_export]` macro is `$crate::`-hygienic
- [ ] Dependencies point downward only (no upward/lateral layer edges)
- [ ] No concrete crypto pushed into the facade layer; no plaintext secrets logged
- [ ] Follows `docs/ref-project-conventions.md`
- [ ] Scope is tight — no unrelated reformatting or dependency bumps

## Verification honesty

<!-- Anything you could NOT verify locally (a target you can't build, hardware)?
State it here — do not present unverified changes as verified. -->

## AI disclosure

- [ ] An AI agent assisted with this change
- Extent / model: <!-- e.g. "Drafted by <model>, reviewed by me" -->
- [ ] A `Co-Authored-By:` trailer is present if AI-authored
