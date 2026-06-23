<!-- TEMPLATE — copy to .github/PULL_REQUEST_TEMPLATE.md.
Before opening: read AGENTS.md and CONTRIBUTING.md. Check only boxes that are
genuinely true. An unchecked box is fine and informative; a falsely-checked one
is grounds for rejection. -->

## What & why

<!-- What does this change do, and why? Link any issue. -->

## Gate (paste the real output, don't just check)

- [ ] `just release-check` is green (fmt + clippy `--all-targets -D warnings` + test + build + feature combos + rustdoc)

```
<paste test result: / clippy Finished lines here>
```

## Rules checklist

- [ ] Dependencies point downward only (no upward/lateral layer edges)
- [ ] No cryptography or randomness for a security decision outside the boundary
- [ ] No backend type leaked into a public API signature
- [ ] No plaintext secrets logged or persisted; security errors fail closed
- [ ] (no_std crates) builds the no_std / alloc / std axes + embedded target; macros are `$crate::`-hygienic
- [ ] Follows the project conventions (naming, layout, manifest inheritance, per-crate README)
- [ ] Scope is tight — no unrelated reformatting or dependency bumps

## Verification honesty

<!-- Anything you could NOT verify locally (a platform-gated path, a target you
can't build)? State it here — do not present unverified changes as verified. -->

## AI disclosure

- [ ] An AI agent assisted with this change
- Extent / model: <!-- e.g. "Drafted by <model>, reviewed by me" -->
- [ ] A `Co-Authored-By:` trailer is present if AI-authored
