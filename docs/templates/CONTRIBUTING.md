<!-- TEMPLATE — copy to the repo root as CONTRIBUTING.md and replace <PLACEHOLDER>s. -->

# Contributing to `<PROJECT>`

Thanks for your interest. `<PROJECT>` was largely built with AI assistance and is
designed to be worked on the same way.

## AI-assisted contributions are welcome

You may use an LLM or coding agent — it's encouraged. **If you do, point your
agent at [`AGENTS.md`](AGENTS.md) first.** That file is the strict, machine-readable
playbook: the gate, the layering rules, the security model, and the honesty
requirements your change must satisfy. A PR from an agent that followed
`AGENTS.md` is what we want; one that skipped it is usually obvious and usually
bounced. Whether human- or AI-authored, every contribution meets the same bar.

## Quick start

```bash
git clone <repo> && cd <repo>
just build && just test
```

Run the full gate — **all green, zero warnings**:

```bash
just release-check
```

**This project has no CI, on purpose** — a supply-chain decision (no third-party
runners or marketplace actions). The gate is run manually and the maintainer
re-runs `just release-check` before merging. Paste its real output into your PR;
an honest red result beats a green claim that doesn't reproduce.

## The hard rules (summary — see [`AGENTS.md`](AGENTS.md))

1. Gate green, no suppression.
2. Layering is downward-only.
3. Crypto stays at the boundary; no plaintext secrets; fail closed.
4. Follow `<conventions-doc>`.
5. Be honest — back claims with output; state what you couldn't verify.
6. Keep scope tight.

## Opening a pull request

Conventional-commit messages; fill out the PR template honestly; **disclose AI
use** and add a `Co-Authored-By:` trailer if AI-authored.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Disclose it privately to the
maintainer first.

## Licence

`<PROJECT>` is licensed under `<LICENSE>`. By contributing, you agree your
contributions are licensed under the same terms.
