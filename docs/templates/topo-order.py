#!/usr/bin/env python3
"""Print a workspace's crates in dependency order (leaves first) for publishing.

`cargo publish` requires every dependency to already be on the registry, so
crates must be published deps-before-dependents. This emits exactly that order.

Usage:
    python3 topo-order.py [path-to-repo]      # default: current directory

Notes:
  - Normal + build deps are honored; DEV-dependencies are excluded — path-only
    dev-deps are stripped from the published manifest, so they don't constrain
    publish order (and versioned dev-deps in this ecosystem are non-forward).
  - Output is one space-separated line, ready to feed into publish.sh's CRATES.
  - For a CROSS-repo release (e.g. a foundation crate set + a framework that
    depends on it), publish the foundation repo's order first, then the
    dependent repo's.
"""
import json
import subprocess
import sys

repo = sys.argv[1] if len(sys.argv) > 1 else "."
md = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=repo
    )
)
names = {p["name"] for p in md["packages"]}
deps = {
    p["name"]: sorted(
        {d["name"] for d in p["dependencies"] if d["name"] in names and d["kind"] != "dev"}
    )
    for p in md["packages"]
}

order, seen = [], set()


def visit(n, stack):
    if n in seen or n in stack:  # `in stack` guards against (impossible) cycles
        return
    stack.add(n)
    for d in deps[n]:
        visit(d, stack)
    stack.discard(n)
    seen.add(n)
    order.append(n)


for n in sorted(deps):
    visit(n, set())

# Validate: every dependency precedes its dependent.
pos = {n: i for i, n in enumerate(order)}
bad = [(n, d) for n in order for d in deps[n] if pos[d] > pos[n]]
assert not bad, f"order error (cycle?): {bad}"

print(" ".join(order))
