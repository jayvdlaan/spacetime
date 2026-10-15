#!/usr/bin/env bash
# Regenerates every file under tests/vectors/ from scratch (contract §5.1).
#
# Requires: python3 (3.9+, stdlib only) and ssh-keygen (OpenSSH >= 8.2,
# developed against OpenSSH_10.2p1) on PATH. Deterministic and idempotent —
# re-running produces byte-identical output; `git diff` after a run should
# be empty unless the generator itself changed.
#
# The Rust test suite (tests/vectors.rs) never invokes this script and never
# needs ssh-keygen — it only reads the committed output.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "gen.sh: python3 not found on PATH (required)" >&2
    exit 1
fi

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "gen.sh: ssh-keygen not found on PATH (required to regenerate — the oracle for" >&2
    echo "  positive vectors and the cross-check for every vector)" >&2
    exit 1
fi

echo "gen.sh: $(ssh -V 2>&1 | head -1)"
python3 gen.py
