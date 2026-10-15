#!/usr/bin/env bash
# Regenerates this directory's rage-oracle vectors (spacetime-age contract §5.3-§5.5).
# Idempotent: safe to re-run; it never reads its own prior output, only the fixed
# seeds in gen.py, so results are byte-identical run to run except where `rage`
# itself injects fresh randomness (the rage_* vectors — decrypt-only oracles).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

command -v rage >/dev/null || { echo "rage not found on PATH (need 0.12.1)" >&2; exit 1; }
command -v rage-keygen >/dev/null || { echo "rage-keygen not found on PATH (need 0.12.1)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found on PATH (need 3.9+)" >&2; exit 1; }

echo "rage:         $(rage --version)"
echo "rage-keygen:  $(rage-keygen --version)"
echo "python3:      $(python3 --version)"
if command -v ssh-keygen >/dev/null; then
  echo "ssh-keygen:   $(ssh-keygen -V 2>&1 | head -1 || ssh-keygen -\? 2>&1 | head -1 || echo present)"
else
  echo "ssh-keygen:   not found (fingerprint cross-check will be skipped, not required)"
fi

exec python3 gen.py
