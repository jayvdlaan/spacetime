#!/usr/bin/env bash
# Self-pacing crates.io publisher for a multi-crate workspace.
#
# Publishes crates in the order given (DEPENDENCY ORDER — leaves first; generate
# it with topo-order.py). On a 429 rate-limit it parses the server's stated reset
# time and sleeps exactly until then; skips crates whose version is already
# published; stops on any real (non-rate-limit) error. Safe to re-run — it resumes
# (already-published crates are skipped).
#
# crates.io rate limits to expect:
#   - NEW crate (new name): 1 per 10 minutes, burst of 5  -> a many-crate first
#     release runs for HOURS; run this in the background.
#   - NEW version of an existing crate: lenient (~1/min)  -> a patch refresh of an
#     existing workspace publishes in minutes.
#
# Usage:
#   cargo login <token>                 # crates.io versions are PERMANENT
#   REPO_DIR=. CRATES="$(python3 docs/templates/topo-order.py)" bash publish.sh
#   # for a long first release, run it in the background.
set -uo pipefail

REPO_DIR="${REPO_DIR:-.}"
CRATES="${CRATES:-}"   # dependency-ordered, space-separated; see topo-order.py

publish_one() {
  local crate="$1" tries=0 out reset now until s
  while :; do
    tries=$((tries+1))
    out=$(cd "$REPO_DIR" && cargo publish -p "$crate" 2>&1)
    if printf '%s' "$out" | grep -qiE 'Uploaded|already (exists|uploaded)|already been uploaded|is already uploaded'; then
      echo ">> OK: $crate"; return 0
    fi
    if printf '%s' "$out" | grep -qi '429 Too Many Requests'; then
      reset=$(printf '%s' "$out" | grep -oiP 'try again after \K.*?GMT' | head -1)
      now=$(date +%s)
      until=$(date -d "$reset" +%s 2>/dev/null || echo $((now + 600)))
      s=$(( until - now + 8 )); [ "$s" -lt 8 ] && s=8; [ "$s" -gt 1800 ] && s=1800
      echo ">> RATE-LIMIT on $crate (try $tries); sleeping ${s}s until '${reset:-unknown}'"
      sleep "$s"; continue
    fi
    echo ">> FATAL on $crate:"; printf '%s\n' "$out" | tail -25; return 1
  done
}

[ -n "$CRATES" ] || { echo "Set CRATES (dependency order). Generate with topo-order.py."; exit 2; }
for c in $CRATES; do publish_one "$c" || { echo "ABORTED at $c"; exit 1; }; done
echo "=== ALL CRATES PUBLISHED ==="
