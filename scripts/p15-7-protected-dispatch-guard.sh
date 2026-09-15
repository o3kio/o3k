#!/usr/bin/env bash
set -Eeuo pipefail

# Called by the cheap GitHub-hosted dispatcher, before it requests a protected
# runner. A single protected TestLab is exclusive; duplicates are rejected.
TARGET_SHA="${1:-${GITHUB_SHA:-}}"
[[ "$TARGET_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "invalid target SHA" >&2; exit 2; }
command -v gh >/dev/null 2>&1 || { echo "gh is required" >&2; exit 2; }
validation_runs="$(gh run list --workflow real-host-validation.yml --limit 100 \
  --json databaseId,status,headSha,event 2>/dev/null)" \
  || { echo "unable to inspect protected validation runs" >&2; exit 2; }
preflight_runs="$(gh run list --workflow p15-7-protected-preflight.yml --limit 100 \
  --json databaseId,status,headSha,event 2>/dev/null)" \
  || { echo "unable to inspect protected preflight runs" >&2; exit 2; }
python3 - "$validation_runs" "$preflight_runs" "$TARGET_SHA" <<'PY'
import json, sys
runs = json.loads(sys.argv[1] or "[]") + json.loads(sys.argv[2] or "[]")
active = [r for r in runs if r.get("status") in {"queued", "in_progress", "waiting", "pending"}]
if active:
    ids = ",".join(str(r.get("databaseId")) for r in active)
    raise SystemExit(f"duplicate_protected_dispatch: active real-host run(s) {ids}")
PY
echo "protected dispatch slot available for ${TARGET_SHA}"
