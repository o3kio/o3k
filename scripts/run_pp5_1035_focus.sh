#!/usr/bin/env bash
set -euo pipefail

# This runner is only the run-owned SQLite/localhost #1035 lane. It must not
# receive an external database, provider, TestLab, or guest configuration.
# It creates daemon processes and writes acceptance evidence, so an operator
# must opt in with a deliberate acknowledgment before any setup.
if [[ "${O3K_PP5_1035_EXPLICIT_AUTH:-}" != "RUN_OWNED_SQLITE_LOCALHOST_1035" ]]; then
  echo "refusing PP.5 #1035 focused run: set O3K_PP5_1035_EXPLICIT_AUTH=RUN_OWNED_SQLITE_LOCALHOST_1035" >&2
  exit 77
fi
command -v cargo >/dev/null 2>&1 || {
  echo "refusing PP.5 #1035 focused run: cargo is unavailable" >&2
  exit 78
}
command -v python3 >/dev/null 2>&1 || {
  echo "refusing PP.5 #1035 focused run: python3 is unavailable" >&2
  exit 78
}
[[ "$(uname -s)" == "Linux" ]] || {
  echo "refusing PP.5 #1035 focused run: Linux is required" >&2
  exit 78
}
command -v ss >/dev/null 2>&1 || {
  echo "refusing PP.5 #1035 focused run: ss is unavailable" >&2
  exit 78
}

# Five independent focused runs.  There is intentionally no retry: a failed
# process iteration is an acceptance failure, not a transient to hide.
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
source_sha=${1:-$(git rev-parse HEAD)}
head_sha=$(git rev-parse HEAD)
if [[ "$source_sha" != "$head_sha" ]]; then
  echo "refusing PP.5 #1035 focused run: source SHA must equal HEAD ($head_sha)" >&2
  exit 78
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing PP.5 #1035 focused run: worktree must be clean" >&2
  exit 78
fi
manifest=${O3K_PP5_1035_MANIFEST:-"bins/o3kd/target/pp5/pp5-1035-focused-manifest.json"}
manifest="${repo_root}/${manifest#./}"
mkdir -p "$(dirname "$manifest")"
tmp_manifest="${manifest}.tmp"
artifacts=()
for iteration in 1 2 3 4 5; do
  run_id=$(python3 - <<'PY'
import uuid
print(uuid.uuid7() if hasattr(uuid, "uuid7") else uuid.uuid4())
PY
)
  artifact="${repo_root}/bins/o3kd/target/pp5/${run_id}/pp5-1035-restart-evidence.json"
  echo "focused PP.5 #1035 run ${iteration}/5: ${run_id}"
  O3K_PP5_1035_RUN_ID="$run_id" \
  O3K_PP5_1035_SOURCE_SHA="$source_sha" \
  O3K_PP5_1035_EVIDENCE_FILE="$artifact" \
  env -u O3K_DATABASE_URL -u O3K_DATABASE_BACKEND -u O3K_TEST_DATABASE_PURPOSE \
    cargo test -p o3kd --test pp5_1035_evidence_process --all-features pp5_1035_restart_writes_fail_closed_evidence -- --ignored --nocapture
  python3 scripts/validate_pp5_1035_evidence.py "$artifact" --source-sha "$source_sha"
  artifacts+=("$artifact")
done

python3 - "$manifest" "$source_sha" "${artifacts[@]}" <<'PY'
import hashlib, json, os, sys
manifest, source_sha, *paths = sys.argv[1:]
entries = []
for path in paths:
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    entries.append({"artifact": path, "sha256": digest})
value = {"schema": "o3k.pp5-1035-focused-manifest.v1", "source_sha": source_sha, "iterations": entries, "verdict": "accepted"}
tmp = manifest + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(value, fh, indent=2); fh.write("\n"); fh.flush(); os.fsync(fh.fileno())
os.replace(tmp, manifest)
PY
echo "FOCUSED #1035 = ACCEPTED (5/5)"
