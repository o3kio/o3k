#!/usr/bin/env bash
set -euo pipefail

# Five independent focused runs.  There is intentionally no retry: a failed
# process iteration is an acceptance failure, not a transient to hide.
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
source_sha=${1:-$(git rev-parse HEAD)}
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
    cargo test -p o3kd --test pp5_1035_evidence_process --all-features -- --nocapture
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
