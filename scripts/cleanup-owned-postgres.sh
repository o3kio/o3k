#!/usr/bin/env bash
set -Eeuo pipefail

phase="${1:?phase required}"
run_id="${2:?run id required}"
artifact="${3:?ownership artifact required}"
source_sha="${TARGET_SHA:-${GITHUB_SHA:-}}"
[[ "$phase" =~ ^[a-z0-9-]+$ && "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "unsafe PostgreSQL identity" >&2; exit 2; }
[[ "$source_sha" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "exact source SHA required" >&2; exit 2; }
container="o3k-${phase}-postgres-${run_id}"
if ! sudo -n docker inspect "$container" >/dev/null 2>&1; then
  exit 0
fi
[[ -f "$artifact" && ! -L "$artifact" ]] || { echo "PostgreSQL ownership ledger missing" >&2; exit 2; }
read -r expected_id expected_phase expected_run expected_sha expected_owner < <(python3 - "$artifact" <<'PY'
import json,sys
d=json.load(open(sys.argv[1], encoding='utf-8'))
print(d.get('container_id',''), d.get('phase',''), d.get('run_id',''), d.get('source_sha',''), d.get('owner',''))
PY
)
actual_id="$(sudo -n docker inspect -f '{{.Id}}' "$container")"
[[ "$actual_id" == "$expected_id" && "$expected_phase" == "$phase" && "$expected_run" == "$run_id" && "$expected_sha" == "$source_sha" && "$expected_owner" == o3k ]] \
  || { echo "PostgreSQL ownership ledger mismatch; refusing removal" >&2; exit 2; }
[[ "$(sudo -n docker inspect -f '{{index .Config.Labels \"o3k.owner\"}}' "$container")" == o3k ]] || { echo "PostgreSQL owner label missing" >&2; exit 2; }
[[ "$(sudo -n docker inspect -f '{{index .Config.Labels \"o3k.run_id\"}}' "$container")" == "$run_id" ]] || { echo "PostgreSQL run label mismatch" >&2; exit 2; }
[[ "$(sudo -n docker inspect -f '{{index .Config.Labels \"o3k.phase\"}}' "$container")" == "$phase" ]] || { echo "PostgreSQL phase label mismatch" >&2; exit 2; }
[[ "$(sudo -n docker inspect -f '{{index .Config.Labels \"o3k.source_sha\"}}' "$container")" == "$source_sha" ]] || { echo "PostgreSQL source label mismatch" >&2; exit 2; }
sudo -n docker rm --force "$container" >/dev/null
