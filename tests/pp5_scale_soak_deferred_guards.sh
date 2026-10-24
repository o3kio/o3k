#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/p15-7-real-host-journey.sh"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

for phase in s3-scale s10-scale s20-scale k-min k-full; do
  artifacts="$tmp/artifacts-$phase"
  state="$tmp/state-$phase"
  status=0
  env -i PATH="$PATH" O3K_P15_7_PHASE="$phase" \
    O3K_REAL_HOST_ARTIFACT_DIR="$artifacts" \
    O3K_TESTLAB_STATE_ROOT="$state" \
    "$SCRIPT" >"$tmp/status-$phase.json" 2>"$tmp/diagnostic-$phase.txt" || status=$?
  [[ "$status" == 3 ]] || {
    echo "$phase did not stop at the policy boundary (exit $status)" >&2
    exit 1
  }
  grep -Fq 'status=DEFERRED_BY_POLICY' "$tmp/diagnostic-$phase.txt"
  grep -Fq 'no campaign or evidence state was changed' "$tmp/diagnostic-$phase.txt"
  python3 - "$phase" "$tmp/status-$phase.json" <<'PY'
import json
import pathlib
import sys

lane, status_path = sys.argv[1:]
record = json.loads(pathlib.Path(status_path).read_text(encoding="utf-8"))
assert record == {
    "record_type": "o3k.pp5-lane-disposition.v1",
    "lane": lane,
    "status": "DEFERRED_BY_POLICY",
    "acceptance_result": "NOT_RUN",
    "evidence_produced": False,
    "state_mutated": False,
}
PY
  test ! -e "$artifacts"
  test ! -e "$state"
done

invalid_status=0
invalid_output="$(bash -c 'source "$1"; pp5_deferred_lane unknown-lane' _ \
  "$ROOT/scripts/pp5-policy.sh" 2>&1)" || invalid_status=$?
[[ "$invalid_status" == 2 ]]
! grep -Fq 'o3k.pp5-lane-disposition.v1' <<<"$invalid_output"

echo "PP.5 scale/soak policy boundary guards passed"
