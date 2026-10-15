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
  output="$(env -i PATH="$PATH" O3K_P15_7_PHASE="$phase" \
    O3K_REAL_HOST_ARTIFACT_DIR="$artifacts" \
    O3K_TESTLAB_STATE_ROOT="$state" \
    "$SCRIPT" 2>&1)" || status=$?
  [[ "$status" == 3 ]] || {
    echo "$phase did not stop at the policy boundary (exit $status)" >&2
    exit 1
  }
  grep -Fq 'status=DEFERRED_BY_POLICY' <<<"$output"
  grep -Fq 'no campaign or evidence state was changed' <<<"$output"
  test ! -e "$artifacts"
  test ! -e "$state"
done

echo "PP.5 scale/soak policy boundary guards passed"
