#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-lock.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
LOCK="$WORK_DIR/campaign.lock"
SHA=0123456789abcdef0123456789abcdef01234567
export O3K_P15_7_CAMPAIGN_LOCK_PATH="$LOCK" O3K_P15_7_RUN_ID=lock-run O3K_P15_7_SOURCE_SHA="$SHA"

python3 "$ROOT_DIR/scripts/p15-7-campaign-lock.py" acquire >/dev/null
test -f "$LOCK/owner.json"
if python3 "$ROOT_DIR/scripts/p15-7-campaign-lock.py" acquire >/dev/null 2>&1; then
  echo "second campaign lock acquisition succeeded" >&2
  exit 1
fi

O3K_P15_7_RUN_ID=foreign-run python3 "$ROOT_DIR/scripts/p15-7-campaign-lock.py" release >/dev/null 2>&1 && {
  echo "foreign campaign lock release succeeded" >&2
  exit 1
}
test -f "$LOCK/owner.json"
python3 "$ROOT_DIR/scripts/p15-7-campaign-lock.py" release
test ! -e "$LOCK"

mkdir "$LOCK"
printf '{"run_id":"foreign","source_sha":"%s"}\n' "$SHA" >"$LOCK/owner.json"
if python3 "$ROOT_DIR/scripts/p15-7-campaign-lock.py" release >/dev/null 2>&1; then
  echo "foreign lock metadata was removed" >&2
  exit 1
fi
test -f "$LOCK/owner.json"

echo "P15.7 campaign lock guards PASS"
