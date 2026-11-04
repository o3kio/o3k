#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$ROOT_DIR/bins/o3k/tests/fixtures/a10-release-verify.pub"
CHECKER="$ROOT_DIR/packaging/check-a10-publisher-disabled.sh"

canonical_marker="$(awk 'NF && $0 !~ /^-----/ { print; exit }' "$FIXTURE")"
embedded_marker="$(sed -n "s/^TEST_VERIFICATION_KEY_MARKER='\(.*\)'$/\1/p" "$CHECKER")"
[[ -n "$canonical_marker" && "$canonical_marker" == "$embedded_marker" ]] || {
  echo "embedded A10 public test-key marker drifted from $FIXTURE" >&2
  exit 1
}
echo "embedded A10 public test-key marker matches canonical fixture"
