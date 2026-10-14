#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/p15-7-workload-image-marker.sh
source "$ROOT_DIR/scripts/p15-7-workload-image-marker.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-image-marker.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT

RUN_ID="marker-test-123"
MARKER="$WORK_DIR/image.o3k-owned"
write_marker() {
  printf 'o3k-disposable-image-v1\nrun=%s\nphase=%s\n' "$1" "$2" >"$MARKER"
}
expect_rejected() {
  local description="$1"
  shift
  if p15_7_verify_disposable_image_marker "$@"; then
    echo "image marker guard accepted $description" >&2
    exit 1
  fi
}

write_marker "$RUN_ID" generic
p15_7_verify_disposable_image_marker "$MARKER" "$RUN_ID" generic
p15_7_verify_disposable_image_marker "$MARKER" "$RUN_ID"
expect_rejected "generic marker in PP.5 context" "$MARKER" "$RUN_ID" pp5

write_marker "$RUN_ID" pp5
p15_7_verify_disposable_image_marker "$MARKER" "$RUN_ID" pp5
expect_rejected "PP.5 marker in generic context" "$MARKER" "$RUN_ID" generic
expect_rejected "wrong run ID" "$MARKER" other-run pp5
expect_rejected "unsupported expected phase" "$MARKER" "$RUN_ID" diagnostic
expect_rejected "missing expected phase" "$MARKER" "$RUN_ID" ""
printf -v LONG_RUN '%0230d' 0
write_marker "$LONG_RUN" pp5
expect_rejected "oversized marker" "$MARKER" "$LONG_RUN" pp5

printf 'o3k-disposable-image-v1\nrun=%s\nphase=pp5\nphase=generic\n' "$RUN_ID" >"$MARKER"
expect_rejected "duplicate phase" "$MARKER" "$RUN_ID" pp5
printf 'o3k-disposable-image-v1\nrun=%s\nphase=pp5\nextra=value\n' "$RUN_ID" >"$MARKER"
expect_rejected "unexpected field" "$MARKER" "$RUN_ID" pp5
rm -f -- "$MARKER"
ln -s "$WORK_DIR/elsewhere" "$MARKER"
expect_rejected "symlink marker" "$MARKER" "$RUN_ID" pp5

echo "P15.7 workload image marker tests passed"
