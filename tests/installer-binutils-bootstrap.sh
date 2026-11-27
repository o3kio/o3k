#!/usr/bin/env bash
# Exercise the exact prerequisite helper used before authenticated bundle inspection.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-binutils-bootstrap.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

sed -n '/^ensure_bundle_inspection_tools()/,/^}/p' "$ROOT/packaging/get-o3k.sh" >"$WORK/helper.sh"
[[ -s "$WORK/helper.sh" ]] || { echo 'could not extract bundle inspection helper' >&2; exit 1; }

mkdir -p "$WORK/tools" "$WORK/failed-tools"
cat >"$WORK/tools/apt-get" <<'SH'
#!/bin/bash
printf '%s\n' "$*" >>"$O3K_TEST_APT_LOG"
if [[ "$*" == 'install -y binutils' ]]; then
  printf '#!/bin/sh\nexit 0\n' >"$O3K_TEST_TOOL_DIR/nm"
  printf '#!/bin/sh\nexit 0\n' >"$O3K_TEST_TOOL_DIR/readelf"
  /bin/chmod 0755 "$O3K_TEST_TOOL_DIR/nm" "$O3K_TEST_TOOL_DIR/readelf"
fi
SH
cat >"$WORK/failed-tools/apt-get" <<'SH'
#!/bin/bash
printf '%s\n' "$*" >>"$O3K_TEST_APT_LOG"
if [[ "$*" == 'install -y binutils' ]]; then exit 23; fi
SH
/bin/chmod 0755 "$WORK/tools/apt-get" "$WORK/failed-tools/apt-get"

cat >"$WORK/success.sh" <<'SH'
set -Eeuo pipefail
source "$O3K_TEST_HELPER"
ensure_bundle_inspection_tools
[[ "$APT_UPDATED" -eq 1 ]]
command -v nm >/dev/null
command -v readelf >/dev/null
printf 'verify-release-bundle\n' >>"$O3K_TEST_APT_LOG"
SH
: >"$WORK/success.log"
env -i PATH="$WORK/tools" O3K_TEST_HELPER="$WORK/helper.sh" \
  O3K_TEST_APT_LOG="$WORK/success.log" O3K_TEST_TOOL_DIR="$WORK/tools" \
  /bin/bash "$WORK/success.sh"
grep -Fxq 'update' "$WORK/success.log"
grep -Fxq 'install -y binutils' "$WORK/success.log"
[[ "$(tail -n 1 "$WORK/success.log")" == 'verify-release-bundle' ]]

cat >"$WORK/failure.sh" <<'SH'
set -Eeuo pipefail
source "$O3K_TEST_HELPER"
ensure_bundle_inspection_tools
printf 'application-installer-ran\n' >>"$O3K_TEST_APT_LOG"
SH
: >"$WORK/failure.log"
if env -i PATH="$WORK/failed-tools" O3K_TEST_HELPER="$WORK/helper.sh" \
  O3K_TEST_APT_LOG="$WORK/failure.log" O3K_TEST_TOOL_DIR="$WORK/failed-tools" \
  /bin/bash "$WORK/failure.sh"; then
  echo 'binutils install failure was not propagated' >&2
  exit 1
fi
! grep -Fq 'application-installer-ran' "$WORK/failure.log"
printf 'installer binutils bootstrap: PASS\n'
