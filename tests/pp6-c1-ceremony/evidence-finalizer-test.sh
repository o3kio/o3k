#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
EVIDENCE="$TMP/evidence"
mkdir -p "$EVIDENCE/work"
printf 'retained evidence\n' >"$EVIDENCE/result.txt"
printf 'QEMU-owned transient scratch\n' >"$EVIDENCE/work/overlay.qcow2"
chmod 000 "$EVIDENCE/work/overlay.qcow2"
before_owner="$(stat -c '%u:%g:%a' "$EVIDENCE/work/overlay.qcow2")"

"$SCRIPT_DIR/finalize-evidence.sh" "$EVIDENCE"
(cd "$EVIDENCE" && sha256sum -c SHA256SUMS)
grep -Fq 'result.txt' "$EVIDENCE/SHA256SUMS"
if grep -Fq 'work/' "$EVIDENCE/SHA256SUMS"; then
  echo "transient scratch was included in qualification evidence" >&2
  exit 1
fi
after_owner="$(stat -c '%u:%g:%a' "$EVIDENCE/work/overlay.qcow2")"
[[ "$before_owner" == "$after_owner" ]]
