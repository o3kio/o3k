#!/usr/bin/env bash
set -Eeuo pipefail

# Bounded, explicitly allowlisted one-time sanitation of the 28 marker-less
# legacy P15.7 libvirt dir pools observed on runner-2404 (created before the
# definition of the durable `.o3k-p15-7-pool-owned` marker). This path may
# remove ONLY the pools named in the allowlist, and only after every live
# ownership check passes. It never creates markers and never touches a pool
# that carries one (those are governed by the automatic
# `p15-7-libvirt-storage-pool.sh cleanup-stale-pools` sweep).
#
# Usage: p15-7-legacy-pool-sanitation.sh ALLOWLIST_FILE
# The allowlist carries exactly one `pool-name run-id expected-path` triple per
# line; blank lines and `#` comment lines are ignored. The expected path is
# verified verbatim against the live pool XML target. Two owned layouts are
# accepted: the storage-image pool `$ROOT/o3k-p15-7-<run>` (name
# `o3k-p15-7-<run>`) and the journey workspace pool whose final directory
# component is `o3k-p15-7-journey-<run>` (name `o3k-p15-7-journey-<run>`,
# located under the journey's run-scoped temp workspace).

ROOT="${O3K_P15_7_LIBVIRT_IMAGE_ROOT:-/var/lib/libvirt/images}"
VIRSH=(virsh -c qemu:///system)
EXPECTED_HOST="runner-2404"
MARKER_NAME=".o3k-p15-7-pool-owned"
MAGIC="o3k-p15-7-pool-owned-v1"
PRESERVED=0

die() {
  echo "P15.7 legacy pool sanitation blocked: $*" >&2
  exit 1
}

if (($# != 1)); then
  echo "usage: $0 ALLOWLIST_FILE" >&2
  exit 2
fi
ALLOWLIST="$1"

# This is a one-time targeted path for a specific runner. Refuse to run
# anywhere else.
host="$(hostname 2>/dev/null || true)"
[[ -n "$host" && "$host" == "$EXPECTED_HOST" ]] \
  || die "refusing to run on host '${host:-unknown}' (expected $EXPECTED_HOST)"

[[ -r "$ALLOWLIST" && -f "$ALLOWLIST" && ! -L "$ALLOWLIST" ]] \
  || die "allowlist is not a readable regular file"
[[ "$ROOT" == /* && "$ROOT" != *..* && -d "$ROOT" && ! -L "$ROOT" ]] \
  || die "libvirt image root is unsafe"

# The actual sanitation result is per-pool: failures preserve the pool and
# are reported, but the overall run only fails if something could not be
# reaped. Listing failure is infrastructure and aborts immediately.
"${VIRSH[@]}" pool-list --all --name >/dev/null 2>&1 \
  || die "cannot inspect libvirt storage pools"

verify_pool_xml() {
  local name="$1" path="$2" xml
  xml="$("${VIRSH[@]}" pool-dumpxml "$name" 2>/dev/null)" || return 1
  python3 -c '
import sys
import xml.etree.ElementTree as ET

name, path = sys.argv[1:]
try:
    pool = ET.fromstring(sys.stdin.read())
except ET.ParseError:
    raise SystemExit(1)
valid = (
    pool.tag == "pool"
    and pool.get("type") == "dir"
    and pool.findtext("name") == name
    and pool.findtext("target/path") == path
)
raise SystemExit(0 if valid else 1)
' "$name" "$path" <<<"$xml"
}

# Any domain whose dumpxml contains the target path blocks the reap.
domain_references_path() {
  local path="$1" dom listing xml
  listing="$("${VIRSH[@]}" list --all --name 2>/dev/null || true)"
  while IFS= read -r dom; do
    [[ -n "$dom" ]] || continue
    xml="$("${VIRSH[@]}" dumpxml "$dom" 2>/dev/null || true)"
    if grep -Fq -- "$path" <<<"$xml"; then
      return 0
    fi
  done <<<"$listing"
  return 1
}

pool_absent() {
  local name="$1"
  ! "${VIRSH[@]}" pool-list --all --name 2>/dev/null | grep -Fxq -- "$name"
}

while IFS= read -r line; do
  [[ -n "$line" ]] && [[ "${line:0:1}" != "#" ]] || continue
  read -r pool_name run_id path extra <<<"$line"
  if [[ -n "${extra:-}" || -z "${pool_name:-}" || -z "${run_id:-}" || -z "${path:-}" ]]; then
    echo "PRESERVED ${pool_name:-?} malformed_allowlist_row"
    PRESERVED=1
    continue
  fi
  [[ "$run_id" =~ ^[0-9]+$ ]] \
    || { echo "PRESERVED $pool_name invalid_run_id"; PRESERVED=1; continue; }
  # Two owned layouts: the storage-image pool and the journey workspace pool.
  case "$pool_name" in
    "o3k-p15-7-$run_id")
      [[ "$path" == "$ROOT/o3k-p15-7-$run_id" ]] \
        || { echo "PRESERVED $pool_name path_not_run_owned"; PRESERVED=1; continue; }
      ;;
    "o3k-p15-7-journey-$run_id")
      [[ "$path" == /* && "$path" == */"o3k-p15-7-journey-$run_id" && "$path" != *..* ]] \
        || { echo "PRESERVED $pool_name path_not_journey_owned"; PRESERVED=1; continue; }
      ;;
    *)
      echo "PRESERVED $pool_name pool_name_not_run_owned"
      PRESERVED=1
      continue
      ;;
  esac
  [[ "$path" == /* && "$path" != *..* ]] \
    || { echo "PRESERVED $pool_name unsafe_path"; PRESERVED=1; continue; }

  # Already gone — idempotent success.
  if pool_absent "$pool_name"; then
    continue
  fi

  # A pool carrying the durable marker belongs to the automatic sweep, never
  # this legacy path.
  if [[ -e "$path/$MARKER_NAME" || -L "$path/$MARKER_NAME" ]]; then
    echo "PRESERVED $pool_name marker_present_governed_by_sweep"
    PRESERVED=1
    continue
  fi

  # Verify the live pool is exactly the run-owned dir pool at the expected
  # target path.
  if ! verify_pool_xml "$pool_name" "$path"; then
    echo "PRESERVED $pool_name pool_xml_not_exact_owned"
    PRESERVED=1
    continue
  fi

  # No live domain may reference the target path.
  if domain_references_path "$path"; then
    echo "PRESERVED $pool_name referenced_by_domain"
    PRESERVED=1
    continue
  fi

  state="$("${VIRSH[@]}" pool-info "$pool_name" | sed -n 's/^State:[[:space:]]*//p')" \
    || { echo "PRESERVED $pool_name cannot_inspect_state"; PRESERVED=1; continue; }
  case "$state" in
    running|active)
      "${VIRSH[@]}" pool-destroy "$pool_name" >/dev/null 2>&1 \
        || { echo "PRESERVED $pool_name destroy_failed"; PRESERVED=1; continue; }
      ;;
    inactive) ;;
    *) echo "PRESERVED $pool_name state_ambiguous"; PRESERVED=1; continue ;;
  esac

  "${VIRSH[@]}" pool-undefine "$pool_name" >/dev/null 2>&1 \
    || { echo "PRESERVED $pool_name undefine_failed"; PRESERVED=1; continue; }
  if ! pool_absent "$pool_name"; then
    echo "PRESERVED $pool_name remains_after_undefine"
    PRESERVED=1
    continue
  fi
  echo "REAPED $pool_name"
done <"$ALLOWLIST"

(( PRESERVED == 0 )) || exit 1
echo "P15.7 legacy pool sanitation completed"
