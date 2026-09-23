#!/usr/bin/env bash
# PP.5 Small Edge campaign teardown: remove EXACTLY this run's domains, disks,
# seed ISOs and inventory, after verifying ownership. Never touches unrelated
# domains (e.g. the existing `p14-*` shells), never deletes the shared base
# image, and fails closed if any owned residue remains.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CAMPAIGN_DIR="$REPO_ROOT/tests/pp5-small-edge-campaign"
RUNS_ROOT="$CAMPAIGN_DIR/runs"
IMGS_DIR="${O3K_PP5_IMAGES_DIR:-/var/lib/libvirt/images}"
BASE_IMG="${O3K_PP5_BASE_IMAGE:-/var/lib/libvirt/images/noble-server-cloudimg-amd64.img}"

RUN_ID="${O3K_PP5_RUN_ID:-${1:-}}"
[[ -n "$RUN_ID" ]] || { echo "teardown-hosts: O3K_PP5_RUN_ID (or argv) is required" >&2; exit 2; }
[[ "$RUN_ID" =~ ^[A-Za-z0-9_.-]+$ ]] \
  || { echo "teardown-hosts: invalid RUN_ID '$RUN_ID'" >&2; exit 2; }

PREFIX="o3k-pp5-$RUN_ID"
EVID="$RUNS_ROOT/$RUN_ID"

fail() { echo "teardown-hosts failed: $1" >&2; exit 1; }

# --- verify ownership before removing anything ------------------------------
[ -d "$EVID" ] && [ ! -L "$EVID" ] || fail "no run evidence directory: $EVID"
[ -f "$EVID/.o3k-pp5-owned" ] && [ ! -L "$EVID/.o3k-pp5-owned" ] \
  || fail "missing ownership marker: $EVID/.o3k-pp5-owned"
marker="$(cat "$EVID/.o3k-pp5-owned")"
grep -Fqx 'o3k-pp5-owned-v1' <<<"$marker" || fail "foreign ownership marker in $EVID"
grep -Fqx "prefix=$PREFIX" <<<"$marker" || fail "ownership marker prefix mismatch (expected $PREFIX)"
grep -Fqx "run=$RUN_ID" <<<"$marker" || fail "ownership marker run mismatch"

command -v virsh >/dev/null 2>&1 || fail "virsh is unavailable"

# --- inventory-driven removal -------------------------------------------------
# Every name we may remove is derived from our exact prefix, never guessed.
readarray -t our_domains < <(virsh -c qemu:///system list --all --name \
  | grep -F -e "$PREFIX-" || true)
for dom in "${our_domains[@]}"; do
  [[ -n "$dom" ]] || continue
  state="$(virsh -c qemu:///system domstate "$dom" 2>/dev/null || printf unknown)"
  if [[ "$state" == running || "$state" == paused || "$state" == "in shutdown" ]]; then
    virsh -c qemu:///system destroy "$dom" >/dev/null 2>&1 || true
  fi
  virsh -c qemu:///system undefine --remove-all-storage "$dom" >/dev/null 2>&1 \
    || virsh -c qemu:///system undefine "$dom" >/dev/null 2>&1 \
    || fail "could not undefine owned domain $dom"
  echo "removed domain $dom"
done

# Remove owned volumes and seed ISOs by exact prefix only. The shared base image
# does not match the prefix and is therefore never a candidate for deletion.
for glob in "$IMGS_DIR/$PREFIX-host-"*.qcow2 "$IMGS_DIR/$PREFIX-host-"*-seed.iso; do
  [ -e "$glob" ] || continue          # skip the literal glob when nothing matches
  [ -f "$glob" ] || fail "refusing to delete non-regular file (safety): $glob"
  rm -f -- "$glob"
  echo "removed volume $glob"
done

# --- residue check: fail closed if anything we own still exists --------------
residue_domains="$(virsh -c qemu:///system list --all --name | grep -F -e "$PREFIX-" || true)"
[ -z "$residue_domains" ] || fail "owned domains remain after teardown: $residue_domains"
left=""
for glob in "$IMGS_DIR/$PREFIX-"*.qcow2 "$IMGS_DIR/$PREFIX-"*-seed.iso; do
  [ -e "$glob" ] && left="$left $glob"
done
[ -z "$left" ] || fail "owned volumes remain after teardown:$left"

rm -rf -- "$EVID"
echo "teardown complete: prefix $PREFIX fully reclaimed (domains, volumes, seeds, evidence)."
exit 0
