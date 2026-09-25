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
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
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
host_count_lines="$(grep -Ec '^host_count=[0-9]+$' <<<"$marker" || true)"
[ "$host_count_lines" -eq 1 ] || fail "ownership marker must contain exactly one host_count"
host_count="$(sed -n 's/^host_count=//p' <<<"$marker")"
[[ "$host_count" =~ ^([1-9]|1[0-9]|2[0-6])$ ]] \
  || fail "ownership marker has invalid host_count: $host_count"

command -v virsh >/dev/null 2>&1 || fail "virsh is unavailable"

# --- exact run-generated removal ---------------------------------------------
# Prefix substring matching can overlap another valid RUN_ID. Derive only the
# exact host names encoded by this run's marker and the exact paths the
# provisioner creates.
for idx in $(seq 1 "$host_count"); do
  letter="$(printf '%b' "\\$(printf '%03o' "$((96 + idx))")")"
  dom="$PREFIX-host-$letter"
  if virsh -c qemu:///system dominfo "$dom" >/dev/null 2>&1; then
    state="$(virsh -c qemu:///system domstate "$dom" 2>/dev/null || printf unknown)"
    if [[ "$state" == running || "$state" == paused || "$state" == "in shutdown" ]]; then
      virsh -c qemu:///system destroy "$dom" >/dev/null 2>&1 || true
    fi
    # Do not ask libvirt to remove all attached storage: an operator may have
    # attached a foreign disk after provisioning. Remove exact owned files below.
    virsh -c qemu:///system undefine "$dom" >/dev/null 2>&1 \
      || fail "could not undefine owned domain $dom"
    echo "removed domain $dom"
  fi
done

for idx in $(seq 1 "$host_count"); do
  letter="$(printf '%b' "\\$(printf '%03o' "$((96 + idx))")")"
  for artifact in \
    "$IMGS_DIR/$PREFIX-host-$letter.qcow2" \
    "$IMGS_DIR/$PREFIX-host-$letter-seed.iso"; do
    [ -e "$artifact" ] || continue
    [ -f "$artifact" ] || fail "refusing to delete non-regular file (safety): $artifact"
    rm -f -- "$artifact"
    echo "removed artifact $artifact"
  done
done

# --- exact residue check ------------------------------------------------------
residue_domains=""
left=""
for idx in $(seq 1 "$host_count"); do
  letter="$(printf '%b' "\\$(printf '%03o' "$((96 + idx))")")"
  dom="$PREFIX-host-$letter"
  if virsh -c qemu:///system dominfo "$dom" >/dev/null 2>&1; then
    residue_domains+=" $dom"
  fi
  for artifact in \
    "$IMGS_DIR/$PREFIX-host-$letter.qcow2" \
    "$IMGS_DIR/$PREFIX-host-$letter-seed.iso"; do
    [ -e "$artifact" ] && left+=" $artifact"
  done
done
[ -z "$residue_domains" ] || fail "owned domains remain after teardown:$residue_domains"
[ -z "$left" ] || fail "owned volumes remain after teardown:$left"

rm -rf -- "$EVID"
echo "teardown complete: run $RUN_ID fully reclaimed (domains, exact disk/seed paths, evidence)."
exit 0
