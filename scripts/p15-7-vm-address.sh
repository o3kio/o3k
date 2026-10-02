#!/usr/bin/env bash
set -Eeuo pipefail

# Resolve the current IPv4 address of a run-owned libvirt VM.
#
# Identity contract (the journey captures the libvirt UUID once, immediately
# after virt-install, and never re-derives it):
#   - the recorded UUID is the lifecycle/observation locator;
#   - the run-owned MAC is the network ownership proof;
#   - a DHCP lease is accepted only when its line is bound to the exact
#     expected MAC; a lease alone is NOT liveness proof;
#   - when several historical leases share the MAC (every rerun of a
#     run-derived MAC mints a new DHCP client id, so dnsmasq accumulates one
#     lease per boot), the FRESHEST lease wins; freshness is read from
#     libvirt's dnsmasq status JSON (max expiry-time per MAC). When that
#     source is unavailable the resolver emits every MAC-bound candidate
#     (one per line) and lets the caller liveness-probe each over SSH —
#     it never silently picks one.
#
# Why all of this is required: the journey derives its MACs deterministically
# from the run id, and dnsmasq retains leases for up to an hour. Reruns of the
# same run id can therefore observe stale addresses. The P15.7 failure
# reproduced on 2026-09-23 (run 990923002, attempt 4) froze exactly such a
# stale address for the whole SSH budget while the live guest held a different
# one, and the follow-up diagnostic run showed three same-MAC leases where the
# stale entry sorted first. This resolver re-resolves from live lease state on
# every invocation so the caller never freezes a stale address, and it only
# ever queries libvirt by UUID — never by domain name.

die() { echo "p15-7-vm-address: $*" >&2; exit 1; }

VIRSH=(virsh -c qemu:///system)
# libvirt keeps the dnsmasq lease set as JSON via its leaseshelper; the
# directory is overridable for deterministic testing.
DNSMASQ_STATUS_DIR="${O3K_P15_7_DNSMASQ_STATUS_DIR:-/var/lib/libvirt/dnsmasq}"

resolve() {
  [[ $# == 4 ]] || die "usage: p15-7-vm-address.sh resolve DOMAIN_UUID EXPECTED_MAC NETWORK GATEWAY"
  local uuid="$1" mac="$2" network="$3" gateway="$4" ip=""
  [[ "$uuid" =~ ^[0-9a-fA-F-]{36}$ ]] || die "domain UUID is invalid"
  [[ "$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || die "expected MAC is invalid"
  [[ "$network" =~ ^[A-Za-z0-9._-]+$ ]] || die "network name is unsafe"
  [[ "$gateway" =~ ^[0-9.]+$ ]] || die "gateway is invalid"
  # The recorded UUID must identify a live domain. Name-based fallbacks are
  # deliberately absent: the UUID was captured at provision time and is the
  # only locator this helper trusts.
  "${VIRSH[@]}" domstate "$uuid" >/dev/null 2>&1 || return 1
  # The domain's interface set must contain the exact expected MAC. A UUID
  # whose interfaces carry different MACs does not identify the expected
  # owned VM; never guess from other interfaces.
  "${VIRSH[@]}" domiflist "$uuid" 2>/dev/null | awk 'NR>2{print $5}' \
    | grep -Fxiq -- "$mac" || return 1
  # Candidate sources: the lease projection through the domain's UUID, then
  # the network's authoritative DHCP lease table. Only lines carrying the
  # exact expected MAC contribute; the gateway is never a candidate. Every
  # unique candidate is printed (normally exactly one).
  {
    "${VIRSH[@]}" domifaddr "$uuid" --source lease 2>/dev/null
    "${VIRSH[@]}" net-dhcp-leases "$network" 2>/dev/null
  } | awk -v m="$mac" -v gw="$gateway" '
    {for (i = 1; i <= NF; i++) if (tolower($i) == tolower(m)) {
      for (j = 1; j <= NF; j++) if ($j ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\//) {
        sub(/\/.*/, "", $j)
        if ($j != gw && !seen[$j]++) print $j
        break}}}
  ' >"$work_candidates" 2>/dev/null || return 1
  local -a candidates=()
  while IFS= read -r ip; do candidates+=("$ip"); done <"$work_candidates"
  [[ "${#candidates[@]}" -ge 1 ]] || return 1
  if [[ "${#candidates[@]}" == 1 ]]; then
    printf '%s\n' "${candidates[0]}"
    return 0
  fi
  # Several historical leases share the MAC: disambiguate by freshness from
  # libvirt's dnsmasq status JSON (max expiry-time per MAC). A newer boot
  # always carries a newer expiry than the leases it inherited.
  local bridge="" status="" fresh=""
  bridge="$("${VIRSH[@]}" net-dumpxml "$network" 2>/dev/null | python3 -c '
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.stdin).getroot()
except ET.ParseError:
    raise SystemExit(0)
for e in root.iter():
    if e.tag.rsplit("}", 1)[-1] == "bridge" and e.get("name"):
        print(e.get("name")); break' || true)"
  for status in "$DNSMASQ_STATUS_DIR/$bridge.status" "$DNSMASQ_STATUS_DIR/$network.status"; do
    [[ -f "$status" && ! -L "$status" ]] || continue
    fresh="$(DNSMASQ_STATUS_FILE="$status" EXPECTED_MAC="$mac" python3 - <<'PY' || true
import json, os
mac = os.environ["EXPECTED_MAC"].lower()
try:
    leases = json.load(open(os.environ["DNSMASQ_STATUS_FILE"], encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(0)
best = None
for lease in leases:
    if str(lease.get("mac-address", "")).lower() != mac:
        continue
    expiry = lease.get("expiry-time")
    ip = lease.get("ip-address", "")
    if not ip or not isinstance(expiry, (int, float)):
        continue
    if best is None or expiry > best[0]:
        best = (expiry, ip)
if best:
    print(best[1])
PY
    )"
    [[ -n "$fresh" ]] && break
  done
  if [[ "$fresh" =~ ^[0-9.]+$ && "$fresh" != "$gateway" ]]; then
    local c
    for c in "${candidates[@]}"; do
      if [[ "$c" == "$fresh" ]]; then
        printf '%s\n' "$fresh"
        return 0
      fi
    done
    # The freshest lease is not among the observed candidates; do not trust
    # it blindly — fall through to the candidate set.
  fi
  # No freshness source: emit every MAC-bound candidate so the caller proves
  # liveness per candidate (SSH) instead of this helper guessing one.
  printf '%s\n' "${candidates[@]}"
}

work_candidates=""
case "${1:-}" in
  resolve)
    shift
    work_candidates="$(mktemp "${TMPDIR:-/tmp}/o3k-p15-7-vm-address.XXXXXX")" \
      || die "cannot create candidate workspace"
    trap 'rm -f -- "$work_candidates"' EXIT
    resolve "$@"
    ;;
  *) die "unknown command: ${1:-<none>}" ;;
esac
