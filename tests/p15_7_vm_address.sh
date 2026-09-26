#!/usr/bin/env bash
# Deterministic regression harness for scripts/p15-7-vm-address.sh.
#
# Protects the fixes for the run 990923002 attempt-4 failure family:
#   1. the journey froze a stale DHCP lease (prior boot, same deterministic
#      run-owned MAC) for the whole SSH window and declared a healthy guest
#      unreachable;
#   2. the follow-up diagnostic reproduced several historical leases sharing
#      the same MAC (each boot mints a new DHCP client id), where the stale
#      entry sorted FIRST — first-match selection would freeze the stale
#      address again.
# The resolver must:
#   - only ever query libvirt by the recorded UUID (never by domain name);
#   - accept a lease only when its line carries the exact expected MAC;
#   - consider both the domain's lease projection and the network lease table;
#   - never return the gateway;
#   - select the FRESHEST lease per MAC (max expiry-time in libvirt's dnsmasq
#     status JSON) when several candidates share the MAC;
#   - emit every MAC-bound candidate when freshness data is unavailable, and
#     never silently guess;
#   - fail closed on wrong/absent UUID, unbound MAC, or no owned lease.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESOLVER="${ROOT_DIR}/scripts/p15-7-vm-address.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-vm-address.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
[[ -x "$RESOLVER" ]] || { echo "resolver is missing: $RESOLVER" >&2; exit 1; }

SHIM_DIR="$WORK_DIR/shim"
STATUS_DIR="$WORK_DIR/status"
mkdir -p "$SHIM_DIR" "$STATUS_DIR"

cat >"$SHIM_DIR/virsh" <<'SHIM'
#!/usr/bin/env bash
# Fake virsh for resolver unit tests. Behaviour is driven entirely by VIRSH_*
# environment variables; every invocation is appended to $VIRSH_LOG so tests
# can audit which identity (UUID vs name) was queried.
printf '%s\n' "$*" >>"${VIRSH_LOG:?VIRSH_LOG required}"
cmd=""
ident=""
source_kind=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c) shift 2 ;;
    --source) source_kind="$2"; shift 2 ;;
    --*) shift ;;
    *) if [[ -z "$cmd" ]]; then cmd="$1"; else ident="${ident:+$ident }$1"; fi; shift ;;
  esac
done
case "$cmd" in
  domstate)
    if [[ "$ident" == "${VIRSH_UUID:?}" && "${VIRSH_RUNNING:-1}" == 1 ]]; then
      echo "running"; exit 0
    fi
    echo "error: failed to get domain '$ident'" >&2; exit 1 ;;
  domiflist)
    if [[ "$ident" != "${VIRSH_UUID:?}" ]]; then
      echo "error: failed to get domain '$ident'" >&2; exit 1
    fi
    printf '%s\n' "${VIRSH_DOMIFLIST_TXT:?VIRSH_DOMIFLIST_TXT required}"; exit 0 ;;
  net-dumpxml)
    printf '%s\n' "${VIRSH_NETDUMXML_TXT:?VIRSH_NETDUMXML_TXT required}"; exit 0 ;;
  domifaddr)
    if [[ "$ident" != "${VIRSH_UUID:?}" ]]; then
      echo "error: failed to get domain '$ident'" >&2; exit 1
    fi
    case "$source_kind" in
      lease)
        if [[ -n "${VIRSH_LEASE_FLIP_AFTER:-}" ]]; then
          count_file="${VIRSH_COUNT_FILE:?}"
          n="$(cat "$count_file" 2>/dev/null || echo 0)"
          n=$((n + 1)); printf '%s' "$n" >"$count_file"
          if (( n <= VIRSH_LEASE_FLIP_AFTER )); then
            printf '%s\n' "${VIRSH_LEASE_STALE_TXT:-}"
          else
            printf '%s\n' "${VIRSH_LEASE_FRESH_TXT:?VIRSH_LEASE_FRESH_TXT required}"
          fi
        else
          printf '%s\n' "${VIRSH_LEASE_TXT:-}"
        fi
        exit 0 ;;
      arp) printf '%s\n' "${VIRSH_ARP_TXT:-}"; exit 0 ;;
      *) echo "error: unsupported --source '$source_kind'" >&2; exit 1 ;;
    esac ;;
  net-dhcp-leases)
    printf '%s\n' "${VIRSH_NET_LEASES_TXT:-}"; exit 0 ;;
  *) echo "error: unsupported fake virsh command '$cmd'" >&2; exit 1 ;;
esac
SHIM
chmod +x "$SHIM_DIR/virsh"

UUID="11111111-2222-4333-8444-555555555555"
MAC="52:54:00:0c:58:5f"
NETWORK="default"
GATEWAY="192.168.122.1"
IP="192.168.122.42"
STALE_IP="192.168.122.20"
OLDER_IP="192.168.122.77"

IFLIST_OK="Interface   Type      Source   Model    MAC
-------------------------------------------------------
vnet0       network   default  virtio   52:54:00:0c:58:5f"
NETXML_OK="<network>
  <bridge name='virbr0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'/>
</network>"

LEASE_OWNED="vnet0   52:54:00:0c:58:5f   ipv4   192.168.122.42/24"
LEASE_STALE="vnet0   52:54:00:0c:58:5f   ipv4   192.168.122.20/24"
LEASE_OLDER="vnet0   52:54:00:0c:58:5f   ipv4   192.168.122.77/24"
LEASE_OTHER="vnet0   52:54:00:de:ad:be   ipv4   192.168.122.88/24"
NET_LEASE_OWNED="2026-09-23 22:00:00   52:54:00:0c:58:5f   ipv4   192.168.122.42/24   block-a-host   duid"
NET_LEASE_STALE="2026-09-23 21:00:00   52:54:00:0c:58:5f   ipv4   192.168.122.20/24   -   duid"
NET_LEASE_OTHER="2026-09-23 22:00:00   52:54:00:de:ad:be   ipv4   192.168.122.88/24   foreign-host   duid"

write_status() { # json written as $STATUS_DIR/virbr0.status
  cat >"$STATUS_DIR/virbr0.status"
}

run_resolver() {
  local log="$WORK_DIR/virsh-$1.log"; shift
  env PATH="$SHIM_DIR:$PATH" VIRSH_LOG="$log" \
    O3K_P15_7_DNSMASQ_STATUS_DIR="$STATUS_DIR" \
    VIRSH_UUID="$UUID" VIRSH_RUNNING=1 VIRSH_NETDUMXML_TXT="$NETXML_OK" \
    "$@" bash "$RESOLVER" resolve "$UUID" "$MAC" "$NETWORK" "$GATEWAY"
}

expect_fail() { # name, then resolver env...
  local name="$1"; shift
  if run_resolver "$name" "$@" >"$WORK_DIR/$name.out" 2>"$WORK_DIR/$name.err"; then
    echo "FAIL: $name unexpectedly succeeded: $(cat "$WORK_DIR/$name.out")" >&2; exit 1
  fi
  echo "ok: $name fails closed"
}

# 1. Happy path: MAC-bound lease through the domain's UUID is accepted.
out="$(run_resolver happy \
  VIRSH_DOMIFLIST_TXT="$IFLIST_OK" VIRSH_LEASE_TXT="$LEASE_OWNED" VIRSH_ARP_TXT="")"
[[ "$out" == "$IP" ]] || { echo "FAIL: happy path returned '$out'" >&2; exit 1; }
echo "ok: MAC-bound UUID lease accepted ($out)"

# 2. UUID-only locator: the domain name must never appear as a query identity,
#    and only the read-only observation queries may be issued.
if grep -q 'o3k-' "$WORK_DIR/virsh-happy.log"; then
  echo "FAIL: resolver queried libvirt by domain name" >&2; exit 1
fi
while IFS= read -r line; do
  case "$line" in
    "-c qemu:///system domstate "*|"-c qemu:///system domiflist "*|\
    "-c qemu:///system domifaddr "*|"-c qemu:///system net-dhcp-leases "*|\
    "-c qemu:///system net-dumpxml "*) ;;
    *) echo "FAIL: unexpected fake-virsh invocation: $line" >&2; exit 1 ;;
  esac
done <"$WORK_DIR/virsh-happy.log"
echo "ok: every libvirt observation used the recorded UUID/network"

# 3. Stale/cross-MAC lease in domifaddr is rejected; the network lease table
#    for the exact expected MAC is an authoritative candidate source.
out="$(run_resolver fallback \
  VIRSH_DOMIFLIST_TXT="$IFLIST_OK" VIRSH_LEASE_TXT="$LEASE_OTHER" \
  VIRSH_NET_LEASES_TXT="$NET_LEASE_OWNED")"
[[ "$out" == "$IP" ]] || { echo "FAIL: fallback returned '$out'" >&2; exit 1; }
echo "ok: different-MAC lease rejected; exact-MAC network lease accepted"

# 4. Gateway is never returned, even when bound to the expected MAC.
expect_fail gateway \
  VIRSH_DOMIFLIST_TXT="$IFLIST_OK" \
  VIRSH_LEASE_TXT="vnet0   52:54:00:0c:58:5f   ipv4   192.168.122.1/24" \
  VIRSH_NET_LEASES_TXT="2026-09-23 22:00:00   52:54:00:0c:58:5f   ipv4   192.168.122.1/24   gw   duid"

# 5. No owned lease anywhere -> fail closed.
expect_fail no-lease \
  VIRSH_DOMIFLIST_TXT="$IFLIST_OK" VIRSH_LEASE_TXT="" \
  VIRSH_NET_LEASES_TXT="$NET_LEASE_OTHER"

# 6. Unknown/absent UUID -> fail closed (domain lookup itself fails).
log="$WORK_DIR/virsh-wronguuid.log"
if env PATH="$SHIM_DIR:$PATH" VIRSH_LOG="$log" \
    O3K_P15_7_DNSMASQ_STATUS_DIR="$STATUS_DIR" \
    VIRSH_UUID="$UUID" VIRSH_RUNNING=1 VIRSH_NETDUMXML_TXT="$NETXML_OK" \
    bash "$RESOLVER" resolve "99999999-8888-4777-8666-555555555555" "$MAC" "$NETWORK" "$GATEWAY" \
    >"$WORK_DIR/wronguuid.out" 2>/dev/null; then
  echo "FAIL: wrong UUID resolved" >&2; exit 1
fi
echo "ok: wrong/absent UUID fails closed"

# 7. Foreign UUID whose interfaces lack the expected MAC -> fail closed
#    (ownership is the MAC binding, never the UUID alone).
out="$(run_resolver foreignmac \
  VIRSH_DOMIFLIST_TXT="Interface   Type      Source   Model    MAC
-------------------------------------------------------
vnet0       network   default  virtio   52:54:00:de:ad:be" \
  VIRSH_LEASE_TXT="$LEASE_OWNED" VIRSH_NET_LEASES_TXT="$NET_LEASE_OWNED")" \
  && { echo "FAIL: foreign-MAC UUID resolved: $out" >&2; exit 1; }
echo "ok: UUID without the expected owned MAC fails closed"

# 8. Stale-same-MAC convergence across re-resolution (the journey pairs this
#    with an SSH probe, which is the actual liveness proof).
rm -f "$STATUS_DIR/virbr0.status"
count_file="$WORK_DIR/flip.count"
: >"$count_file"
candidate=""
for tick in $(seq 1 8); do
  candidate="$(env PATH="$SHIM_DIR:$PATH" \
    VIRSH_LOG="$WORK_DIR/virsh-flip.log" \
    O3K_P15_7_DNSMASQ_STATUS_DIR="$STATUS_DIR" \
    VIRSH_UUID="$UUID" VIRSH_RUNNING=1 VIRSH_NETDUMXML_TXT="$NETXML_OK" \
    VIRSH_DOMIFLIST_TXT="$IFLIST_OK" \
    VIRSH_LEASE_FLIP_AFTER=2 \
    VIRSH_COUNT_FILE="$count_file" \
    VIRSH_LEASE_STALE_TXT="$LEASE_STALE" \
    VIRSH_LEASE_FRESH_TXT="$LEASE_OWNED" \
    VIRSH_NET_LEASES_TXT="" \
    bash "$RESOLVER" resolve "$UUID" "$MAC" "$NETWORK" "$GATEWAY" 2>/dev/null || true)"
  [[ "$candidate" == "$IP" ]] && break
done
[[ "$candidate" == "$IP" ]] \
  || { echo "FAIL: re-resolving loop did not converge to the live address: '$candidate'" >&2; exit 1; }
(( $(cat "$count_file") >= 3 )) \
  || { echo "FAIL: flip scenario did not exercise the stale window" >&2; exit 1; }
echo "ok: stale-same-MAC lease converges to the live address across re-resolution"

# 9. MULTI-LEASE FIRST-MATCH REGRESSION (diag run 3): several historical
#    leases share the MAC and the stale entries sort first; the freshest
#    lease (max expiry-time in the dnsmasq status JSON) must win.
write_status <<JSON
[
  {"ip-address": "$STALE_IP", "mac-address": "$MAC", "client-id": "a",
   "expiry-time": 1000},
  {"ip-address": "$OLDER_IP", "mac-address": "$MAC", "client-id": "b",
   "expiry-time": 2000},
  {"ip-address": "$IP", "mac-address": "$MAC", "hostname": "block-a-host",
   "client-id": "c", "expiry-time": 3000}
]
JSON
out="$(run_resolver freshest \
  VIRSH_DOMIFLIST_TXT="$IFLIST_OK" \
  VIRSH_LEASE_TXT="$LEASE_STALE
$LEASE_OLDER
$LEASE_OWNED" \
  VIRSH_NET_LEASES_TXT="$NET_LEASE_STALE")"
[[ "$out" == "$IP" ]] \
  || { echo "FAIL: freshest selection returned '$out' (expected $IP)" >&2; exit 1; }
echo "ok: among same-MAC historical leases, the freshest (max expiry) wins"

# 10. Freshness data unavailable -> every MAC-bound candidate is emitted, one
#     per line, so the caller liveness-probes each instead of the resolver
#     silently picking (deterministic non-guessing contract).
rm -f "$STATUS_DIR/virbr0.status"
out="$(run_resolver noclue \
  VIRSH_DOMIFLIST_TXT="$IFLIST_OK" \
  VIRSH_LEASE_TXT="$LEASE_STALE
$LEASE_OWNED" \
  VIRSH_NET_LEASES_TXT="")"
[[ "$out" == "$STALE_IP
$IP" ]] \
  || { echo "FAIL: candidate fallback returned '$out'" >&2; exit 1; }
echo "ok: without freshness data, all MAC-bound candidates are emitted"

# 11. A freshest lease that is NOT among the observed candidates is never
#     trusted blindly; the candidate set is emitted instead.
write_status <<JSON
[
  {"ip-address": "$STALE_IP", "mac-address": "$MAC", "client-id": "a",
   "expiry-time": 1000},
  {"ip-address": "192.168.122.99", "mac-address": "$MAC", "client-id": "z",
   "expiry-time": 9999}
]
JSON
out="$(run_resolver orphanfresh \
  VIRSH_DOMIFLIST_TXT="$IFLIST_OK" \
  VIRSH_LEASE_TXT="$LEASE_STALE
$LEASE_OWNED" \
  VIRSH_NET_LEASES_TXT="")"
[[ "$out" == "$STALE_IP
$IP" ]] \
  || { echo "FAIL: orphan-freshness returned '$out'" >&2; exit 1; }
echo "ok: freshest entry absent from candidates -> candidate set emitted"

echo "P15.7 VM address resolver guards passed"
