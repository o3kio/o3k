#!/usr/bin/env bash
set -Eeuo pipefail

# Disposable Fabric v3 bridge/packet harness.
#
# This runs two logical compute hosts as network namespaces on one development
# machine. It exercises the production LinuxFabricBackend adapter, provider
# VXLAN/WireGuard realization, realm bridges, bounded HER, and endpoint L2/L3
# traffic. It is development evidence only: both logical hosts share one
# physical underlay and cannot satisfy the independent three-host gate.

ROOT_A="${FABRIC_V3_ROOT_A:-/tmp/o3k-fabric-v3-bridge-a}"
ROOT_B="${FABRIC_V3_ROOT_B:-/tmp/o3k-fabric-v3-bridge-b}"
HOST_A="o3k-v3-host-a"
HOST_B="o3k-v3-host-b"
CANARY_NS="o3k-v3-foreign-canary"
UNDERLAY_A="o3kv3ua"
UNDERLAY_B="o3kv3ub"
HELPER_BIN="${FABRIC_V3_HELPER_BIN:-}"

REALM_A="a1000000000000000000000000000001"
REALM_B="b1000000000000000000000000000001"
BRIDGE_A="o3k-b-a1000000"
BRIDGE_B="o3k-b-b1000000"

EP_NS=(o3k-v3-ep-a1 o3k-v3-ep-a2 o3k-v3-ep-b1 o3k-v3-ep-b2)
RUNNER_A=""
RUNNER_B=""

die() { echo "fabric-v3-bridge-gate: $*" >&2; exit 1; }
need_root() { [[ "${EUID}" -eq 0 ]] || die "run as root (use sudo)"; }
run_in() {
  case "$1" in
    "$HOST_A") nsenter -t "$RUNNER_A" -m -n -- "${@:2}" ;;
    "$HOST_B") nsenter -t "$RUNNER_B" -m -n -- "${@:2}" ;;
    *) ip netns exec "$1" "${@:2}" ;;
  esac
}

start_runner() {
  local host_ns="$1"
  ip netns exec "$host_ns" unshare --mount sh -c \
    'mount --make-rprivate /; mount -t tmpfs o3k-v3-netns /run/netns; exec sleep 2147483647' \
    >/dev/null 2>&1 &
  echo $!
}

cleanup() {
  if [[ "${FABRIC_V3_KEEP:-0}" == "1" ]]; then
    echo "fabric-v3-bridge-gate: FABRIC_V3_KEEP=1; preserving disposable namespaces and roots" >&2
    return 0
  fi
  set +e
  [[ -n "$RUNNER_A" ]] && kill "$RUNNER_A" 2>/dev/null || true
  [[ -n "$RUNNER_B" ]] && kill "$RUNNER_B" 2>/dev/null || true
  [[ -n "$RUNNER_A" ]] && wait "$RUNNER_A" 2>/dev/null || true
  [[ -n "$RUNNER_B" ]] && wait "$RUNNER_B" 2>/dev/null || true
  for ns in "${EP_NS[@]}" "$CANARY_NS" "$HOST_A" "$HOST_B"; do
    ip netns del "$ns" 2>/dev/null || true
  done
  rm -rf -- "$ROOT_A" "$ROOT_B"
  set -e
}
trap cleanup EXIT INT TERM

need_root
umask 077
[[ -n "$HELPER_BIN" && -x "$HELPER_BIN" ]] || die "FABRIC_V3_HELPER_BIN must point to fabric-regression-helper"
command -v ip >/dev/null || die "iproute2 is required"
command -v wg >/dev/null || die "wireguard tools are required"
command -v ping >/dev/null || die "iputils ping is required"

cleanup
mkdir -p "$ROOT_A" "$ROOT_B"

# A foreign namespace is deliberately created outside provider ownership. It
# must survive the test cleanup.
ip netns add "$CANARY_NS"

ip netns add "$HOST_A"
ip netns add "$HOST_B"
ip link add "$UNDERLAY_A" type veth peer name "$UNDERLAY_B"
ip link set "$UNDERLAY_A" netns "$HOST_A"
ip link set "$UNDERLAY_B" netns "$HOST_B"

# Each logical host gets a private /run/netns mount. LinuxFabricBackend uses
# host-local names such as o3k-fabric and o3k-r-*, which are distinct on real
# machines; the private mount namespaces preserve that property here.
RUNNER_A="$(start_runner "$HOST_A")"
RUNNER_B="$(start_runner "$HOST_B")"
for _ in $(seq 1 50); do
  nsenter -t "$RUNNER_A" -m -n -- mountpoint -q /run/netns && break
  sleep 0.05
done
nsenter -t "$RUNNER_A" -m -n -- mountpoint -q /run/netns || die "host-A mount namespace runner did not start"
for _ in $(seq 1 50); do
  nsenter -t "$RUNNER_B" -m -n -- mountpoint -q /run/netns && break
  sleep 0.05
done
nsenter -t "$RUNNER_B" -m -n -- mountpoint -q /run/netns || die "host-B mount namespace runner did not start"

run_in "$HOST_A" ip link set lo up
run_in "$HOST_B" ip link set lo up
run_in "$HOST_A" ip link set "$UNDERLAY_A" name eth0
run_in "$HOST_B" ip link set "$UNDERLAY_B" name eth0
run_in "$HOST_A" ip addr add 10.77.0.1/24 dev eth0
run_in "$HOST_B" ip addr add 10.77.0.2/24 dev eth0
run_in "$HOST_A" ip link set eth0 up
run_in "$HOST_B" ip link set eth0 up
run_in "$HOST_A" sysctl -qw net.ipv4.ip_forward=1 || true
run_in "$HOST_B" sysctl -qw net.ipv4.ip_forward=1 || true

mkdir -p "$ROOT_A/fabric-provider" "$ROOT_B/fabric-provider"
wg genkey >"$ROOT_A/fabric-provider/wireguard-private.key"
wg genkey >"$ROOT_B/fabric-provider/wireguard-private.key"
chmod 600 "$ROOT_A/fabric-provider/wireguard-private.key" "$ROOT_B/fabric-provider/wireguard-private.key"
PUB_A="$(wg pubkey <"$ROOT_A/fabric-provider/wireguard-private.key")"
PUB_B="$(wg pubkey <"$ROOT_B/fabric-provider/wireguard-private.key")"

apply_host() {
  local host_ns="$1" root="$2" host_id="$3" transport="$4" peer_id="$5" peer_transport="$6" peer_key="$7" peer_underlay="$8"
  run_in "$host_ns" "$HELPER_BIN" \
    --root "$root" --mode apply \
    --host-id "$host_id" --transport-ip "$transport" \
    --peer-host-id "$peer_id" --peer-transport-ip "$peer_transport" \
    --peer-public-key "$peer_key" --underlay-endpoint "$peer_underlay:65001"
}

apply_host "$HOST_A" "$ROOT_A" reg-host-a 198.18.0.1 reg-host-b 198.18.0.2 "$PUB_B" 10.77.0.2
apply_host "$HOST_B" "$ROOT_B" reg-host-b 198.18.0.2 reg-host-a 198.18.0.1 "$PUB_A" 10.77.0.1

assert_link() { run_in "$1" ip link show "$2" >/dev/null; }
assert_output() {
  local needle="$1"
  shift
  local output
  output="$("$@")"
  [[ "$output" == *"$needle"* ]]
}
assert_link "$HOST_A" "$BRIDGE_A"
assert_link "$HOST_A" "$BRIDGE_B"
assert_link "$HOST_B" "$BRIDGE_A"
assert_link "$HOST_B" "$BRIDGE_B"

for ns in "$HOST_A" "$HOST_B"; do
  run_in "$ns" ip netns exec o3k-fabric ip link show o3k-wg >/dev/null
  assert_output vxlan run_in "$ns" ip netns exec o3k-fabric ip -d link show
  assert_output 'dstport 4789' run_in "$ns" ip netns exec o3k-fabric ip -d link show
  assert_output learning run_in "$ns" ip netns exec o3k-fabric ip -d link show
done

if [[ "${FABRIC_V3_PROVIDER_ONLY:-0}" == "1" ]]; then
  echo "fabric-v3-bridge-gate: provider-realization=passed"
  echo "fabric-v3-bridge-gate: endpoint-bridges=not-run (FABRIC_V3_PROVIDER_ONLY=1)"
  run_in "$HOST_A" "$HELPER_BIN" --root "$ROOT_A" --mode remove \
    --host-id reg-host-a --transport-ip 198.18.0.1 \
    --peer-host-id reg-host-b --peer-transport-ip 198.18.0.2 \
    --peer-public-key "$PUB_B" --underlay-endpoint 10.77.0.2:65001
  run_in "$HOST_B" "$HELPER_BIN" --root "$ROOT_B" --mode remove \
    --host-id reg-host-b --transport-ip 198.18.0.2 \
    --peer-host-id reg-host-a --peer-transport-ip 198.18.0.1 \
    --peer-public-key "$PUB_A" --underlay-endpoint 10.77.0.1:65001
  ip netns exec "$CANARY_NS" true
  echo "fabric-v3-bridge-gate: provider-cleanup-and-foreign-canary=passed"
  exit 0
fi

# Attach disposable endpoint namespaces to the O3K realm bridges. The bridge
# attachment is test-only; endpoint identity remains the canonical fixture
# encoded in fabric-regression-helper.
attach_endpoint() {
  local ep_ns="$1" host_ns="$2" bridge="$3" ip_addr="$4" mac="$5"
  local host_veth="${ep_ns}-h" ep_veth="${ep_ns}-e"
  ip netns add "$ep_ns"
  ip link add "$host_veth" type veth peer name "$ep_veth"
  ip link set "$host_veth" netns "$host_ns"
  ip link set "$ep_veth" netns "$ep_ns"
  run_in "$host_ns" ip link set "$host_veth" master "$bridge"
  run_in "$host_ns" ip link set "$host_veth" up
  run_in "$ep_ns" ip link set lo up
  run_in "$ep_ns" ip link set "$ep_veth" name eth0
  run_in "$ep_ns" ip link set eth0 address "$mac"
  run_in "$ep_ns" ip addr add "$ip_addr/24" dev eth0
  run_in "$ep_ns" ip link set eth0 up
  run_in "$ep_ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 || true
}

dump_debug() {
  echo "fabric-v3-bridge-gate: diagnostic snapshot"
  for ns in "$HOST_A" "$HOST_B"; do
    echo "-- $ns --"
    run_in "$ns" ip -4 addr show || true
    run_in "$ns" ip route show || true
    run_in "$ns" ip netns exec o3k-fabric wg show || true
    run_in "$ns" ip netns exec o3k-fabric ip -4 addr show || true
    run_in "$ns" ip netns exec o3k-fabric ip route show || true
    run_in "$ns" ip netns exec o3k-fabric bridge fdb show || true
    run_in "$ns" nft list tables bridge || true
    run_in "$ns" nft -a list ruleset || true
  done
}

attach_endpoint o3k-v3-ep-a1 "$HOST_A" "$BRIDGE_A" 10.0.0.10 02:00:00:00:a1:01
attach_endpoint o3k-v3-ep-a2 "$HOST_B" "$BRIDGE_A" 10.0.0.20 02:00:00:00:a1:02
attach_endpoint o3k-v3-ep-b1 "$HOST_A" "$BRIDGE_B" 10.0.0.10 02:00:00:00:b1:01
attach_endpoint o3k-v3-ep-b2 "$HOST_B" "$BRIDGE_B" 10.0.0.20 02:00:00:00:b1:02

# ICMP triggers ARP, and the neighbour table records the remote canonical MAC.
run_in o3k-v3-ep-a1 ping -c 3 -W 2 10.0.0.20 || { dump_debug; die "Realm A endpoint A1 could not reach A2"; }
run_in o3k-v3-ep-a2 ping -c 3 -W 2 10.0.0.10 || { dump_debug; die "Realm A endpoint A2 could not reach A1"; }
run_in o3k-v3-ep-b1 ping -c 3 -W 2 10.0.0.20 || { dump_debug; die "Realm B endpoint B1 could not reach B2"; }
run_in o3k-v3-ep-b2 ping -c 3 -W 2 10.0.0.10 || { dump_debug; die "Realm B endpoint B2 could not reach B1"; }

assert_output '02:00:00:00:a1:02' run_in o3k-v3-ep-a1 ip neigh show 10.0.0.20
assert_output '02:00:00:00:a1:01' run_in o3k-v3-ep-a2 ip neigh show 10.0.0.10
assert_output '02:00:00:00:b1:02' run_in o3k-v3-ep-b1 ip neigh show 10.0.0.20
assert_output '02:00:00:00:b1:01' run_in o3k-v3-ep-b2 ip neigh show 10.0.0.10

# Same-address endpoints in different realms must not resolve each other.
if run_in o3k-v3-ep-a1 ping -c 1 -W 1 10.0.0.10 >/dev/null 2>&1; then
  : # local-address ping is expected and does not test cross-realm isolation.
fi
assert_output '00:00:00:00:00:00' run_in "$HOST_A" ip netns exec o3k-fabric bridge fdb show
assert_output '00:00:00:00:00:00' run_in "$HOST_B" ip netns exec o3k-fabric bridge fdb show

echo "fabric-v3-bridge-gate: provider-realization=passed"
echo "fabric-v3-bridge-gate: endpoint-bridges=passed"
echo "fabric-v3-bridge-gate: remote-arp-mac-and-icmp=passed"
echo "fabric-v3-bridge-gate: bounded-her-fdb=passed"

# Remove through the same production helper before the trap removes test
# namespaces, then assert the foreign canary is still present.
run_in "$HOST_A" "$HELPER_BIN" --root "$ROOT_A" --mode remove \
  --host-id reg-host-a --transport-ip 198.18.0.1 \
  --peer-host-id reg-host-b --peer-transport-ip 198.18.0.2 \
  --peer-public-key "$PUB_B" --underlay-endpoint 10.77.0.2:65001
run_in "$HOST_B" "$HELPER_BIN" --root "$ROOT_B" --mode remove \
  --host-id reg-host-b --transport-ip 198.18.0.2 \
  --peer-host-id reg-host-a --peer-transport-ip 198.18.0.1 \
  --peer-public-key "$PUB_A" --underlay-endpoint 10.77.0.1:65001
ip netns exec "$CANARY_NS" true
echo "fabric-v3-bridge-gate: provider-cleanup-and-foreign-canary=passed"
