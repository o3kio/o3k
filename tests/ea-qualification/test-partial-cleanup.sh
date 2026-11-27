#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/images/test-campaign"
cat >"$tmp/bin/virsh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "$1" in
  net-list) printf 'o3k-ea-test-net\n' ;;
  pool-list) : ;;
  net-uuid) printf '%s\n' "${FAKE_NETWORK_UUID:-00000000-0000-4000-8000-000000000001}" ;;
  dominfo) exit 1 ;;
  *) echo "unexpected virsh command: $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/virsh"
cat >"$tmp/config" <<EOF
EA_RUN_ID=test-campaign
EA_NETWORK=o3k-ea-test-net
EA_NETWORK_UUID=00000000-0000-4000-8000-000000000001
EA_NETWORK_BRIDGE=o3kea-test
EA_NETWORK_CIDR=10.253.240.0/24
EA_NETWORK_GATEWAY=10.253.240.1
EA_DHCP_START=10.253.240.100
EA_DHCP_END=10.253.240.199
EA_POOL=o3k-ea-test-pool
EA_POOL_UUID=00000000-0000-4000-8000-000000000002
EA_IMAGE_ROOT=$tmp/images
EA_POOL_ROOT=$tmp/images/test-campaign
EA_BASE_IMAGE=$tmp/noble.img
EA_BASE_SHA256=$(printf '0%.0s' {1..64})
EA_DOMAIN_PREFIX=o3k-ea-test-
EA_HOSTS=3
EOF
state="$tmp/images/test-campaign/.ea-owned"
cat >"$state" <<EOF
o3k-ea-qualification-owned-v1
run=test-campaign
network=o3k-ea-test-net
network_uuid=00000000-0000-4000-8000-000000000001
pool=o3k-ea-test-pool
pool_uuid=00000000-0000-4000-8000-000000000002
host_a=o3k-ea-test-a|11111111-1111-4111-8111-111111111111|$tmp/images/test-campaign/o3k-ea-test-a.qcow2|$tmp/images/test-campaign/o3k-ea-test-a-seed.iso
host_b=o3k-ea-test-b|22222222-2222-4222-8222-222222222222|$tmp/images/test-campaign/o3k-ea-test-b.qcow2|$tmp/images/test-campaign/o3k-ea-test-b-seed.iso
host_c=o3k-ea-test-c|33333333-3333-4333-8333-333333333333|$tmp/images/test-campaign/o3k-ea-test-c.qcow2|$tmp/images/test-campaign/o3k-ea-test-c-seed.iso
EOF
chmod 0600 "$state"

if output="$(PATH="$tmp/bin:$PATH" FAKE_NETWORK_UUID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  EA_CONFIG_FILE="$tmp/config" "$ROOT_DIR/tests/ea-qualification/ea-testlab.sh" cleanup 2>&1)"; then
  echo "cleanup accepted a campaign network name with a foreign UUID" >&2
  exit 1
fi
grep -Fq 'campaign network name has a different UUID' <<<"$output"
[[ -f "$state" ]] || { echo "rejected cleanup removed the ownership marker" >&2; exit 1; }

PATH="$tmp/bin:$PATH" EA_CONFIG_FILE="$tmp/config" "$ROOT_DIR/tests/ea-qualification/ea-testlab.sh" cleanup
[[ ! -e "$state" ]] || { echo "cleanup retained a valid partial campaign marker" >&2; exit 1; }

echo "EA partial provisioning cleanup: PASS"
