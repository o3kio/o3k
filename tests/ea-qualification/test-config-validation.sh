#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="$(mktemp)"
trap 'rm -f -- "$config"' EXIT
cat >"$config" <<'EOF'
EA_RUN_ID=test-campaign
EA_NETWORK='bad" network'
EA_NETWORK_UUID=00000000-0000-4000-8000-000000000001
EA_NETWORK_BRIDGE=o3kea-test
EA_NETWORK_CIDR=10.253.240.0/24
EA_NETWORK_GATEWAY=10.253.240.1
EA_DHCP_START=10.253.240.100
EA_DHCP_END=10.253.240.199
EA_POOL=o3k-ea-test-pool
EA_POOL_UUID=00000000-0000-4000-8000-000000000002
EA_IMAGE_ROOT=/tmp/o3k-testlab
EA_POOL_ROOT=/tmp/o3k-testlab/campaign
EA_BASE_IMAGE=/tmp/noble.img
EA_BASE_SHA256=0000000000000000000000000000000000000000000000000000000000000000
EA_DOMAIN_PREFIX=o3k-ea-test-
EA_HOSTS=3
EOF

if output="$(EA_CONFIG_FILE="$config" "$ROOT_DIR/tests/ea-qualification/ea-testlab.sh" inventory 2>&1)"; then
  echo "unsafe campaign network name was accepted" >&2
  exit 1
fi
grep -Fq 'invalid qualification config value: EA_NETWORK' <<<"$output"

sed -i 's/bad" network/o3k-ea-test-net/' "$config"
sed -i 's/00000000-0000-4000-8000-000000000001/0000000A-0000-4000-8000-000000000001/' "$config"
if output="$(EA_CONFIG_FILE="$config" "$ROOT_DIR/tests/ea-qualification/ea-testlab.sh" inventory 2>&1)"; then
  echo "uppercase campaign UUID was accepted" >&2
  exit 1
fi
grep -Fq 'invalid qualification config value: EA_NETWORK_UUID' <<<"$output"

sed -i 's/0000000A-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000001/' "$config"
sed -i 's#10.253.240.0/24#fd00::/64#; s/10.253.240.1/fd00::1/; s/10.253.240.100/fd00::100/; s/10.253.240.199/fd00::199/' "$config"
if output="$(EA_CONFIG_FILE="$config" "$ROOT_DIR/tests/ea-qualification/ea-testlab.sh" inventory 2>&1)"; then
  echo "IPv6 campaign network was accepted" >&2
  exit 1
fi
grep -Fq 'qualification network and addresses must use IPv4' <<<"$output"

sed -i 's#fd00::/64#10.253.0.0/16#; s/fd00::1/10.253.240.1/; s/fd00::100/10.253.240.100/; s/fd00::199/10.253.240.199/' "$config"
if output="$(EA_CONFIG_FILE="$config" "$ROOT_DIR/tests/ea-qualification/ea-testlab.sh" inventory 2>&1)"; then
  echo "unsupported campaign subnet prefix was accepted" >&2
  exit 1
fi
grep -Fq 'qualification network must use the supported /24 prefix' <<<"$output"
echo "EA qualification config validation: PASS"
