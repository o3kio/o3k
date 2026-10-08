#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installer="$root/tests/fabric-v3-install-agent-host.sh"
campaign="$root/tests/fabric-v3-o3k-three-host-campaign.sh"
capture="$root/tests/fabric-v3-remote-dhcp-boundary-capture.py"

bash -n "$installer"
bash -n "$campaign"
python3 - "$installer" "$campaign" "$capture" <<'PY'
import pathlib
import re
import sys

installer, campaign, capture = map(lambda p: pathlib.Path(p).read_text(), sys.argv[1:])
assert re.search(r'fabric_root="\$base/network/fabric"', installer)
assert re.search(r'provider_key_dir="\$fabric_root/fabric-provider"', installer)
assert re.search(r'O3K_NETWORK_FABRIC_ROOT="\$fabric_root"', installer)
assert re.search(r'private_key="\$provider_key_dir/wireguard-private\.key"', installer)
assert re.search(r'public_key="\$provider_key_dir/wireguard-public\.key"', installer)
assert 'network/fabric/fabric-provider/wireguard-public.key' in campaign
assert 'network/fabric-provider/wireguard-public.key' not in campaign
assert 'wireguard_identity_check' in capture
assert 'live_interface_public_key' in capture
assert 'prime_wireguard_peers(args, ev, maps)' in capture
assert capture.index('prime_wireguard_peers(args, ev, maps)') < capture.index('ok, detail = wg_check(args, ev, maps)')
print('WireGuard provider key-root and runtime identity contract: PASS')
PY
