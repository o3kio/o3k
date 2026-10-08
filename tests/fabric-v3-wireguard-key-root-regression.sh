#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installer="$root/tests/fabric-v3-install-agent-host.sh"
campaign="$root/tests/fabric-v3-o3k-three-host-campaign.sh"
capture="$root/tests/fabric-v3-remote-dhcp-boundary-capture.py"

bash -n "$installer"
bash -n "$campaign"
python3 - "$root" "$installer" "$campaign" "$capture" <<'PY'
import subprocess
import pathlib
import re
import sys

root, installer_path, campaign_path, capture_path = sys.argv[1:]
installer, campaign, capture = map(lambda p: pathlib.Path(p).read_text(),
                                   (installer_path, campaign_path, capture_path))
product_sha = 'e4ca1805dc16839b855e969e7e17928a54cc211f'
assert f'PRODUCT_SHA={product_sha}' in campaign
dhcp_realizer = subprocess.run(
    ['git', '-C', root, 'show', f'{product_sha}:crates/o3k-network/src/fabric_dhcp.rs'],
    check=True, text=True, capture_output=True
).stdout
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
assert 'fabric-dhcp-ownership.json' in dhcp_realizer
assert 'fabric-dhcp-ownership.json' in capture and 'owner.json' not in capture
assert 'config.get("mtu") != 1390' in capture
assert 'else {"config": None, "bindings": {}}' in capture
assert 'server-b-dhcp-trigger.request.json' in campaign
assert '"reboot":{"type":"HARD"}' in campaign
assert '/servers/${SERVER_IDS[1]}/action' in campaign
assert "reboot_http_status\" == 202" in campaign
assert 'console_command b' not in campaign[campaign.index('if [[ "$DHCP_BOUNDARY_DIAGNOSTIC" == 1 ]]; then'):campaign.index('if [[ "$DHCP_BOUNDARY_DIAGNOSTIC" != 1 ]]; then')]
assert "grep -Fq 'listening on '" in capture
assert 'timeout --signal=INT 45s tcpdump' in capture
print('WireGuard provider key-root and runtime identity contract: PASS')
PY
