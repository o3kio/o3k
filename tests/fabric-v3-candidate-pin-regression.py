#!/usr/bin/env python3
"""Keep the retirement campaign pinned to remotely visible protected main."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DRIVER = (ROOT / "fabric-v3-o3k-three-host-campaign.sh").read_text()

EXPECTED_SHA = "adaf6168b124111ee62bf53f6eaf6e0f6cab155e"
EXPECTED_TREE = "194863fc49735a9d30e16fd03afa498e91c6d871"

assert f"PRODUCT_SHA={EXPECTED_SHA}" in DRIVER
assert f"PRODUCT_TREE={EXPECTED_TREE}" in DRIVER
assert "PRODUCT_REMOTE_NAME=origin" in DRIVER
assert "PRODUCT_REMOTE_REF=refs/heads/main" in DRIVER
assert "git -C \"$ROOT_DIR\" ls-remote --exit-code --refs \"$PRODUCT_REMOTE_NAME\" \"$PRODUCT_REMOTE_REF\"" in DRIVER
assert '[[ "$product_remote_line" ==' in DRIVER
assert "PRODUCT_REMOTE_SHA=" in DRIVER and "product_remote_line%%" in DRIVER
assert '"product_remote_ref"' in DRIVER and '"product_remote_sha"' in DRIVER

remote_guard = DRIVER.index('ls-remote --exit-code --refs')
evidence_creation = DRIVER.index('mkdir -p "$EVIDENCE"')
provisioning = DRIVER.index('virsh -c qemu:///system net-define')
assert remote_guard < evidence_creation < provisioning

print("protected-main candidate pin and remote visibility regression: PASS")
