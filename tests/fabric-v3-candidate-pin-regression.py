#!/usr/bin/env python3
"""Keep the retirement campaign pinned to its remotely visible product candidate."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DRIVER = (ROOT / "fabric-v3-o3k-three-host-campaign.sh").read_text()

EXPECTED_SHA = "2193e50f6fb72dccf2bd8be5968eb8c178220809"
EXPECTED_TREE = "72e739f8c1fcd841aac535f3e8686679ebd8254a"

assert f"PRODUCT_SHA={EXPECTED_SHA}" in DRIVER
assert f"PRODUCT_TREE={EXPECTED_TREE}" in DRIVER
assert "PRODUCT_REMOTE_NAME=origin" in DRIVER
assert "PRODUCT_REMOTE_REF=refs/heads/fix/fabric-v3-survivor-fdb-retirement" in DRIVER
assert "git -C \"$ROOT_DIR\" ls-remote --exit-code --refs \"$PRODUCT_REMOTE_NAME\" \"$PRODUCT_REMOTE_REF\"" in DRIVER
assert '[[ "$product_remote_line" ==' in DRIVER
assert "PRODUCT_REMOTE_SHA=" in DRIVER and "product_remote_line%%" in DRIVER
assert '"product_remote_ref"' in DRIVER and '"product_remote_sha"' in DRIVER

remote_guard = DRIVER.index('ls-remote --exit-code --refs')
evidence_creation = DRIVER.index('mkdir -p "$EVIDENCE"')
provisioning = DRIVER.index('virsh -c qemu:///system net-define')
assert remote_guard < evidence_creation < provisioning

print("frozen candidate pin and remote visibility regression: PASS")
