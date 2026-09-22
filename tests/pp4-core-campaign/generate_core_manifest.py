#!/usr/bin/env python3
"""Emit the authoritative Core campaign manifest; never upgrades missing evidence."""
from __future__ import annotations
import json, platform, sys
from pathlib import Path

PASS = "PASS"
NOT_PROVEN = "NOT PROVEN"
OPTIONAL = "NOT_APPLICABLE_OPTIONAL"

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

def exists(root: Path, *names: str) -> bool:
    return all((root / name).is_file() and (root / name).stat().st_size > 0 for name in names)

def equal_files(root: Path, left: str, right: str) -> bool:
    return exists(root, left, right) and (root / left).read_bytes() == (root / right).read_bytes()

def main() -> int:
    if len(sys.argv) != 6:
        raise SystemExit("usage: generate_core_manifest.py EVID VERSION SOURCE_SHA HARNESS_SHA DISTRO")
    root = Path(sys.argv[1]); version, source, harness, distro = sys.argv[2:]
    horizon = PASS if "RESULT: PASS" in read(root / "horizon-summary.txt") else (OPTIONAL if distro == "debian" else NOT_PROVEN)
    required = {
        "public_release_trust": PASS if exists(root, "installed-identity.txt", "release.env") else NOT_PROVEN,
        "canonical_bootstrap": PASS if exists(root, "identity-me.json", "durable-bootstrap.json", "doctor-bootstrap.json") else NOT_PROVEN,
        "topology": PASS if exists(root, "durable-bootstrap.json", "regions.json", "failure-domains.json") else NOT_PROVEN,
        "placement": PASS if exists(root, "placement-providers.json", "placement-inventory.json") else NOT_PROVEN,
        "native_network": PASS if exists(root, "native-networks.json", "native-network-show.json", "native-network.json", "native-subnets.json") else NOT_PROVEN,
        "native_first_create": PASS if exists(root, "native-create.json", "native-operation.json", "native-server.json", "native-domain.txt", "native-console.log") else NOT_PROVEN,
        "canonical_replay": PASS if exists(root, "native-replay.json") and equal_files(root, "side-effects-before-replay.json", "side-effects-after-replay.json") else NOT_PROVEN,
        "changed_body_conflict": PASS if exists(root, "native-conflict.json") and equal_files(root, "side-effects-before-replay.json", "side-effects-after-conflict.json") else NOT_PROVEN,
        "openstack_observation": PASS if exists(root, "openstack-native-show.json", "openstack-native-list.json", "openstack-native-port-show.json") else NOT_PROVEN,
        "compatibility_create": PASS if exists(root, "openstack-create.json", "compat-domain.txt", "compat-console.log") else NOT_PROVEN,
        "native_projection": PASS if exists(root, "native-compat-show.json") else NOT_PROVEN,
        "cross_interface_lifecycle": PASS if exists(root, "native-after-compat-reboot.json", "openstack-compat-show.json", "openstack-lifecycle-list.json") else NOT_PROVEN,
        "cross_interface_delete": PASS if exists(root, "native-compat-delete.json") else NOT_PROVEN,
        "horizon": horizon,
        "horizon_independent_readiness": PASS if exists(root, "ready-after-horizon-stop.txt") else NOT_PROVEN,
        "host_reboot": PASS if exists(root, "ready-after-reboot.txt", "durable-bootstrap-after-reboot.json", "libvirt-after-reboot.txt") else NOT_PROVEN,
        "installer_rerun": PASS if exists(root, "rerun-identity.txt", "durable-bootstrap-after-rerun.json") else NOT_PROVEN,
        "reset_reinstall": PASS if "reset_rc=0" in read(root / "cleanup-status.env") and exists(root, "reset-reinstall-identity.txt", "ready-after-reset-reinstall.txt") else NOT_PROVEN,
        "uninstall_reinstall": PASS if "uninstall=PASS" in read(root / "cleanup-status.env") and exists(root, "reinstall-identity.txt", "ready-after-uninstall-reinstall.txt") else NOT_PROVEN,
        "purge_reinstall": PASS if "purge=PASS" in read(root / "cleanup-status.env") and exists(root, "purge-reinstall-identity.txt", "ready-after-purge-reinstall.txt") else NOT_PROVEN,
        "foreign_state": PASS if exists(root, "foreign-before.txt", "foreign-after-final.txt", "foreign-user-before.txt", "foreign-user-after-final.txt") and equal_files(root, "foreign-before.txt", "foreign-after-final.txt") and equal_files(root, "foreign-user-before.txt", "foreign-user-after-final.txt") else NOT_PROVEN,
        "secret_scan": PASS if "secret_scan=PASS" in read(root / "security.env") else NOT_PROVEN,
        "owned_leak_check": PASS if "unexpected_owned_leaks=0" in read(root / "leaks.env") else NOT_PROVEN,
    }
    side_effects = {}
    try:
        before = json.loads(read(root / "side-effects-before-replay.json"))
        after = json.loads(read(root / "side-effects-after-replay.json"))
        side_effects = {key: {"before": before.get(key), "after": after.get(key), "duplicate": before.get(key) != after.get(key)} for key in sorted(before)}
    except (json.JSONDecodeError, TypeError):
        side_effects = {key: NOT_PROVEN for key in ("resources", "operations", "network_ports", "placement_allocations", "quota_reservations", "provider_execution")}
    manifest = {
        "schema": "o3k.pp4-core.evidence.v1",
        "campaign": f"PP.4 Core {version} complete matrix",
        "verdict": PASS if all(v in (PASS, "NOT_APPLICABLE_OPTIONAL") for v in required.values()) else "BLOCKED",
        "release": {"version": version, "source_sha": source, "public_url": f"https://github.com/o3kio/o3k/releases/tag/{version}"},
        "harness": {"commit_sha": harness},
        "host": {"distro": distro, "kernel": platform.release(), "architecture": platform.machine(), "kvm": Path("/dev/kvm").exists()},
        "gates": required,
        "replay_side_effects": side_effects,
        "evidence_root": str(root),
        "evidence_files": sorted(p.name for p in root.iterdir() if p.is_file()),
    }
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
