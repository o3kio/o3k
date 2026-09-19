#!/usr/bin/env python3
"""Assemble the PP.4 durable (redacted) evidence manifest.

Reads a campaign evidence directory and emits a JSON manifest containing only
immutable metadata: what was tested, on what host, against which exact
artifacts, which cases passed, and SHA-256 values of every evidence file.
No log content and no secrets are embedded.

Usage: make-manifest.py <distro> <evidence-final-dir> <o3k-version> <source-sha>
"""
import hashlib
import json
import os
import sys
import urllib.request


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_key_value(path: str) -> dict:
    values = {}
    if not os.path.isfile(path):
        return values
    for line in open(path, encoding="utf-8", errors="replace"):
        if "=" in line:
            key, _, value = line.strip().partition("=")
            values[key.strip()] = value.strip()
    return values


def read_cases(path: str) -> list:
    cases = []
    if not os.path.isfile(path):
        return cases
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line:
            cases.append(json.loads(line))
    return cases


def main() -> int:
    distro, evidence_dir, o3k_version, source_sha = sys.argv[1:5]
    files = {}
    for name in sorted(os.listdir(evidence_dir)):
        path = os.path.join(evidence_dir, name)
        if os.path.isfile(path) and not name.endswith("-done"):
            files[name] = sha256_file(path)

    inventory = open(os.path.join(evidence_dir, "00-host-inventory.txt"),
                     encoding="utf-8", errors="replace").read() \
        if os.path.isfile(os.path.join(evidence_dir, "00-host-inventory.txt")) else ""
    inventory_lines = dict(
        line.split(": ", 1) for line in inventory.splitlines() if ": " in line
    )

    release = {}
    manifest_path = os.path.join(evidence_dir, "06-release-identity.txt")
    if os.path.isfile(manifest_path):
        release = read_key_value(manifest_path)

    stamps = read_key_value(os.path.join(evidence_dir, "03-timestamps.env"))
    stamps = {k: int(v) for k, v in stamps.items() if v.isdigit()}
    timing = {}
    ordered = [t for t in ("T0", "T1", "T2", "T3", "T4", "T5") if t in stamps]
    for label, key in (("T0_oneline_invoked", "T0"),
                       ("T1_o3k_canonical_ready", "T1"),
                       ("T2_buildingblock_ready", "T2"),
                       ("T3_araf_ready", "T3"),
                       ("T4_browser_login_usable", "T4"),
                       ("T5_first_vm_active_boot", "T5")):
        if key in stamps:
            timing[label] = stamps[key]
    if "T0" in stamps and "T5" in stamps:
        timing["T0_to_T5_seconds"] = stamps["T5"] - stamps["T0"]

    identity = {}
    identity_path = os.path.join(evidence_dir, "14-scenarioA-identity.txt")
    if os.path.isfile(identity_path):
        for line in open(identity_path):
            parts = line.split()
            if len(parts) == 2:
                identity[parts[0]] = parts[1]

    boot_after = ""
    boot_after_path = os.path.join(evidence_dir, "boot-id-after.txt")
    if os.path.isfile(boot_after_path):
        boot_after = open(boot_after_path).read().strip()

    cases = read_cases(os.path.join(evidence_dir, "cases.jsonl"))

    manifest = {
        "campaign": f"pp4-{distro}",
        "tracking_issue": "o3kio/o3k#973",
        "generated_utc": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "host": {
            "distro": distro,
            "os_pretty": inventory_lines.get("PRETTY_NAME", ""),
            "kernel": inventory_lines.get("kernel", next(
                (l.split(" ", 2)[2] for l in inventory.splitlines()
                 if l.startswith("Linux ")), "")),
            "cpu": inventory_lines.get("cpu", ""),
            "kvm_device": inventory_lines.get("kvm device", ""),
            "svm_vmx_flag": inventory_lines.get("svm/vmx flag", "").strip(),
            "boot_id_before": inventory_lines.get("boot_id", ""),
            "boot_id_after_reboot": boot_after,
        },
        "o3k": {
            "version": release.get("installed_version", o3k_version),
            "source_sha": release.get("installed_source_commit", source_sha),
            "campaign_source_sha": source_sha,
        },
        "araf": {
            "version": "v1.0.0-rc.12",
            "source_sha": "de64cc9193085116fa30ad51c04ccab24a013dd0",
        },
        "canonical_resources": identity,
        "timestamps_unix": timing,
        "test_cases": cases,
        "result": "PASS" if (
            cases
            and all(c["status"] == "PASS" for c in cases)
            and identity
            and "T5_first_vm_active_boot" in timing
        ) else "CHECK",
        "evidence_file_sha256": files,
        "known_limitations": [
            "single-node demo profile (o3k-demo-v1); not HA, not multi-node",
            "Araf v1.0.0-rc.12 GitHub release metadata is non-prerelease (recorded fact; future Araf RCs publish as prereleases)",
            "demo IdP (Keycloak start-dev) is not a production identity claim",
            "native demo tokens are 1-hour HMAC without renewal (accepted Araf deviation)",
            "Horizon is an optional external compatibility witness, not the O3K dashboard",
        ],
    }
    json.dump(manifest, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
