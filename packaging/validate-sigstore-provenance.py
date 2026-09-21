#!/usr/bin/env python3
"""Validate the signed release metadata before invoking Cosign."""

import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


if len(sys.argv) != 5:
    fail("usage: validate-sigstore-provenance.py PROVENANCE POLICY VERSION SOURCE_COMMIT")

provenance_path, policy_path, expected_version, expected_commit = map(Path, sys.argv[1:])
try:
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    policy = __import__("yaml").safe_load(policy_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as error:
    fail(f"metadata is unreadable: {error}")

if not isinstance(provenance, dict) or not isinstance(policy, dict):
    fail("metadata roots must be objects")
current = policy.get("current")
if not isinstance(current, dict):
    fail("trust policy current section is missing")
required = {
    "signature_scheme": "sigstore-keyless",
    "release": str(expected_version),
    "source_commit": str(expected_commit),
    "oidc_issuer": current.get("oidc_issuer"),
    "repository": current.get("repository"),
    "workflow": current.get("workflow"),
}
for field, expected in required.items():
    if provenance.get(field) != expected:
        fail(f"provenance {field!r} does not match the governed policy")
if provenance.get("digest_manifest") != "release-digests.txt":
    fail("provenance must name release-digests.txt as its digest manifest")
if provenance.get("self_digest_binding") != "release-digests.txt":
    fail("provenance must declare its external digest binding")
if not isinstance(provenance.get("assets"), list) or not provenance["assets"]:
    fail("provenance assets must be a non-empty list")
asset_names = set()
for asset in provenance["assets"]:
    if not isinstance(asset, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(asset.get("sha256", ""))):
        fail("provenance asset digest is invalid")
    name = asset.get("name")
    if not isinstance(name, str) or name in asset_names:
        fail("provenance asset names must be unique")
    asset_names.add(name)
print("sigstore provenance policy: PASS")
