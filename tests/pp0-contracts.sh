#!/usr/bin/env bash
# PP.0 contract freeze validation (issue #969).
#
# Deterministically validates the frozen o3k-demo-v1 / o3k-small-edge-v1
# profile contracts and the release/installer/Araf contract files. This is a
# contract-shape check; it never promotes an evidence state.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "${ROOT_DIR}" <<'PY'
import pathlib
import sys

import yaml

root = pathlib.Path(sys.argv[1])


def load(path):
    with open(root / path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


registry = load("compatibility/product-profiles.yaml")
status = load("docs/status/current-state.yaml")
release = load("contracts/release-bundle-v1.yaml")
installer = load("contracts/installer-v1.yaml")
araf = load("contracts/araf-compatibility-v1.yaml")

profiles = {p["id"]: p for p in registry.get("profiles", []) if isinstance(p, dict)}
for profile_id in ("o3k-demo-v1", "o3k-small-edge-v1"):
    profile = profiles.get(profile_id)
    check(profile is not None, f"{profile_id} missing from product-profiles.yaml")
    if not profile:
        continue
    check(profile.get("maturity") == "frozen-contract",
          f"{profile_id} maturity must be frozen-contract")
    for field in ("supported_targets", "runtime_components", "database",
                  "compute_provider", "network_profile", "storage_profile",
                  "cloud_profile", "building_block", "interfaces",
                  "evidence_dependencies", "known_limitations",
                  "araf_integration"):
        check(field in profile, f"{profile_id} missing field {field}")
    check(profile.get("araf_integration") == "client-only-not-required-for-readiness",
          f"{profile_id} Araf boundary drifted")

# Profile boundaries must be clearly different.
demo = profiles.get("o3k-demo-v1", {})
edge = profiles.get("o3k-small-edge-v1", {})
demo_components = {c.get("component") for c in demo.get("runtime_components", [])
                   if c.get("required")}
edge_components = {c.get("component") for c in edge.get("runtime_components", [])
                   if c.get("required")}
check("o3k-network-agent" not in demo_components,
      "o3k-demo-v1 must not require the o3k-network agent")
check("o3k-network-agent" in edge_components,
      "o3k-small-edge-v1 must require the o3k-network agent")
check(demo.get("parent_profile") != edge.get("parent_profile"),
      "demo and small-edge must derive from different parent profiles")

# Every required runtime component must map to a released binary or a host
# package, and required binaries must be covered by the bundle contract.
bundle_binaries = {b["binary"]: b for b in release.get("bundle_contents", {}).get("binaries", [])}
for profile_id in ("o3k-demo-v1", "o3k-small-edge-v1"):
    for component in profiles[profile_id].get("runtime_components", []):
        if component.get("required"):
            binary = component.get("binary")
            check(binary in bundle_binaries or binary == "host-package",
                  f"{profile_id} required component {component.get('component')} has no bundle binary")
        if component.get("required") and component.get("binary") in bundle_binaries:
            scope = bundle_binaries[component["binary"]].get("profile_scope", [])
            check(profile_id in scope,
                  f"{component['binary']} bundle scope does not cover {profile_id}")

# Release bundle contract: assets, distribution authority, traceability.
check(release.get("distribution", {}).get("canonical_public_source") == "github-release-asset",
      "canonical distribution source must be the GitHub Release asset")
check(release["distribution"].get("convenience_redirect") == "get.o3k.io",
      "get.o3k.io must be a convenience redirect only")
check(release["bundle_contents"].get("no_source_compilation_on_target") is True,
      "target hosts must not compile from source")
for asset in ("install.sh", "manifest.json", "SHA256SUMS", "sbom.spdx.json",
              "release-digests.txt", "release-digests.sig", "provenance.json",
              "release-verify.pub"):
    check(any(a.get("name") == asset for a in release.get("required_assets", [])),
          f"release contract missing required asset {asset}")
install_asset = next((a for a in release.get("required_assets", [])
                      if a.get("name") == "install.sh"), {})
check("get-o3k.sh" in install_asset.get("source", ""),
      "install.sh release asset must be the byte-identical get-o3k.sh export")
units = {u.get("unit") for u in release.get("bundle_contents", {}).get("systemd_units", [])}
check("o3k-network.service" in units,
      "release contract must ship the o3k-network.service unit")
bundle_binaries = {b["binary"] for b in release.get("bundle_contents", {}).get("binaries", [])}
check("o3k-network" in bundle_binaries,
      "release contract must ship the o3k-network binary")
gaps = " ".join(str(g).lower() for g in release.get("known_gaps", []))
check("compiles" not in gaps and "compilation" not in gaps,
      "target-compilation gap must be resolved, not just recorded")
for profile_id in ("o3k-demo-v1", "o3k-small-edge-v1"):
    targets = profiles[profile_id].get("supported_targets", {})
    check(targets.get("hosts", {}).get("proven_support_claim") is False,
          f"{profile_id} supported_targets must not be a support claim")

# Installer contract: authority boundary, phase order, convergence, lifecycle.
check(installer.get("authority_boundary", {}).get("installer_must_not_fabricate"),
      "installer authority boundary must forbid fabricating P15 authorities")
canonical = installer["authority_boundary"].get("canonical_workflows", {})
check("init" in canonical and "join" in canonical,
      "installer must invoke canonical init/join workflows")
phases = [p for phase in installer.get("installer_semantics", {}).get("phases", [])
          for p in [phase.split(" ")[0]]]
check(phases[0] == "preflight", "installer must start with preflight")
check("verify_release_artifact_integrity" in phases
      and phases.index("verify_release_artifact_integrity") < phases.index("install_runtime_files"),
      "artifact verification must precede installation")
check("invoke_canonical_init_join" in phases and "wait_for_canonical_readiness" in phases,
      "installer must invoke canonical init/join and wait for canonical readiness")
check(phases.index("invoke_canonical_init_join") < phases.index("wait_for_canonical_readiness"),
      "readiness wait must follow canonical init/join")
semantics = installer.get("installer_semantics", {})
check(semantics.get("convergence") and semantics.get("fail_before_mutation"),
      "installer convergence/fail-before-mutation semantics required")
convergence_text = str(semantics.get("convergence", "")).lower()
for token in ("idempotent", "never duplicate", "canonical"):
    check(token in convergence_text,
          f"installer convergence contract must bind '{token}'")
check("cargo" in " ".join(map(str, installer.get("installer_semantics", {}).get("phases", []))).lower()
      or "prebuilt" in str(semantics.get("phases", "")).lower()
      or "never cargo build" in " ".join(map(str, semantics.get("phases", []))).lower(),
      "installer phases must forbid target compilation")
lifecycle = installer.get("lifecycle_safety", {})
ops = set(lifecycle.get("operations", {}))
check(ops == {"reset", "uninstall", "purge"},
      "reset/uninstall/purge must be distinct operations")
check(len(lifecycle.get("ownership_proof_required_before_delete", [])) >= 5,
      "lifecycle safety must require ownership proof for foreign state")
check("preserved" in str(lifecycle.get("ambiguous_state", "")).lower(),
      "ambiguous state must be reported/preserved")
upgrade = installer.get("upgrade_boundary", {})
check(upgrade.get("unsupported_downgrade") and upgrade.get("schema_compatibility"),
      "upgrade boundary must fence downgrade and schema compatibility")

# Araf boundary: separately versioned client, never a readiness gate.
check("separately versioned" in araf.get("model", {}).get("versioning", ""),
      "Araf must remain separately versioned")
araf_text = str(araf).lower()
check("owner-of-o3k-state" in araf_text and "required-for-o3kd-readiness" in araf_text,
      "Araf is-not list must exclude state ownership and readiness gating")
check("fake" in araf_text and "forbidden" in araf_text,
      "Araf fake/demo mode must be forbidden")

# Frozen profiles must have matching authoritative state records.
status_profiles = status.get("profiles", {})
for profile_id in ("o3k-demo-v1", "o3k-small-edge-v1"):
    check(profile_id in status_profiles,
          f"{profile_id} missing from docs/status/current-state.yaml")

# Normative documents must exist.
for doc in ("docs/specs/SPEC-0048-pp0-demo-and-small-edge-baseline-freeze.md",
            "docs/pp0/PP0_PRODUCT_BASELINE.md"):
    check((root / doc).is_file(), f"missing {doc}")

if failures:
    print("PP.0 contract validation FAILED:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    sys.exit(1)
print("PP.0 contract validation passed: frozen profiles, release bundle, "
      "installer/lifecycle/upgrade semantics, and Araf boundary are consistent.")
PY
