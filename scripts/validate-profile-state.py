#!/usr/bin/env python3
"""Fail closed on product-profile status drift in docs/status/current-state.yaml.

Governance checks (SPEC-0024):

1. the status file records exactly the product profiles registered in
   compatibility/product-profiles.yaml;
2. every profile record has the required field contract;
3. evidence uses the explicit vocabulary (passed/failed/not-executed/
   not-proven) and is profile-scoped;
4. native-rust-testlab isolation: no Cinder/Tempest evidence may appear
   under the native profile, so "passed external Cinder" can never be
   interpreted as native alpha readiness;
5. every source_commit resolves in this repository's git history;
6. consistency with docs/release-tracker.md: while the tracker remains
   blocked/pending, native-rust-testlab full-profile evidence must not be
   `passed` and its release relevance must not claim readiness.

Usage:
    python3 scripts/validate-profile-state.py [--root REPO_ROOT]
"""

import argparse
import pathlib
import re
import subprocess
import sys

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)

EVIDENCE_STATES = {"passed", "failed", "not-executed", "not-proven"}
REQUIRED_PROFILE_FIELDS = {
    "implementation_state",
    "source_commit",
    "portable_evidence",
    "protected_component_evidence",
    "full_profile_evidence",
    "release_relevance",
    "blockers",
    "next_evidence_action",
    "explicitly_unproven_claims",
}
EVIDENCE_LISTS = (
    "portable_evidence",
    "protected_component_evidence",
    "full_profile_evidence",
)
CLAIM_RECONCILIATION_SOURCES = (
    "README.md",
    "docs/ROADMAP.md",
    "docs/status/current-state.yaml",
    "compatibility/product-profiles.yaml",
    "docs/compatibility/matrix.yaml",
    "docs/architecture/p15-e2d-gap-register.md",
)
NATIVE_PROFILE = "native-rust-testlab"
NATIVE_FORBIDDEN_EVIDENCE = re.compile(r"(?i)cinder|tempest")
RELEASE_READY_CLAIM = re.compile(r"(?i)\brelease[-_ ]?ready\b")

TRACKER_CONTRACT = re.compile(
    r"<!-- tracker-contract\n(?P<body>.*?)\n-->", re.DOTALL
)


def fail(errors, message):
    errors.append(message)


def load_yaml(path, errors):
    if not path.is_file():
        fail(errors, f"missing file: {path}")
        return None
    try:
        with path.open(encoding="utf-8") as handle:
            return yaml.load(handle, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        fail(errors, f"invalid YAML in {path.name}: {exc}")
        return None


def tracker_state(root, errors):
    tracker = root / "docs" / "release-tracker.md"
    if not tracker.is_file():
        fail(errors, "missing docs/release-tracker.md for tracker cross-check")
        return None, None
    text = tracker.read_text(encoding="utf-8")
    match = TRACKER_CONTRACT.search(text)
    if not match:
        fail(errors, "docs/release-tracker.md tracker-contract block is missing")
        return None, None
    metadata = {}
    for line in match.group("body").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip()
    return metadata.get("program_status"), metadata.get("closure_decision")


def commit_resolves(root, sha):
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == sha


def validate_claim_reconciliation(root, status, errors):
    """Cross-check the single claim-state record against its public projections.

    This is intentionally a conservative consistency check: it verifies that
    the machine-readable E2D state is present in the gap register and that all
    public profile/matrix inputs exist.  It never promotes an evidence state.
    """
    record = status.get("claim_reconciliation")
    if not isinstance(record, dict):
        fail(errors, "claim_reconciliation must be a mapping")
        return
    if record.get("status") not in EVIDENCE_STATES:
        fail(errors, "claim_reconciliation.status has invalid evidence state")
    sources = record.get("sources")
    if not isinstance(sources, list) or set(sources) != set(CLAIM_RECONCILIATION_SOURCES):
        fail(errors, "claim_reconciliation.sources must name the six public claim inputs")
    for relative in CLAIM_RECONCILIATION_SOURCES:
        if not (root / relative).is_file():
            fail(errors, f"claim reconciliation source is missing: {relative}")

    expected = record.get("e2d_status")
    if not isinstance(expected, dict) or not expected:
        fail(errors, "claim_reconciliation.e2d_status must be a non-empty mapping")
        return
    gap_path = root / "docs/architecture/p15-e2d-gap-register.md"
    gap_text = gap_path.read_text(encoding="utf-8") if gap_path.is_file() else ""
    for identifier, expected_status in expected.items():
        if not re.fullmatch(r"E2D-\d{2}", str(identifier)):
            fail(errors, f"invalid claim reconciliation identifier: {identifier!r}")
            continue
        match = re.search(
            rf"^\|\s*{re.escape(identifier)}\s*\|[^|]*\|\s*([^|]+?)\s*\|",
            gap_text,
            re.MULTILINE,
        )
        if not match:
            fail(errors, f"{identifier} is absent from the E2D gap register")
        elif match.group(1).strip() != expected_status:
            fail(errors, f"{identifier} status drift: current-state={expected_status!r}, gap-register={match.group(1).strip()!r}")
    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8") if readme_path.is_file() else ""
    if "E2D-18" not in readme or "claim" not in readme.lower():
        fail(errors, "README.md does not expose the governed E2D claim state")
    roadmap_path = root / "docs/ROADMAP.md"
    roadmap = roadmap_path.read_text(encoding="utf-8") if roadmap_path.is_file() else ""
    if "P15.7" not in roadmap or "SPEC-0047" not in roadmap:
        fail(errors, "docs/ROADMAP.md does not expose the governed P15 scope")
    matrix = load_yaml(root / "docs/compatibility/matrix.yaml", errors)
    if matrix is not None and matrix.get("profile") != "testlab-alpha":
        fail(errors, "compatibility matrix profile drifted from testlab-alpha")


def validate(root, status_file, profiles_file, errors):
    status = load_yaml(status_file, errors)
    registry = load_yaml(profiles_file, errors)
    if status is None or registry is None:
        return

    if status.get("schema_version") != 2:
        fail(errors, "status schema_version must be 2")
    if status.get("status_kind") != "authoritative-current-state":
        fail(errors, "status_kind must be authoritative-current-state")

    validate_claim_reconciliation(root, status, errors)

    top_commit = status.get("source_commit")
    if not top_commit:
        fail(errors, "top-level source_commit is required")
    elif not commit_resolves(root, top_commit):
        fail(errors, f"top-level source_commit does not resolve in git: {top_commit!r}")

    registry_ids = {
        profile.get("id")
        for profile in registry.get("profiles", [])
        if isinstance(profile, dict) and profile.get("id")
    }
    if not registry_ids:
        fail(errors, "product-profiles.yaml declares no profile ids")
    status_profiles = status.get("profiles", {})
    if not isinstance(status_profiles, dict) or not status_profiles:
        fail(errors, "status must declare a non-empty profiles map")

    status_ids = set(status_profiles)
    if status_ids != registry_ids:
        fail(
            errors,
            "status profile ids must equal the product-profile registry ids "
            f"(missing: {sorted(registry_ids - status_ids)}, "
            f"extra: {sorted(status_ids - registry_ids)})",
        )

    program_status, closure_decision = tracker_state(root, errors)
    tracker_blocked = (
        program_status == "blocked" or closure_decision == "pending"
    )

    for profile_id in sorted(registry_ids):
        record = status_profiles[profile_id]
        if not isinstance(record, dict):
            fail(errors, f"profile {profile_id} must be a mapping")
            continue

        for field in REQUIRED_PROFILE_FIELDS:
            if field not in record:
                fail(errors, f"profile {profile_id} is missing required field {field!r}")
                continue

        commit = record.get("source_commit")
        if commit and not commit_resolves(root, commit):
            fail(errors, f"profile {profile_id} source_commit does not resolve in git: {commit!r}")

        for list_name in EVIDENCE_LISTS:
            entries = record.get(list_name)
            if not isinstance(entries, list):
                fail(errors, f"profile {profile_id} {list_name} must be a list")
                continue
            for entry in entries:
                if not isinstance(entry, dict) or not entry.get("name"):
                    fail(errors, f"profile {profile_id} {list_name} entries need a name")
                    continue
                name = entry["name"]
                state = entry.get("state")
                if state not in EVIDENCE_STATES:
                    fail(
                        errors,
                        f"profile {profile_id} {list_name} entry {name!r} has "
                        f"invalid evidence state {state!r} "
                        f"(must be one of {sorted(EVIDENCE_STATES)})",
                    )
                if profile_id == NATIVE_PROFILE and NATIVE_FORBIDDEN_EVIDENCE.search(name):
                    fail(
                        errors,
                        f"native-rust-testlab must not claim Cinder/Tempest evidence "
                        f"(profile-scoped; see openstack-service-testbed): {name!r}",
                    )

        if profile_id == NATIVE_PROFILE and tracker_blocked:
            for entry in record.get("full_profile_evidence", []):
                if isinstance(entry, dict) and entry.get("state") == "passed":
                    fail(
                        errors,
                        "native-rust-testlab full-profile evidence cannot be 'passed' "
                        "while the release tracker is blocked/pending",
                    )
            relevance = record.get("release_relevance")
            if isinstance(relevance, str) and RELEASE_READY_CLAIM.search(relevance):
                fail(
                    errors,
                    "native-rust-testlab release_relevance cannot claim release "
                    "readiness while the release tracker is blocked/pending",
                )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
        help="repository root (defaults to the checkout containing this script)",
    )
    parser.add_argument(
        "--status-file",
        type=pathlib.Path,
        default=None,
        help="status file (defaults to docs/status/current-state.yaml under --root)",
    )
    parser.add_argument(
        "--profiles-file",
        type=pathlib.Path,
        default=None,
        help="profile registry (defaults to compatibility/product-profiles.yaml under --root)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    status_file = (args.status_file or root / "docs/status/current-state.yaml").resolve()
    profiles_file = (args.profiles_file or root / "compatibility/product-profiles.yaml").resolve()

    errors = []
    validate(root, status_file, profiles_file, errors)
    if errors:
        print("Product-profile status validation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(
        "Product-profile status validated: four profiles, field contract, "
        "evidence vocabulary, native alpha isolation, source commits, and "
        "release-tracker consistency all pass."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
