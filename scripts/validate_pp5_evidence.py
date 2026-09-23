#!/usr/bin/env python3
"""Validate the protected PP.5 Small Edge v1 campaign evidence contract.

This validator intentionally accepts only a completed, provenance-bound
campaign artifact.  A missing, skipped, source-built, or fixture-only result is
not evidence of PP.5.  It fails closed: every field the execution plan
(``PP5_EXECUTION_PLAN.md`` §7, §9) makes binding must be present and well
formed, leaked owned resources must be absent, and a claimed pass must be
supported by every per-row verdict.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

from collections.abc import Mapping

SCHEMA = "o3k.pp5-small-edge.campaign-evidence.v1"
ARTIFACT_TYPE = "o3k-pp5-small-edge-campaign-evidence"
PHASE = "PP.5"

SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# The declared matrix from §4 as executed.  Scale tiers carry their declared
# hypervisor count; soak tiers must declare a non-empty duration.  Each tier
# records its executed verdict, and a claimed campaign pass requires every
# verdict to be "pass".
ACCEPTANCE_ROWS = "ABCDEFGHIJKLMNOPQRS"

# Every tier the plan declares as required (PP5_EXECUTION_PLAN.md §4.1, §4.2,
# §12.2) must actually appear in the executed campaign.  A certification that
# drops a required tier row fails closed: the result may not silently choose a
# smaller envelope than the plan bound for this profile.
REQUIRED_SCALE_TIERS = ("S1", "S2", "S5", "S3", "S10", "S20")
REQUIRED_SOAK_TIERS = ("K-min", "K-full")

# PP.5 declares a fixed set of claims it explicitly does NOT make.  Every one
# must be present in the evidence's non_claims list so a certification cannot
# silently downgrade them.  Matching is case-insensitive substring on each
# key's distinctive fragment(s), not exact-sentence equality: evidence wording
# is allowed to vary, but the disclaimed capability must be stated.  A key is
# satisfied when at least one of its fragments appears in some non_claims
# entry.  A missing required non-claim fails validation closed.
REQUIRED_NON_CLAIMS = {
    "no HA or SLA claim": ("ha", "sla"),
    "no live migration or automatic evacuation claim": ("live migration", "evacuation"),
    "no arbitrary datacenter scale claim": ("datacenter scale", "arbitrary datacenter"),
    "no multi-region claim": ("multi-region", "multi region"),
    "no cells or sharding claim": ("cells", "sharding"),
    "no blanket OpenStack compatibility claim": ("blanket",),
    "no Araf readiness claim": ("araf",),
    "no GA or PP.7 certification claim": ("ga", "pp.7"),
}

# The evidence must not carry secret-bearing fields.  Campaign artifacts are
# public trust material; a database connection string with a password, a
# private key, or a token has no place in them.  Only field paths are reported,
# never the secret value, so a failed gate does not echo a secret to the log.
SECRET_KEY_HINTS = ("token", "secret", "password", "passwd", "private_key", "private-key")
SECRET_VALUE_PATTERNS = (
    # scheme://user:pass@...  — a connection string that embeds a password.
    re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/:@\s]+:[^@\s]+@"),
    re.compile(r"PRIVATE KEY"),
    re.compile(r"-----BEGIN"),
)


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def mapping(value: Any, name: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        fail(errors, f"{name} must be an object")
        return None
    return value


def key_mapping(root: Mapping[str, Any], key: str, errors: list[str]) -> dict[str, Any] | None:
    return mapping(root.get(key), f"{key}", errors)


def required_string(value: Any, name: str, errors: list[str]) -> bool:
    if not isinstance(value, str) or not value.strip():
        fail(errors, f"{name} must be a non-empty string")
        return False
    return True


def required_int(value: Any, name: str, errors: list[str], minimum: int | None = None) -> bool:
    if not isinstance(value, int) or isinstance(value, bool):
        fail(errors, f"{name} must be an integer")
        return False
    if minimum is not None and value < minimum:
        fail(errors, f"{name} must be at least {minimum}")
        return False
    return True


def validate_release(root: Mapping[str, Any], errors: list[str]) -> None:
    release = key_mapping(root, "release", errors)
    if release is None:
        return
    required_string(release.get("version"), "release.version", errors)
    for key in ("tag_object", "source_sha"):
        value = release.get(key)
        if not isinstance(value, str) or not SHA1.fullmatch(value):
            fail(errors, f"release.{key} must be a lowercase 40-character hex digest")
    required_string(release.get("artifact_url"), "release.artifact_url", errors)
    for key in ("archive_sha256", "manifest_sha256", "sbom_sha256", "provenance_sha256"):
        value = release.get(key)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            fail(errors, f"release.{key} must be a lowercase 64-character hex digest")
    if not isinstance(release.get("signature_verified"), bool):
        fail(errors, "release.signature_verified must be a boolean")


def validate_harness(root: Mapping[str, Any], errors: list[str]) -> None:
    harness = key_mapping(root, "harness", errors)
    if harness is None:
        return
    value = harness.get("harness_sha")
    if not isinstance(value, str) or not SHA1.fullmatch(value):
        fail(errors, "harness.harness_sha must be a lowercase 40-character hex digest")
    value = harness.get("campaign_tree_digest")
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(errors, "harness.campaign_tree_digest must be a lowercase 64-character hex digest")


def validate_hosts(root: Mapping[str, Any], errors: list[str]) -> None:
    hosts = root.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        fail(errors, "hosts must be a non-empty list")
        return
    for index, host in enumerate(hosts):
        name = f"hosts[{index}]"
        host = mapping(host, name, errors)
        if host is None:
            continue
        required_string(host.get("name"), f"{name}.name", errors)
        required_string(host.get("distro"), f"{name}.distro", errors)
        required_string(host.get("distro_version"), f"{name}.distro_version", errors)
        required_string(host.get("kernel"), f"{name}.kernel", errors)
        required_string(host.get("architecture"), f"{name}.architecture", errors)
        if not isinstance(host.get("kvm"), bool):
            fail(errors, f"{name}.kvm must be a boolean")


def validate_database(root: Mapping[str, Any], errors: list[str]) -> None:
    database = key_mapping(root, "database", errors)
    if database is None:
        return
    backend = database.get("backend")
    if backend not in {"sqlite", "postgres"}:
        fail(errors, "database.backend must be 'sqlite' or 'postgres'")
        return
    if backend == "postgres":
        # The execution plan binds backend identity, not just its name.
        required_string(database.get("server_version"), "database.server_version", errors)
        required_int(database.get("migrations_applied"), "database.migrations_applied", errors, minimum=1)
        required_string(database.get("server_identity"), "database.server_identity", errors)


def validate_tier_verdict(value: Any, name: str, errors: list[str]) -> None:
    if value != "pass":
        fail(errors, f"{name} must be 'pass'; a non-pass executed tier does not support a campaign pass")


def validate_scale_tier(tier: Any, index: int, errors: list[str]) -> None:
    name = f"campaign.scale_tiers[{index}]"
    tier = mapping(tier, name, errors)
    if tier is None:
        return
    required_string(tier.get("name"), f"{name}.name", errors)
    required_int(tier.get("hypervisors"), f"{name}.hypervisors", errors, minimum=1)
    validate_tier_verdict(tier.get("verdict"), f"{name}.verdict", errors)


def validate_soak_tier(tier: Any, index: int, errors: list[str]) -> None:
    name = f"campaign.soak_tiers[{index}]"
    tier = mapping(tier, name, errors)
    if tier is None:
        return
    required_string(tier.get("name"), f"{name}.name", errors)
    # A soak tier whose declared duration is missing cannot be executed to the
    # declared envelope; fail closed on it.
    required_string(tier.get("duration"), f"{name}.duration", errors)
    required_string(tier.get("scale"), f"{name}.scale", errors)
    validate_tier_verdict(tier.get("verdict"), f"{name}.verdict", errors)


def validate_campaign(root: Mapping[str, Any], errors: list[str]) -> None:
    campaign = key_mapping(root, "campaign", errors)
    if campaign is None:
        return
    required_string(campaign.get("declared_scale_tier"), "campaign.declared_scale_tier", errors)
    required_string(campaign.get("declared_soak_tier"), "campaign.declared_soak_tier", errors)

    scale_tiers = campaign.get("scale_tiers")
    if not isinstance(scale_tiers, list) or not scale_tiers:
        fail(errors, "campaign.scale_tiers must be a non-empty list")
    elif not all(isinstance(tier, dict) for tier in scale_tiers):
        fail(errors, "campaign.scale_tiers must contain objects")
    else:
        scale_names = []
        for index, tier in enumerate(scale_tiers):
            validate_scale_tier(tier, index, errors)
            if isinstance(tier, dict):
                name = tier.get("name")
                if isinstance(name, str):
                    scale_names.append(name)
        declared = campaign.get("declared_scale_tier")
        if isinstance(declared, str) and declared not in scale_names:
            fail(errors, f"campaign.declared_scale_tier {declared!r} is not a declared scale tier")
        missing_scale = [name for name in REQUIRED_SCALE_TIERS if name not in scale_names]
        if missing_scale:
            fail(errors, "campaign.scale_tiers missing required tier(s): " + ", ".join(missing_scale))

    soak_tiers = campaign.get("soak_tiers")
    if not isinstance(soak_tiers, list) or not soak_tiers:
        fail(errors, "campaign.soak_tiers must be a non-empty list")
    elif not all(isinstance(tier, dict) for tier in soak_tiers):
        fail(errors, "campaign.soak_tiers must contain objects")
    else:
        soak_names = []
        for index, tier in enumerate(soak_tiers):
            validate_soak_tier(tier, index, errors)
            if isinstance(tier, dict):
                name = tier.get("name")
                if isinstance(name, str):
                    soak_names.append(name)
        declared = campaign.get("declared_soak_tier")
        if isinstance(declared, str) and declared not in soak_names:
            fail(errors, f"campaign.declared_soak_tier {declared!r} is not a declared soak tier")
        missing_soak = [name for name in REQUIRED_SOAK_TIERS if name not in soak_names]
        if missing_soak:
            fail(errors, "campaign.soak_tiers missing required tier(s): " + ", ".join(missing_soak))


def validate_results(root: Mapping[str, Any], errors: list[str]) -> None:
    results = root.get("results")
    if not isinstance(results, list) or not results:
        fail(errors, "results must be a non-empty list")
        return
    rows_seen = set()
    for index, result in enumerate(results):
        name = f"results[{index}]"
        result = mapping(result, name, errors)
        if result is None:
            continue
        row = result.get("acceptance_row")
        if not isinstance(row, str) or not row.strip() or row not in ACCEPTANCE_ROWS:
            fail(errors, f"{name}.acceptance_row must be a single acceptance row from {ACCEPTANCE_ROWS}")
        elif row in rows_seen:
            fail(errors, f"{name}.acceptance_row {row!r} is duplicated")
        else:
            rows_seen.add(row)
        # A claimed pass is not supported while any acceptance row is not pass.
        validate_tier_verdict(result.get("verdict"), f"{name}.verdict", errors)


def validate_negatives(root: Mapping[str, Any], errors: list[str]) -> None:
    non_claims = root.get("non_claims")
    if not isinstance(non_claims, list) or not non_claims:
        fail(errors, "non_claims must be a non-empty explicit list of claims NOT made")
    elif not all(isinstance(claim, str) and claim.strip() for claim in non_claims):
        fail(errors, "non_claims must contain non-empty strings")
    else:
        # Every declared non-claim must actually appear.  Match case-insensitive
        # substring on each key's distinctive fragment(s); the evidence may word
        # the disclaimer differently, but each required capability must be named.
        joined = " ".join(non_claims).lower()
        missing = [
            key for key, fragments in REQUIRED_NON_CLAIMS.items()
            if not any(fragment in joined for fragment in fragments)
        ]
        if missing:
            fail(errors, "non_claims missing required disclaimer(s): " + "; ".join(sorted(missing)))

    leaks = root.get("leaked_owned_resources")
    if not isinstance(leaks, list):
        fail(errors, "leaked_owned_resources must be an empty list")
    elif leaks:
        fail(errors, f"leaked_owned_resources must be empty; found {len(leaks)} leaked owned resource(s)")

    remaining = root.get("server_owned_endpoints_remaining")
    if not isinstance(remaining, int) or isinstance(remaining, bool) or remaining != 0:
        fail(errors, "server_owned_endpoints_remaining must be 0 (zero durable 'o3k-server:%' endpoints)")


def secret_hint_in(name: str) -> bool:
    return any(hint in name.lower() for hint in SECRET_KEY_HINTS)


def collect_secret_fields(value: Any, path: str, hits: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if secret_hint_in(str(key)):
                hits.append(child_path)
            collect_secret_fields(child, child_path, hits)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            collect_secret_fields(child, f"{path}[{index}]", hits)
    elif isinstance(value, str):
        for pattern in SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                hits.append(path)
                break


def validate_secrets(root: Mapping[str, Any], errors: list[str]) -> None:
    hits: list[str] = []
    collect_secret_fields(root, "evidence", hits)
    if hits:
        fail(errors, "secret-bearing field(s) present: " + ", ".join(hits))


def validate(document: Any) -> list[str]:
    errors: list[str] = []
    root = mapping(document, "evidence", errors)
    if root is None:
        return errors

    if root.get("schema") != SCHEMA:
        fail(errors, f"schema must be {SCHEMA!r}")
    if root.get("artifact_type") != ARTIFACT_TYPE:
        fail(errors, "invalid artifact_type")
    if root.get("schema_version") != 1:
        fail(errors, "schema_version must be 1")
    if root.get("phase") != PHASE:
        fail(errors, f"phase must be {PHASE}")

    validate_release(root, errors)
    validate_harness(root, errors)
    validate_hosts(root, errors)
    validate_database(root, errors)
    validate_campaign(root, errors)
    validate_results(root, errors)
    validate_negatives(root, errors)
    validate_secrets(root, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"PP.5 evidence validation FAILED: {exc}", file=sys.stderr)
        return 1
    errors = validate(document)
    if errors:
        print("PP.5 evidence validation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("PP.5 Small Edge v1 campaign evidence validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
