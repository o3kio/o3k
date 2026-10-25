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
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

from collections.abc import Mapping

from pp5_scale_soak_contract import ContractError, artifact_path, secret_paths, validate_run

SCHEMA = "o3k.pp5-small-edge.campaign-evidence.v1"
ARTIFACT_TYPE = "o3k-pp5-small-edge-campaign-evidence"
PHASE = "PP.5"

SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# S1/S2 are boundary smokes, S5 is the mandatory development foundation, and
# only S3/S10/S20 are the declared scale-certification tiers. Each result is
# represented separately so a boundary smoke cannot be mislabeled as a scale
# tier and S5 cannot replace a certification tier.
ACCEPTANCE_ROWS = "ABCDEFGHIJKLMNOPQRS"
REQUIRED_SCALE_CARDINALITIES = {
    "S3": 3,
    "S10": 10,
    "S20": 20,
}
REQUIRED_BOUNDARY_CARDINALITIES = {"S1": 1, "S2": 2}
FOUNDATION_CARDINALITY = ("S5", 5)
REQUIRED_SOAK_ENVELOPES = {
    "K-min": ("2h", "S10"),
    "K-full": ("12h", "S20"),
}

# Every tier the plan declares as required (PP5_EXECUTION_PLAN.md §4.1, §4.2,
# §12.2) must actually appear in the executed campaign.  A certification that
# drops a required tier row fails closed: the result may not silently choose a
# smaller envelope than the plan bound for this profile.
REQUIRED_SCALE_TIERS = ("S3", "S10", "S20")
REQUIRED_BOUNDARY_SMOKES = ("S1", "S2")
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


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_release(root: Mapping[str, Any], errors: list[str]) -> None:
    release = key_mapping(root, "release", errors)
    if release is None:
        return
    required_string(release.get("version"), "release.version", errors)
    required_string(release.get("tag"), "release.tag", errors)
    for key in ("tag_object", "source_sha", "source_tree"):
        value = release.get(key)
        if not isinstance(value, str) or not SHA1.fullmatch(value):
            fail(errors, f"release.{key} must be a lowercase 40-character hex digest")
    required_string(release.get("artifact_url"), "release.artifact_url", errors)
    for key in ("archive_sha256", "install_sha256", "manifest_sha256", "sbom_sha256",
                "provenance_sha256", "signature_bundle_sha256", "verification_report_sha256"):
        value = release.get(key)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            fail(errors, f"release.{key} must be a lowercase 64-character hex digest")
    if release.get("signature_verified") is not True:
        fail(errors, "release.signature_verified must be true")
    if release.get("provenance_verified") is not True:
        fail(errors, "release.provenance_verified must be true")
    if release.get("workflow_identity_verified") is not True:
        fail(errors, "release.workflow_identity_verified must be true")
    if release.get("transparency_verified") is not True:
        fail(errors, "release.transparency_verified must be true")
    if isinstance(release.get("version"), str) and isinstance(release.get("tag"), str) and release["tag"] != f"v{release['version']}":
        fail(errors, "release.tag must be the v-prefixed published release version")


def validate_release_artifacts(root: Mapping[str, Any], evidence_root: pathlib.Path, errors: list[str]) -> None:
    release = root.get("release")
    if not isinstance(release, dict):
        return
    artifacts = release.get("artifacts")
    if not isinstance(artifacts, dict):
        fail(errors, "release.artifacts must contain digest-checked release files")
        return
    expected = {
        "archive": "archive_sha256",
        "installer": "install_sha256",
        "manifest": "manifest_sha256",
        "sbom": "sbom_sha256",
        "provenance": "provenance_sha256",
        "signature_bundle": "signature_bundle_sha256",
        "verification_report": "verification_report_sha256",
    }
    for name, digest_key in expected.items():
        reference = artifacts.get(name)
        try:
            if not isinstance(reference, dict):
                raise ContractError(f"release.artifacts.{name} reference is required")
            path = artifact_path(evidence_root, reference.get("path"), reference.get("sha256"),
                                 f"release.artifacts.{name}")
            if reference.get("sha256") != release.get(digest_key):
                raise ContractError(f"release.artifacts.{name} digest differs from release.{digest_key}")
            if name == "installer" and release.get("install_sha256") != reference.get("sha256"):
                raise ContractError("release installer digest binding is inconsistent")
            if not path.is_file():
                raise ContractError(f"release.artifacts.{name} is not a regular file")
            if name == "verification_report":
                report = json.loads(path.read_text(encoding="utf-8"))
                secret_hits = secret_paths(report, "release.verification_report")
                if secret_hits:
                    raise ContractError("verification report contains secret-bearing field(s): " + ", ".join(secret_hits))
                if not isinstance(report, dict) or report.get("schema") != "o3k.release-verification-report.v1":
                    raise ContractError("verification report schema is invalid")
                if report.get("status") != "passed":
                    raise ContractError("release verification report did not pass")
                bindings = {
                    "version": "version", "tag": "tag", "tag_object": "tag_object",
                    "source_sha": "source_sha", "source_tree": "source_tree",
                    "archive_sha256": "archive_sha256", "install_sha256": "install_sha256",
                    "manifest_sha256": "manifest_sha256", "sbom_sha256": "sbom_sha256",
                    "provenance_sha256": "provenance_sha256",
                    "signature_bundle_sha256": "signature_bundle_sha256",
                }
                for report_key, release_key in bindings.items():
                    if report.get(report_key) != release.get(release_key):
                        raise ContractError(f"verification report {report_key} differs from release binding")
                checks = report.get("checks")
                if not isinstance(checks, dict):
                    raise ContractError("verification report checks must be an object")
                for check in ("archive_round_trip", "signature", "provenance", "workflow_identity", "transparency"):
                    if checks.get(check) != "passed":
                        raise ContractError(f"verification report {check} check did not pass")
                verifier = report.get("verifier")
                if not isinstance(verifier, dict) or not all(isinstance(verifier.get(key), str) and verifier[key]
                                                               for key in ("name", "version", "workflow_identity")):
                    raise ContractError("verification report verifier identity is incomplete")
        except (OSError, UnicodeError, json.JSONDecodeError, ContractError, TypeError) as error:
            fail(errors, f"release.artifacts.{name} invalid: {error}")


def validate_harness(root: Mapping[str, Any], errors: list[str]) -> None:
    harness = key_mapping(root, "harness", errors)
    if harness is None:
        return
    value = harness.get("harness_sha")
    if not isinstance(value, str) or not SHA1.fullmatch(value):
        fail(errors, "harness.harness_sha must be a lowercase 40-character hex digest")
    value = harness.get("harness_tree")
    if not isinstance(value, str) or not SHA1.fullmatch(value):
        fail(errors, "harness.harness_tree must be a lowercase 40-character hex digest")
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
    if backend != "postgres":
        fail(errors, "final PP.5 acceptance requires database.backend='postgres'")
        return
    required_string(database.get("server_version"), "database.server_version", errors)
    required_int(database.get("migrations_applied"), "database.migrations_applied", errors, minimum=1)
    required_string(database.get("server_identity"), "database.server_identity", errors)


def validate_tier_verdict(value: Any, name: str, errors: list[str]) -> None:
    if value != "pass":
        fail(errors, f"{name} must be 'pass'; a non-pass executed tier does not support a campaign pass")


def validate_run_artifact(
    row: Mapping[str, Any], index: int, kind: str, evidence_root: pathlib.Path,
    release: Mapping[str, Any], harness: Mapping[str, Any], errors: list[str]
) -> None:
    name = f"campaign.{kind}[{index}]"
    reference = row.get("run_artifact")
    try:
        path = artifact_path(evidence_root, reference.get("path") if isinstance(reference, dict) else None,
                             reference.get("sha256") if isinstance(reference, dict) else None,
                             f"{name}.run_artifact")
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ContractError("run artifact must contain an object")
        secret_hits = secret_paths(document, name)
        if secret_hits:
            raise ContractError("run artifact contains secret-bearing field(s): " + ", ".join(secret_hits))
        root_real = evidence_root.resolve(strict=True)
        run_directory = path.parent.resolve(strict=True).relative_to(root_real).as_posix() or "."
        tier_name = row.get("name")
        expected_database_identity = row.get("database_identity")
        expected_run_id = row.get("run_id")
        validate_run(document, tier_name, evidence_root, release.get("source_sha"), release.get("source_tree"),
                     harness.get("harness_sha"), harness.get("harness_tree"), run_directory,
                     release.get("tag"), release.get("archive_sha256"), expected_database_identity, expected_run_id,
                     artifact_root=path.parent)
        run_release = document.get("release", {})
        bindings = {
            "version": "version", "tag": "tag", "tag_object": "tag_object_sha",
            "source_sha": "source_sha", "source_tree": "source_tree",
            "archive_sha256": "archive_sha256", "install_sha256": "install_sha256",
            "manifest_sha256": "manifest_sha256", "sbom_sha256": "sbom_sha256",
            "provenance_sha256": "provenance_sha256", "signature_bundle_sha256": "signature_bundle_sha256",
            "verification_report_sha256": "verification_report_sha256",
        }
        for evidence_key, run_key in bindings.items():
            if release.get(evidence_key) != run_release.get(run_key):
                raise ContractError(f"run release {run_key} differs from final release binding")
        if row.get("verdict") != "pass":
            raise ContractError("run artifact cannot support a non-pass row")
        run_identity = document.get("run", {}).get("id")
        db_identity = document.get("database", {}).get("identity")
        if row.get("run_id") != run_identity:
            raise ContractError("declared run_id differs from the raw run artifact")
        if row.get("database_identity") != db_identity:
            raise ContractError("declared database identity differs from the raw run artifact")
        if kind == "scale_tiers":
            if row.get("hypervisors") != document.get("observed_eligible_host_count"):
                raise ContractError("declared hypervisors differ from observed eligible host count")
        else:
            elapsed = document.get("timestamps", {}).get("monotonic_elapsed_seconds")
            if row.get("duration_seconds") != elapsed:
                raise ContractError("declared soak duration differs from measured monotonic duration")
            if row.get("scale") != document.get("soak", {}).get("scale"):
                raise ContractError("declared soak scale differs from run artifact")
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError, TypeError, ValueError) as error:
        fail(errors, f"{name}.run_artifact invalid: {error}")


def validate_scale_tier(tier: Any, index: int, errors: list[str], evidence_root: pathlib.Path,
                        release: Mapping[str, Any], harness: Mapping[str, Any]) -> None:
    name = f"campaign.scale_tiers[{index}]"
    tier = mapping(tier, name, errors)
    if tier is None:
        return
    required_string(tier.get("name"), f"{name}.name", errors)
    required_string(tier.get("run_id"), f"{name}.run_id", errors)
    required_string(tier.get("database_identity"), f"{name}.database_identity", errors)
    tier_name = tier.get("name")
    hypervisors = tier.get("hypervisors")
    if required_int(hypervisors, f"{name}.hypervisors", errors, minimum=1):
        expected = REQUIRED_SCALE_CARDINALITIES.get(tier_name) if isinstance(tier_name, str) else None
        if expected is not None and hypervisors != expected:
            fail(errors, f"{name} {tier_name} must declare {expected} hypervisors")
    validate_tier_verdict(tier.get("verdict"), f"{name}.verdict", errors)
    validate_run_artifact(tier, index, "scale_tiers", evidence_root, release, harness, errors)


def validate_foundation_artifact(
    row: Mapping[str, Any], tier: str, expected_hosts: int, kind: str, index: int,
    evidence_root: pathlib.Path, release: Mapping[str, Any], harness: Mapping[str, Any],
    errors: list[str],
) -> None:
    name = f"campaign.{kind}[{index}].run_artifact"
    reference = row.get("run_artifact")
    try:
        path = artifact_path(
            evidence_root,
            reference.get("path") if isinstance(reference, dict) else None,
            reference.get("sha256") if isinstance(reference, dict) else None,
            name,
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ContractError("foundation artifact must contain an object")
        secret_hits = secret_paths(document, name)
        if secret_hits:
            raise ContractError("foundation artifact contains secret-bearing field(s): " + ", ".join(secret_hits))
        if document.get("schema") != "o3k.pp5-foundation-run.v1":
            raise ContractError("foundation artifact schema is invalid")
        if document.get("artifact_type") != "o3k-pp5-foundation-run" or document.get("status") != "passed":
            raise ContractError("foundation artifact must identify a passed PP.5 foundation run")
        if document.get("tier") != tier:
            raise ContractError(f"foundation artifact tier must be {tier}")
        source = document.get("source")
        run_release = document.get("release")
        run_harness = document.get("harness")
        run = document.get("run")
        database = document.get("database")
        observations = document.get("observations")
        for value, field in ((source, "source"), (run_release, "release"), (run_harness, "harness"),
                             (run, "run"), (database, "database"), (observations, "observations")):
            if not isinstance(value, dict):
                raise ContractError(f"foundation {field} must be an object")
        if source.get("sha") != release.get("source_sha") or source.get("tree") != release.get("source_tree"):
            raise ContractError("foundation source identity differs from the final candidate")
        release_bindings = {
            "version": "version", "tag": "tag", "tag_object": "tag_object",
            "source_sha": "source_sha", "source_tree": "source_tree",
            "archive_sha256": "archive_sha256", "install_sha256": "install_sha256",
            "manifest_sha256": "manifest_sha256", "sbom_sha256": "sbom_sha256",
            "provenance_sha256": "provenance_sha256", "signature_bundle_sha256": "signature_bundle_sha256",
            "verification_report_sha256": "verification_report_sha256",
        }
        for evidence_key, run_key in release_bindings.items():
            if release.get(evidence_key) != run_release.get(run_key):
                raise ContractError(f"foundation release {run_key} differs from final release binding")
        if run_harness.get("sha") != harness.get("harness_sha") or run_harness.get("tree") != harness.get("harness_tree"):
            raise ContractError("foundation harness identity differs from the final evidence binding")
        run_id = run.get("id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9]+-[A-Za-z0-9_-]{1,96}", run_id):
            raise ContractError("foundation run.id must include workflow run ID and unique lane suffix")
        workflow_run_id = run.get("workflow_run_id")
        if not isinstance(workflow_run_id, str) or not re.fullmatch(r"[0-9]+", workflow_run_id) or not run_id.startswith(workflow_run_id + "-"):
            raise ContractError("foundation workflow_run_id does not match run identity")
        if run.get("workflow_sha") != harness.get("harness_sha"):
            raise ContractError("foundation workflow SHA differs from the bound harness SHA")
        if not isinstance(run.get("runner_name"), str) or not run["runner_name"]:
            raise ContractError("foundation runner_name is required")
        evidence_root_name = run.get("evidence_root")
        if not isinstance(evidence_root_name, str) or not evidence_root_name:
            raise ContractError("foundation evidence_root is required")
        evidence_root_path = pathlib.PurePosixPath(evidence_root_name)
        if evidence_root_path.is_absolute() or ".." in evidence_root_path.parts:
            raise ContractError("foundation evidence_root must stay inside its evidence bundle")
        artifact_directory = path.parent.resolve(strict=True).relative_to(evidence_root.resolve(strict=True)).as_posix() or "."
        canonical_evidence_root = "." if evidence_root_name in ("", ".") else evidence_root_path.as_posix().rstrip("/")
        if artifact_directory != canonical_evidence_root:
            raise ContractError("foundation evidence_root differs from raw artifact directory")
        workflow_ref = run.get("workflow_ref")
        allowed_refs = {
            "o3kio/o3k/.github/workflows/real-host-validation.yml@refs/heads/main",
            "o3kio/o3k/.github/workflows/pp5-foundation.yml@refs/heads/main",
        }
        if workflow_ref not in allowed_refs:
            raise ContractError("foundation workflow must be a protected O3K workflow on main")
        if row.get("run_id") != run_id or row.get("database_identity") != database.get("identity"):
            raise ContractError("foundation row run/database identity differs from raw artifact")
        if database.get("backend") != "postgres" or not isinstance(database.get("server_version"), str) or not database["server_version"]:
            raise ContractError("foundation database must bind a PostgreSQL server version")
        if not is_positive_int(database.get("migrations_applied")):
            raise ContractError("foundation database migration count must be positive")
        expected_db = f"o3k_pp5_{tier.lower()}_{run_id}"
        if database.get("identity") != expected_db:
            raise ContractError("foundation PostgreSQL identity must be unique to tier and run")
        if not is_int(document.get("observed_eligible_host_count")) or document.get("observed_eligible_host_count") != expected_hosts:
            raise ContractError(f"foundation observed eligible host count must be {expected_hosts}")
        eligible_hosts = document.get("eligible_hosts")
        if not isinstance(eligible_hosts, list) or len(eligible_hosts) != expected_hosts:
            raise ContractError(f"foundation eligible_hosts must contain exactly {expected_hosts} hosts")
        host_ids = []
        for host in eligible_hosts:
            if not isinstance(host, dict):
                raise ContractError("foundation eligible host entries must be objects")
            if any(host.get(key) is not True for key in ("ready", "compute_capable", "placement_eligible")):
                raise ContractError("foundation eligible hosts must be Ready, compute-capable, and Placement-eligible")
            host_id = host.get("stable_host_id")
            if not isinstance(host_id, str) or not host_id:
                raise ContractError("foundation eligible host stable_host_id is required")
            host_ids.append(host_id)
        if len(set(host_ids)) != expected_hosts:
            raise ContractError("foundation eligible host identities must be unique")
        if (not is_int(document.get("owned_leaks")) or document.get("owned_leaks") != 0
                or not is_int(observations.get("owned_leaks")) or observations.get("owned_leaks") != 0):
            raise ContractError("foundation owned resource leak count must be zero")
        if not is_int(document.get("foreign_mutations")) or document.get("foreign_mutations") != 0:
            raise ContractError("foundation foreign mutation count must be zero")
        foreign_before = observations.get("foreign_fingerprint_before")
        foreign_after = observations.get("foreign_fingerprint_after")
        if not isinstance(foreign_before, str) or not foreign_before or foreign_before != foreign_after:
            raise ContractError("foundation foreign-state fingerprints are absent or changed")
        if tier in REQUIRED_BOUNDARY_CARDINALITIES:
            if (not is_int(observations.get("canonical_eligible_host_count"))
                    or observations.get("canonical_eligible_host_count") != expected_hosts):
                raise ContractError(f"{tier} canonical topology count must be {expected_hosts}")
            observed_ids = observations.get("canonical_eligible_host_ids")
            if not isinstance(observed_ids, list) or any(not isinstance(item, str) for item in observed_ids):
                raise ContractError(f"{tier} canonical topology identities must be a string list")
            if set(observed_ids) != set(host_ids) or len(observed_ids) != expected_hosts:
                raise ContractError(f"{tier} canonical topology identities differ from eligible hosts")
            if not is_int(observations.get("bootstrap_host_count")) or observations.get("bootstrap_host_count") != 1:
                raise ContractError(f"{tier} must prove exactly one bootstrap host")
            if (not is_int(observations.get("child_host_count"))
                    or observations.get("child_host_count") != expected_hosts - 1):
                raise ContractError(f"{tier} child host count differs from boundary tier")
            if not is_int(observations.get("initial_workload_count")) or observations.get("initial_workload_count") != 0:
                raise ContractError(f"{tier} initial workload count must be zero")
            if observations.get("workload_reached_active") is not True:
                raise ContractError(f"{tier} must prove a real workload reached ACTIVE")
            if (not is_int(observations.get("provider_allocations_before_workload"))
                    or observations.get("provider_allocations_before_workload") != 0):
                raise ContractError(f"{tier} provider allocations must be zero before workload creation")
            if observations.get("supported_api_teardown") is not True:
                raise ContractError(f"{tier} must prove supported API teardown")
        else:
            gates = observations.get("lifecycle_gates")
            required = set("ABCDEFGHIJKLMNOPQR")
            if not isinstance(gates, list) or any(not isinstance(item, str) for item in gates) or len(gates) != len(required) or set(gates) != required:
                raise ContractError("S5 must prove every lifecycle gate A through R exactly once")
            if observations.get("supported_api_teardown") is not True:
                raise ContractError("S5 must prove supported API teardown")
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError, TypeError, ValueError) as error:
        fail(errors, f"{name} invalid: {error}")


def is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_boundary_smoke(smoke: Any, index: int, errors: list[str], evidence_root: pathlib.Path,
                            release: Mapping[str, Any], harness: Mapping[str, Any]) -> None:
    name = f"campaign.boundary_smokes[{index}]"
    smoke = mapping(smoke, name, errors)
    if smoke is None:
        return
    required_string(smoke.get("name"), f"{name}.name", errors)
    smoke_name = smoke.get("name")
    expected = REQUIRED_BOUNDARY_CARDINALITIES.get(smoke_name) if isinstance(smoke_name, str) else None
    if expected is None:
        fail(errors, f"{name}.name must be S1 or S2")
    if required_int(smoke.get("hypervisors"), f"{name}.hypervisors", errors, minimum=1) and expected is not None:
        if smoke.get("hypervisors") != expected:
            fail(errors, f"{name} {smoke_name} must declare {expected} hypervisors")
    validate_tier_verdict(smoke.get("verdict"), f"{name}.verdict", errors)
    if expected is not None:
        validate_foundation_artifact(smoke, smoke_name, expected, "boundary_smokes", index,
                                     evidence_root, release, harness, errors)


def validate_foundation_tier(foundation: Any, errors: list[str], evidence_root: pathlib.Path,
                             release: Mapping[str, Any], harness: Mapping[str, Any]) -> None:
    name = "campaign.foundation_tier"
    foundation = mapping(foundation, name, errors)
    if foundation is None:
        return
    required_string(foundation.get("name"), f"{name}.name", errors)
    if foundation.get("name") != FOUNDATION_CARDINALITY[0]:
        fail(errors, f"{name}.name must be S5")
    if required_int(foundation.get("hypervisors"), f"{name}.hypervisors", errors, minimum=1):
        if foundation.get("hypervisors") != FOUNDATION_CARDINALITY[1]:
            fail(errors, f"{name} S5 must declare 5 hypervisors")
    validate_tier_verdict(foundation.get("verdict"), f"{name}.verdict", errors)
    validate_foundation_artifact(foundation, "S5", FOUNDATION_CARDINALITY[1], "foundation_tier", 0,
                                 evidence_root, release, harness, errors)


def validate_soak_tier(tier: Any, index: int, errors: list[str], evidence_root: pathlib.Path,
                       release: Mapping[str, Any], harness: Mapping[str, Any]) -> None:
    name = f"campaign.soak_tiers[{index}]"
    tier = mapping(tier, name, errors)
    if tier is None:
        return
    required_string(tier.get("name"), f"{name}.name", errors)
    required_string(tier.get("run_id"), f"{name}.run_id", errors)
    required_string(tier.get("database_identity"), f"{name}.database_identity", errors)
    # A soak tier whose declared duration is missing cannot be executed to the
    # declared envelope; fail closed on it.
    tier_name = tier.get("name")
    duration = tier.get("duration")
    scale = tier.get("scale")
    required_string(duration, f"{name}.duration", errors)
    required_string(scale, f"{name}.scale", errors)
    expected = REQUIRED_SOAK_ENVELOPES.get(tier_name) if isinstance(tier_name, str) else None
    if expected is not None:
        expected_duration, expected_scale = expected
        if duration != expected_duration:
            fail(errors, f"{name} {tier_name} must declare duration {expected_duration}")
        if scale != expected_scale:
            fail(errors, f"{name} {tier_name} must declare scale {expected_scale}")
    validate_tier_verdict(tier.get("verdict"), f"{name}.verdict", errors)
    validate_run_artifact(tier, index, "soak_tiers", evidence_root, release, harness, errors)


def validate_soak_scale_baseline_binding(
    soak_row: Mapping[str, Any], scale_rows: list[Any], index: int,
    evidence_root: pathlib.Path, errors: list[str],
) -> None:
    name = f"campaign.soak_tiers[{index}].scale_baseline"
    soak_name = soak_row.get("name")
    expected_scale = {"K-min": "S10", "K-full": "S20"}.get(soak_name)
    if expected_scale is None:
        return
    scale_row = next((row for row in scale_rows
                      if isinstance(row, dict) and row.get("name") == expected_scale), None)
    if scale_row is None:
        fail(errors, f"{name} requires the campaign {expected_scale} scale run")
        return
    try:
        soak_ref = soak_row.get("run_artifact")
        soak_path = artifact_path(
            evidence_root,
            soak_ref.get("path") if isinstance(soak_ref, dict) else None,
            soak_ref.get("sha256") if isinstance(soak_ref, dict) else None,
            f"campaign.soak_tiers[{index}].run_artifact",
        )
        soak_document = json.loads(soak_path.read_text(encoding="utf-8"))
        if not isinstance(soak_document, dict) or not isinstance(soak_document.get("soak"), dict):
            raise ContractError("soak run artifact has no soak object")
        baseline = soak_document["soak"].get("scale_baseline")
        if not isinstance(baseline, dict) or baseline.get("tier") != expected_scale:
            raise ContractError(f"must bind the campaign {expected_scale} operational baseline")
        baseline_ref = baseline.get("evidence")
        scale_ref = scale_row.get("run_artifact")
        if not isinstance(baseline_ref, dict) or not isinstance(scale_ref, dict):
            raise ContractError("scale baseline and campaign scale row require artifact references")
        if (baseline_ref.get("path") != scale_ref.get("path")
                or baseline_ref.get("sha256") != scale_ref.get("sha256")):
            raise ContractError(f"must reference the exact campaign {expected_scale} run artifact")
        if baseline.get("run_id") != scale_row.get("run_id"):
            raise ContractError(f"must use the campaign {expected_scale} run identity")
        scale_run = json.loads(artifact_path(
            evidence_root, scale_ref.get("path"), scale_ref.get("sha256"),
            f"campaign.scale_tiers.{expected_scale}.run_artifact",
        ).read_text(encoding="utf-8"))
        if (not isinstance(scale_run, dict)
                or soak_row.get("run_id") == scale_row.get("run_id")
                or scale_run.get("run", {}).get("id") != baseline.get("run_id")):
            raise ContractError("soak and scale baseline run identities are invalid or shared")
        if baseline.get("resource_baseline_sha256") != hashlib.sha256(
            json.dumps(scale_run.get("resource_baseline"), sort_keys=True,
                       separators=(",", ":")).encode("utf-8")
        ).hexdigest():
            raise ContractError("resource baseline digest differs from the campaign scale run")
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError, TypeError, ValueError) as error:
        fail(errors, f"{name} invalid: {error}")


def validate_campaign(root: Mapping[str, Any], errors: list[str], evidence_root: pathlib.Path) -> None:
    campaign = key_mapping(root, "campaign", errors)
    if campaign is None:
        return

    run_ids: list[str] = []
    database_ids: list[str] = []
    required_string(campaign.get("declared_scale_tier"), "campaign.declared_scale_tier", errors)
    required_string(campaign.get("declared_soak_tier"), "campaign.declared_soak_tier", errors)

    release = root.get("release") if isinstance(root.get("release"), dict) else {}
    harness = root.get("harness") if isinstance(root.get("harness"), dict) else {}
    validate_foundation_tier(campaign.get("foundation_tier"), errors, evidence_root, release, harness)
    foundation = campaign.get("foundation_tier")
    if isinstance(foundation, dict):
        if isinstance(foundation.get("run_id"), str):
            run_ids.append(foundation["run_id"])
        if isinstance(foundation.get("database_identity"), str):
            database_ids.append(foundation["database_identity"])

    boundary_smokes = campaign.get("boundary_smokes")
    if not isinstance(boundary_smokes, list) or not boundary_smokes:
        fail(errors, "campaign.boundary_smokes must be a non-empty list")
    elif not all(isinstance(smoke, dict) for smoke in boundary_smokes):
        fail(errors, "campaign.boundary_smokes must contain objects")
    else:
        boundary_names = []
        for index, smoke in enumerate(boundary_smokes):
            validate_boundary_smoke(smoke, index, errors, evidence_root, release, harness)
            if isinstance(smoke.get("run_id"), str):
                run_ids.append(smoke["run_id"])
            if isinstance(smoke.get("database_identity"), str):
                database_ids.append(smoke["database_identity"])
            name = smoke.get("name")
            if isinstance(name, str):
                boundary_names.append(name)
        missing = [name for name in REQUIRED_BOUNDARY_SMOKES if name not in boundary_names]
        if missing:
            fail(errors, "campaign.boundary_smokes missing required smoke(s): " + ", ".join(missing))
        duplicates = sorted({name for name in boundary_names if boundary_names.count(name) > 1})
        if duplicates:
            fail(errors, "campaign.boundary_smokes duplicate smoke(s): " + ", ".join(duplicates))

    scale_tiers = campaign.get("scale_tiers")
    if not isinstance(scale_tiers, list) or not scale_tiers:
        fail(errors, "campaign.scale_tiers must be a non-empty list")
    elif not all(isinstance(tier, dict) for tier in scale_tiers):
        fail(errors, "campaign.scale_tiers must contain objects")
    else:
        scale_names = []
        for index, tier in enumerate(scale_tiers):
            release = root.get("release") if isinstance(root.get("release"), dict) else {}
            harness = root.get("harness") if isinstance(root.get("harness"), dict) else {}
            validate_scale_tier(tier, index, errors, evidence_root, release, harness)
            if isinstance(tier, dict):
                name = tier.get("name")
                if isinstance(name, str):
                    scale_names.append(name)
                if isinstance(tier.get("run_id"), str):
                    run_ids.append(tier["run_id"])
                if isinstance(tier.get("database_identity"), str):
                    database_ids.append(tier["database_identity"])
        declared = campaign.get("declared_scale_tier")
        if isinstance(declared, str) and declared not in scale_names:
            fail(errors, f"campaign.declared_scale_tier {declared!r} is not a declared scale tier")
        missing_scale = [name for name in REQUIRED_SCALE_TIERS if name not in scale_names]
        if missing_scale:
            fail(errors, "campaign.scale_tiers missing required tier(s): " + ", ".join(missing_scale))
        duplicate_scale = sorted({name for name in scale_names if scale_names.count(name) > 1})
        if duplicate_scale:
            fail(errors, "campaign.scale_tiers duplicate tier(s): " + ", ".join(duplicate_scale))

    soak_tiers = campaign.get("soak_tiers")
    if not isinstance(soak_tiers, list) or not soak_tiers:
        fail(errors, "campaign.soak_tiers must be a non-empty list")
    elif not all(isinstance(tier, dict) for tier in soak_tiers):
        fail(errors, "campaign.soak_tiers must contain objects")
    else:
        soak_names = []
        for index, tier in enumerate(soak_tiers):
            release = root.get("release") if isinstance(root.get("release"), dict) else {}
            harness = root.get("harness") if isinstance(root.get("harness"), dict) else {}
            validate_soak_tier(tier, index, errors, evidence_root, release, harness)
            if isinstance(tier, dict):
                name = tier.get("name")
                if isinstance(name, str):
                    soak_names.append(name)
                if isinstance(tier.get("run_id"), str):
                    run_ids.append(tier["run_id"])
                if isinstance(tier.get("database_identity"), str):
                    database_ids.append(tier["database_identity"])
                if isinstance(scale_tiers, list):
                    validate_soak_scale_baseline_binding(tier, scale_tiers, index, evidence_root, errors)
        declared = campaign.get("declared_soak_tier")
        if isinstance(declared, str) and declared not in soak_names:
            fail(errors, f"campaign.declared_soak_tier {declared!r} is not a declared soak tier")
        missing_soak = [name for name in REQUIRED_SOAK_TIERS if name not in soak_names]
        if missing_soak:
            fail(errors, "campaign.soak_tiers missing required tier(s): " + ", ".join(missing_soak))
        duplicate_soak = sorted({name for name in soak_names if soak_names.count(name) > 1})
        if duplicate_soak:
            fail(errors, "campaign.soak_tiers duplicate tier(s): " + ", ".join(duplicate_soak))
    if len(run_ids) != len(set(run_ids)):
        fail(errors, "campaign run IDs must be unique across all foundation, scale, and soak tiers")
    if len(database_ids) != len(set(database_ids)):
        fail(errors, "campaign PostgreSQL database identities must be unique across all foundation, scale, and soak tiers")


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
    missing_rows = sorted(set(ACCEPTANCE_ROWS) - rows_seen)
    if missing_rows:
        fail(errors, "results missing acceptance row(s): " + ", ".join(missing_rows))


def validate_negatives(root: Mapping[str, Any], errors: list[str]) -> None:
    non_claims = root.get("non_claims")
    if not isinstance(non_claims, list) or not non_claims:
        fail(errors, "non_claims must be a non-empty explicit list of claims NOT made")
    elif not all(isinstance(claim, str) and claim.strip() for claim in non_claims):
        fail(errors, "non_claims must contain non-empty strings")
    else:
        # Every declared non-claim must actually appear. Match case-insensitively
        # and require word boundaries around single-token fragments so incidental
        # text such as "thanks" cannot satisfy the HA disclaimer.
        joined = " ".join(non_claims).lower()

        def names_fragment(fragment: str) -> bool:
            escaped = re.escape(fragment)
            left = r"(?<!\w)" if fragment and fragment[0].isalnum() else ""
            right = r"(?!\w)" if fragment and fragment[-1].isalnum() else ""
            return re.search(left + escaped + right, joined) is not None

        missing = [
            key for key, fragments in REQUIRED_NON_CLAIMS.items()
            if not any(names_fragment(fragment) for fragment in fragments)
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


def validate(document: Any, evidence_root: pathlib.Path | None = None) -> list[str]:
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
    validate_release_artifacts(root, evidence_root or pathlib.Path.cwd(), errors)
    validate_harness(root, errors)
    validate_hosts(root, errors)
    validate_database(root, errors)
    validate_campaign(root, errors, evidence_root or pathlib.Path.cwd())
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
    errors = validate(document, args.evidence.resolve().parent)
    if errors:
        print("PP.5 evidence validation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("PP.5 Small Edge v1 campaign evidence validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
