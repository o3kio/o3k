#!/usr/bin/env python3
"""Fail-closed evidence contract for PP.5 scale and soak runs.

Run artifacts are produced by the protected runner. This module validates the
observed evidence; configured scale, duration, or workflow inputs alone never
constitute a passing result.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import pathlib
import re
import statistics
import sys
import uuid
from collections import Counter
from typing import Any

SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAC_ADDRESS = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
SCALE_HOSTS = {"S3": 3, "S10": 10, "S20": 20}
SOAKS = {"K-min": ("S10", 7200), "K-full": ("S20", 43200)}

GATE_RESOURCE_CLASSES = {
    "release_install": "release_artifact",
    "control_plane_init": "control_plane",
    "authenticated_joins": "capacity_topology",
    "canonical_topology": "capacity_topology",
    "placement": "compute_placement",
    "capacity_change": "compute_capacity",
    "drain": "building_block_lifecycle",
    "placement_rejection": "compute_placement",
    "resident_blocker": "building_block_lifecycle",
    "remove": "building_block_lifecycle",
    "replacement": "building_block_lifecycle",
    "control_plane_restart": "control_plane_process",
    "postgres_restart": "postgres_process",
    "identity_reconstruction": "capacity_identity",
    "projection_convergence": "capacity_projection",
    "fabric_networking": "fabric_network",
    "tenant_isolation": "tenant_network_security",
    "mtu": "network_mtu",
    "endpoint_lifecycle": "network_endpoint",
    "agent_restart": "agent_process",
    "durable_work_recovery": "durable_work",
    "quota_allocation": "quota_allocation",
    "supported_teardown": "owned_resources",
    "owned_leaks_zero": "owned_resources",
    "foreign_state_unchanged": "foreign_inventory",
}
GATE_OBSERVER_TYPES = {
    "release_install": {"release_verifier"},
    "control_plane_init": {"authenticated_api", "protected_runner_command"},
    "authenticated_joins": {"authenticated_api", "capacity_api"},
    "canonical_topology": {"capacity_api"},
    "placement": {"authenticated_api", "capacity_api"},
    "capacity_change": {"capacity_api"},
    "drain": {"capacity_api"},
    "placement_rejection": {"authenticated_api", "capacity_api"},
    "resident_blocker": {"capacity_api", "authenticated_api"},
    "remove": {"capacity_api"},
    "replacement": {"capacity_api", "authenticated_api"},
    "control_plane_restart": {"host_procfs_read_only", "authenticated_api"},
    "postgres_restart": {"host_procfs_read_only", "postgresql_read_only"},
    "identity_reconstruction": {"capacity_api"},
    "projection_convergence": {"capacity_api", "authenticated_api"},
    "fabric_networking": {"packet_probe"},
    "tenant_isolation": {"packet_probe", "host_network_read_only"},
    "mtu": {"packet_probe"},
    "endpoint_lifecycle": {"authenticated_api", "provider_api"},
    "agent_restart": {"host_procfs_read_only", "agent_api"},
    "durable_work_recovery": {"durable_work_api", "authenticated_api"},
    "quota_allocation": {"capacity_api", "authenticated_api"},
    "supported_teardown": {"authenticated_api", "host_inventory_read_only"},
    "owned_leaks_zero": {"host_inventory_read_only"},
    "foreign_state_unchanged": {"host_inventory_read_only"},
}
SOAK_SAMPLE_OBSERVER_TYPES = {
    "authenticated_api", "durable_work_api", "host_procfs_read_only", "postgresql_read_only",
}
LIFECYCLE_GATES = (
    "release_install", "control_plane_init", "authenticated_joins",
    "canonical_topology", "placement", "capacity_change", "drain",
    "placement_rejection", "resident_blocker", "remove", "replacement",
    "control_plane_restart", "postgres_restart", "identity_reconstruction",
    "projection_convergence", "fabric_networking", "tenant_isolation",
    "mtu", "endpoint_lifecycle", "agent_restart", "durable_work_recovery",
    "quota_allocation", "supported_teardown", "owned_leaks_zero",
    "foreign_state_unchanged",
)
SOAK_SAMPLE_FIELDS = (
    "elapsed_seconds", "eligible_hosts", "server_count", "create_attempts",
    "create_successes", "delete_attempts", "delete_successes", "operation_failures",
    "operations_in_flight", "retries", "quota_usage", "allocation_count", "owned_endpoints",
    "orphan_endpoints", "durable_work_pending", "durable_work_applying",
    "durable_work_unknown", "durable_work_retryable", "oldest_work_age_seconds",
    "o3kd_rss_bytes", "o3kd_fd_count",
    "postgres_connections", "postgres_database_size_bytes", "process_count", "thread_count",
    "reconciliation_latency_ms", "orphan_repair_duration_ms", "orphan_repair_cpu_millis",
    "deleted_server_history_size",
)
RESOURCE_LIMITS = {
    "o3kd_rss_bytes": {"absolute": 64 * 1024 * 1024, "fraction": 0.25},
    "o3kd_fd_count": {"absolute": 32, "fraction": 0.25},
    "agent_rss_bytes": {"absolute": 64 * 1024 * 1024, "fraction": 0.25},
    "agent_fd_count": {"absolute": 32, "fraction": 0.25},
    "process_count": {"absolute": 4, "fraction": 0.25},
    "thread_count": {"absolute": 16, "fraction": 0.25},
    "postgres_connections": {"absolute": 5, "fraction": 0.25},
    "postgres_database_size_bytes": {"absolute": 64 * 1024 * 1024, "fraction": 0.10},
    "quota_usage": {"absolute": 1, "fraction": 0.10},
    "allocation_count": {"absolute": 1, "fraction": 0.10},
    "owned_endpoints": {"absolute": 1, "fraction": 0.10},
    "orphan_endpoints": {"absolute": 1, "fraction": 0.0},
    "durable_work_pending": {"absolute": 10, "fraction": 1.0},
    "durable_work_applying": {"absolute": 10, "fraction": 1.0},
    "durable_work_unknown": {"absolute": 1, "fraction": 1.0},
    "durable_work_retryable": {"absolute": 1, "fraction": 1.0},
    "oldest_work_age_seconds": {"absolute": 300, "fraction": 1.0},
}
SECRET_KEY_HINTS = ("token", "secret", "password", "passwd", "private_key", "private-key")
SECRET_VALUE_PATTERNS = (
    re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/:@\s]+:[^@\s]+@"),
    re.compile(r"PRIVATE KEY"),
    re.compile(r"-----BEGIN"),
)


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def object_at(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    require(isinstance(value, dict), f"{key} must be an object")
    return value


def secret_paths(value: Any, path: str = "evidence") -> list[str]:
    """Return sensitive field paths only; never include secret values."""
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if any(hint in str(key).lower() for hint in SECRET_KEY_HINTS):
                hits.append(child_path)
            hits.extend(secret_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            hits.extend(secret_paths(child, f"{path}[{index}]"))
    elif isinstance(value, str) and any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS):
        hits.append(path)
    return hits


def reject_secrets(document: Any, name: str) -> None:
    hits = secret_paths(document, name)
    require(not hits, f"{name} contains secret-bearing field(s): " + ", ".join(hits))


def checked_digest(path: pathlib.Path, expected: str) -> None:
    require(bool(SHA256.fullmatch(expected)), "artifact SHA-256 is malformed")
    require(not path.is_symlink() and path.is_file(), "evidence artifact must be a regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    require(digest.hexdigest() == expected, "evidence artifact digest mismatch")


def string_list(value: Any, name: str) -> list[str]:
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
            f"{name} must be a list of non-empty strings")
    return value


def finite_number(value: Any, name: str, minimum: float = 0) -> float:
    require(isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value >= minimum,
            f"{name} must be finite and at least {minimum}")
    return float(value)


def strict_json_equal(left: Any, right: Any, name: str) -> bool:
    """Compare JSON values without Python's bool/int equivalence (False == 0)."""
    try:
        left_json = json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False)
        right_json = json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ContractError(f"{name} must contain finite JSON values") from error
    return left_json == right_json


def artifact_path(root: pathlib.Path, value: Any, digest: Any, field: str) -> pathlib.Path:
    require(isinstance(value, str) and value, f"{field}.path must be non-empty")
    relative = pathlib.PurePosixPath(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{field}.path escapes evidence root")
    require(not root.is_symlink(), "evidence root must not be a symlink")
    root = root.resolve(strict=True)
    require(root.is_dir(), "evidence root must be a directory")
    target = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), f"{field}.path must not contain symlinks")
    resolved = target.resolve(strict=True)
    require(resolved == root or root in resolved.parents, f"{field}.path escapes evidence root")
    require(isinstance(digest, str), f"{field}.sha256 is required")
    checked_digest(resolved, digest)
    return resolved


def load_json_artifact(root: pathlib.Path, entry: Any, name: str) -> dict[str, Any]:
    require(isinstance(entry, dict), f"{name} evidence reference must be an object")
    path = artifact_path(root, entry.get("path"), entry.get("sha256"), name)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{name} artifact is not valid JSON") from error
    require(isinstance(document, dict), f"{name} artifact must contain a JSON object")
    reject_secrets(document, name)
    return document


def validate_bound_observation(
    root: pathlib.Path,
    entry: Any,
    name: str,
    schema: str,
    document: dict[str, Any],
    tier: str,
) -> dict[str, Any]:
    """Load an immutable observation artifact and bind it to this campaign."""
    artifact = load_json_artifact(root, entry, name)
    require(artifact.get("schema") == schema, f"{name} schema is invalid")
    for key, expected in (
        ("run_id", document["run"]["id"]),
        ("source_sha", document["source"]["sha"]),
        ("source_tree", document["source"]["tree"]),
        ("harness_sha", document["harness"]["sha"]),
        ("harness_tree", document["harness"]["tree"]),
        ("workflow_sha", document["run"]["workflow_sha"]),
        ("database_identity", document["database"]["identity"]),
        ("tier", tier),
    ):
        require(artifact.get(key) == expected, f"{name} {key} differs from the campaign")
    return artifact


def validate_identity(
    document: dict[str, Any],
    tier: str,
    expected_source_sha: str | None,
    expected_source_tree: str | None = None,
    expected_harness_sha: str | None = None,
    expected_harness_tree: str | None = None,
    expected_run_directory: str | None = None,
    expected_release_tag: str | None = None,
    expected_archive_sha256: str | None = None,
    expected_database_identity: str | None = None,
    expected_run_id: str | None = None,
) -> None:
    require(document.get("schema") == "o3k.pp5-scale-soak-run.v1", "schema is unsupported")
    require(document.get("artifact_type") == "o3k-pp5-scale-soak-run", "artifact_type is invalid")
    require(document.get("status") == "passed", "run status must be passed")
    require(document.get("tier") == tier, f"tier must be {tier}")
    source = object_at(document, "source")
    source_sha = source.get("sha")
    require(isinstance(source_sha, str) and SHA1.fullmatch(source_sha), "source.sha is invalid")
    require(isinstance(source.get("tree"), str) and SHA1.fullmatch(source["tree"]), "source.tree is invalid")
    if expected_source_sha:
        require(source_sha == expected_source_sha, "run source SHA does not match the expected candidate")
    if expected_source_tree:
        require(source["tree"] == expected_source_tree, "run source tree does not match the expected candidate")
    release = object_at(document, "release")
    require(isinstance(release.get("version"), str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+", release["version"]),
            "release.version must be a canonical prerelease version without the v prefix")
    require(isinstance(release.get("tag"), str) and release["tag"] == f"v{release['version']}",
            "release.tag must be v-prefixed and match release.version")
    if expected_release_tag:
        require(release["tag"] == expected_release_tag, "run release tag does not match the protected workflow input")
    require(isinstance(release.get("tag_object_sha"), str) and SHA1.fullmatch(release["tag_object_sha"]), "release.tag_object_sha is invalid")
    require(release.get("source_sha") == source_sha, "release source SHA differs from tested source")
    require(isinstance(release.get("source_tree"), str) and release["source_tree"] == source["tree"], "release source tree differs from tested tree")
    for field in ("archive_sha256", "install_sha256", "manifest_sha256", "sbom_sha256",
                  "provenance_sha256", "signature_bundle_sha256", "verification_report_sha256"):
        require(isinstance(release.get(field), str) and SHA256.fullmatch(release[field]), f"release.{field} is invalid")
    if expected_archive_sha256:
        require(release["archive_sha256"] == expected_archive_sha256,
                "run release archive digest does not match the protected workflow input")
    require(release.get("signature_verified") is True, "release signature verification must pass")
    require(release.get("provenance_verified") is True, "release provenance verification must pass")
    require(release.get("workflow_identity_verified") is True, "release workflow identity verification must pass")
    require(release.get("transparency_verified") is True, "release transparency verification must pass")
    harness = object_at(document, "harness")
    require(isinstance(harness.get("sha"), str) and SHA1.fullmatch(harness["sha"]), "harness.sha is invalid")
    require(isinstance(harness.get("tree"), str) and SHA1.fullmatch(harness["tree"]), "harness.tree is invalid")
    if expected_harness_sha:
        require(harness["sha"] == expected_harness_sha, "run harness SHA differs from the campaign harness")
    if expected_harness_tree:
        require(harness["tree"] == expected_harness_tree, "run harness tree differs from the campaign harness")
    require(isinstance(harness.get("workflow_sha"), str) and SHA1.fullmatch(harness["workflow_sha"]),
            "harness.workflow_sha is invalid")
    run = object_at(document, "run")
    require(isinstance(run.get("id"), str) and re.fullmatch(r"[0-9]+-[A-Za-z0-9_-]{1,96}", run["id"]),
            "run.id must include the workflow run ID and a unique lane suffix")
    require(isinstance(run.get("workflow_run_id"), str) and re.fullmatch(r"[0-9]+", run["workflow_run_id"])
            and run["id"].startswith(run["workflow_run_id"] + "-"),
            "run.workflow_run_id must be the numeric prefix of the run identity")
    if expected_run_id:
        require(run["id"] == expected_run_id, "run identity differs from the protected workflow input")
    require(isinstance(run.get("workflow_ref"), str) and run["workflow_ref"], "run.workflow_ref is required")
    require(run["workflow_ref"] == "o3kio/o3k/.github/workflows/real-host-validation.yml@refs/heads/main",
            "run.workflow_ref must identify the canonical protected validation workflow on main")
    require(isinstance(run.get("workflow_sha"), str) and SHA1.fullmatch(run["workflow_sha"]), "run.workflow_sha is invalid")
    require(run["workflow_sha"] == harness["workflow_sha"],
            "workflow SHA differs from the explicitly bound workflow identity")
    require(isinstance(run.get("runner_name"), str) and run["runner_name"], "run.runner_name is required")
    require(isinstance(run.get("evidence_root"), str) and run["evidence_root"], "run.evidence_root is required")
    evidence_root = pathlib.PurePosixPath(run["evidence_root"])
    require(not evidence_root.is_absolute() and ".." not in evidence_root.parts,
            "run.evidence_root must be a portable path inside the evidence bundle")
    canonical_run_dir = "." if run["evidence_root"] in ("", ".") else evidence_root.as_posix().rstrip("/")
    require(canonical_run_dir == run["evidence_root"], "run.evidence_root must be canonical")
    if expected_run_directory is not None:
        require(canonical_run_dir == expected_run_directory,
                "run.evidence_root differs from the raw run artifact directory")
    database = object_at(document, "database")
    require(database.get("backend") == "postgres", "PP.5 scale/soak requires PostgreSQL")
    require(isinstance(database.get("identity"), str) and database["identity"], "database.identity is required")
    database_tier = tier.lower().replace("-", "_")
    require(database["identity"] == f"o3k_pp5_{database_tier}_{run['id']}",
            "database identity must be unique to the tier and workflow run")
    if expected_database_identity:
        require(database["identity"] == expected_database_identity,
                "database identity differs from the protected workflow input")
    require(isinstance(database.get("server_version"), str) and database["server_version"], "database.server_version is required")
    require(is_int(database.get("migrations_applied")) and database["migrations_applied"] > 0, "database.migrations_applied must be positive")
    timestamps = object_at(document, "timestamps")
    try:
        started = dt.datetime.fromisoformat(timestamps["started_at"].replace("Z", "+00:00"))
        finished = dt.datetime.fromisoformat(timestamps["finished_at"].replace("Z", "+00:00"))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ContractError("timestamps.started_at and finished_at must be ISO-8601 timestamps") from error
    require(started.tzinfo is not None and finished.tzinfo is not None, "timestamps must include a timezone")
    wall_elapsed = (finished - started).total_seconds()
    monotonic_elapsed = timestamps.get("monotonic_elapsed_seconds")
    require(isinstance(monotonic_elapsed, (int, float)) and not isinstance(monotonic_elapsed, bool)
            and math.isfinite(monotonic_elapsed) and monotonic_elapsed >= 0,
            "timestamps.monotonic_elapsed_seconds must be finite and non-negative")
    require(wall_elapsed >= 0 and abs(wall_elapsed - monotonic_elapsed) <= max(30, monotonic_elapsed * 0.01),
            "wall-clock interval does not corroborate monotonic elapsed duration")


def validate_hosts(document: dict[str, Any], expected: int) -> None:
    hosts = document.get("eligible_hosts")
    require(isinstance(hosts, list), "eligible_hosts must be a list of observed hosts")
    require(len(hosts) == expected, f"observed eligible host count must equal {expected}")
    identities: set[str] = set()
    compute_agents: set[str] = set()
    network_agents: set[str] = set()
    boot_ids: set[str] = set()
    for index, host in enumerate(hosts):
        require(isinstance(host, dict), f"eligible_hosts[{index}] must be an object")
        identity = host.get("stable_host_id")
        require(isinstance(identity, str) and identity, f"eligible_hosts[{index}].stable_host_id is required")
        require(identity not in identities, "eligible host identities must be unique")
        identities.add(identity)
        for field in ("ready", "compute_capable", "placement_eligible"):
            require(host.get(field) is True, f"eligible_hosts[{index}].{field} must be observed true")
        for field in ("kernel", "distro", "architecture", "kvm_state", "compute_agent_id", "compute_agent_epoch",
                      "network_agent_id", "network_agent_epoch", "fabric_generation", "kernel_boot_id"):
            require(isinstance(host.get(field), str) and host[field], f"eligible_hosts[{index}].{field} is required")
        require(isinstance(host.get("canonical_mac"), str) and MAC_ADDRESS.fullmatch(host["canonical_mac"]),
                f"eligible_hosts[{index}].canonical_mac is invalid")
        try:
            parsed_boot_id = uuid.UUID(host["kernel_boot_id"])
        except (AttributeError, TypeError, ValueError) as error:
            raise ContractError(f"eligible_hosts[{index}].kernel_boot_id must be a UUID") from error
        require(str(parsed_boot_id) == host["kernel_boot_id"],
                f"eligible_hosts[{index}].kernel_boot_id must be a canonical UUID")
        require(host["kernel_boot_id"] not in boot_ids,
                "eligible hosts must prove independent kernel boot identities")
        require(host["kvm_state"].lower() in {"enabled", "true", "1"},
                f"eligible_hosts[{index}].kvm_state must prove KVM is enabled")
        require(host["compute_agent_id"] not in compute_agents, "compute agent identities must be unique")
        require(host["network_agent_id"] not in network_agents, "network agent identities must be unique")
        compute_agents.add(host["compute_agent_id"])
        network_agents.add(host["network_agent_id"])
        boot_ids.add(host["kernel_boot_id"])


def validate_resource_budget(document: dict[str, Any], child_hosts: int) -> None:
    budget = object_at(document, "resource_budget")
    for field in ("physical_host_cpus", "physical_host_memory_bytes", "physical_disk_free_bytes",
                  "nested_vcpu_per_host", "nested_memory_bytes_per_host", "nested_disk_bytes_per_host",
                  "management_addresses_reserved"):
        require(is_int(budget.get(field)) and budget[field] > 0,
                f"resource_budget.{field} must be a positive integer")
    require(budget.get("kvm_available") is True, "resource_budget.kvm_available must be true")
    planned_cpu = child_hosts * budget["nested_vcpu_per_host"]
    planned_memory = child_hosts * budget["nested_memory_bytes_per_host"]
    planned_disk = child_hosts * budget["nested_disk_bytes_per_host"]
    require(budget["management_addresses_reserved"] >= child_hosts,
            "management address reservation is below the nested host count")
    require(planned_cpu <= budget["physical_host_cpus"], "nested vCPU budget exceeds physical host CPUs")
    require(planned_memory <= budget["physical_host_memory_bytes"], "nested memory budget exceeds physical host memory")
    require(planned_disk <= budget["physical_disk_free_bytes"], "nested disk budget exceeds available physical disk")


def validate_resource_baseline(document: dict[str, Any], expected_host_ids: set[str], database: dict[str, Any]) -> None:
    baseline = object_at(document, "resource_baseline")
    require(baseline.get("schema") == "o3k.pp5-resource-baseline.v1", "resource_baseline schema is unsupported")
    try:
        captured_at = dt.datetime.fromisoformat(baseline["captured_at"].replace("Z", "+00:00"))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ContractError("resource_baseline.captured_at must be ISO-8601") from error
    require(captured_at.tzinfo is not None, "resource_baseline.captured_at must include a timezone")
    controller = object_at(baseline, "controller")
    for field in ("rss_bytes", "fd_count", "process_count", "thread_count"):
        require(is_int(controller.get(field)) and controller[field] > 0,
                f"resource_baseline.controller.{field} must be a positive integer")
    postgres = object_at(baseline, "postgres")
    require(postgres.get("database_identity") == database.get("identity"),
            "resource baseline PostgreSQL identity differs from the run database")
    require(postgres.get("server_version") == database.get("server_version"),
            "resource baseline PostgreSQL version differs from the run database")
    for field in ("connections", "database_size_bytes"):
        require(is_int(postgres.get(field)) and postgres[field] >= 0,
                f"resource_baseline.postgres.{field} must be a non-negative integer")
    hosts = baseline.get("hosts")
    require(isinstance(hosts, list) and len(hosts) == len(expected_host_ids),
            "resource baseline must include every eligible host")
    seen: set[str] = set()
    for index, host in enumerate(hosts):
        require(isinstance(host, dict), f"resource_baseline.hosts[{index}] must be an object")
        host_id = host.get("stable_host_id")
        require(isinstance(host_id, str) and host_id in expected_host_ids and host_id not in seen,
                "resource baseline host identities must exactly cover eligible hosts")
        seen.add(host_id)
        for role in ("compute_agent", "network_agent"):
            process = object_at(host, role)
            eligible_host = next(
                (item for item in document["eligible_hosts"]
                 if isinstance(item, dict) and item.get("stable_host_id") == host_id),
                None,
            )
            require(eligible_host is not None,
                    f"resource baseline {role} host is absent from eligible host evidence")
            expected_agent_id = eligible_host.get(f"{role}_id")
            require(isinstance(expected_agent_id, str) and expected_agent_id,
                    f"eligible host {role} identity is required")
            require(process.get("agent_id") == expected_agent_id,
                    f"resource baseline {role} identity differs from eligible host evidence")
            require(is_int(process.get("pid")) and process["pid"] > 0,
                    f"resource baseline {role} PID must be positive")
            for field in ("rss_bytes", "fd_count"):
                require(is_int(process.get(field)) and process[field] >= 0,
                        f"resource baseline {role}.{field} must be non-negative")
    require(seen == expected_host_ids, "resource baseline host identities differ from eligible hosts")


def host_ids(document: dict[str, Any], key: str, expected: int) -> set[str]:
    rows = document.get(key)
    require(isinstance(rows, list) and len(rows) == expected,
            f"{key} must contain exactly {expected} observed hosts")
    identities = [row.get("stable_host_id") for row in rows if isinstance(row, dict)]
    require(len(identities) == expected and all(isinstance(item, str) and item for item in identities),
            f"{key} must contain stable host identities")
    require(len(set(identities)) == expected, f"{key} identities must be unique")
    return set(identities)


def validate_capture(row: dict[str, Any], name: str) -> None:
    captured_at = row.get("captured_at")
    try:
        timestamp = dt.datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise ContractError(f"{name}.captured_at must be an ISO-8601 timestamp") from error
    require(timestamp.tzinfo is not None, f"{name}.captured_at must include a timezone")
    require(isinstance(row.get("command_class"), str)
            and re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", row["command_class"]) is not None,
            f"{name}.command_class is invalid")
    require(is_int(row.get("exit_code")) and row["exit_code"] == 0,
            f"{name}.exit_code must be integer zero")
    raw_output = row.get("raw_output")
    require(isinstance(raw_output, str) and raw_output, f"{name}.raw_output must be retained")
    require(hashlib.sha256(raw_output.encode("utf-8")).hexdigest() == row.get("raw_output_sha256"),
            f"{name}.raw_output_sha256 does not match captured output")
    reject_secrets(row, name)


def validate_network_observations(artifact: dict[str, Any], eligible_hosts: dict[str, dict[str, Any]], icmp_summary: int) -> None:
    eligible_ids = set(eligible_hosts)
    probes = artifact.get("probes")
    require(isinstance(probes, list) and probes, "packet probe evidence must contain observations")
    seen_ids: set[str] = set()
    dhcp_hosts: set[str] = set()
    arp_matches: list[dict[str, Any]] = []
    icmp_received = 0
    icmp_sources: set[str] = set()
    required_network = {"tcp", "udp"}
    observed_network: set[str] = set()
    for index, probe in enumerate(probes):
        name = f"packet probe[{index}]"
        require(isinstance(probe, dict), f"{name} must be an object")
        probe_id = probe.get("probe_id")
        require(isinstance(probe_id, str) and probe_id and probe_id not in seen_ids,
                f"{name}.probe_id must be unique")
        seen_ids.add(probe_id)
        validate_capture(probe, name)
        kind = probe.get("kind")
        require(kind in {"dhcp_dora", "canonical_arp", "icmp", "tcp", "udp"},
                f"{name}.kind is unsupported")
        source = probe.get("source_host_id")
        require(source in eligible_ids, f"{name}.source_host_id is not an eligible host")
        if kind == "dhcp_dora":
            require(probe.get("result") == "passed" and probe.get("lease_acquired") is True,
                    f"{name} does not prove a DHCP DORA lease")
            dhcp_hosts.add(source)
            continue
        destination = probe.get("destination_host_id")
        require(destination in eligible_ids and destination != source,
                f"{name}.destination_host_id must be a different eligible host")
        if kind == "canonical_arp":
            require(probe.get("result") == "passed", f"{name} canonical ARP did not pass")
            resolved_mac = probe.get("resolved_mac")
            require(isinstance(resolved_mac, str) and MAC_ADDRESS.fullmatch(resolved_mac),
                    f"{name}.resolved_mac is invalid")
            require(probe.get("destination_canonical_mac") == eligible_hosts[destination]["canonical_mac"],
                    f"{name}.destination_canonical_mac differs from canonical host inventory")
            arp_matches.append(probe)
        elif kind == "icmp":
            sent, received = probe.get("packets_sent"), probe.get("packets_received")
            require(is_int(sent) and sent > 0 and is_int(received) and received == sent,
                    f"{name} must prove every ICMP request was received")
            require(probe.get("result") == "passed", f"{name} ICMP probe did not pass")
            icmp_received += received
            icmp_sources.add(source)
        else:
            require(probe.get("result") == "passed", f"{name} {kind} probe did not pass")
            require(is_int(probe.get("connections_succeeded")) and probe["connections_succeeded"] > 0,
                    f"{name} {kind} probe must prove a successful connection")
            observed_network.add(kind)
    require(dhcp_hosts == eligible_ids, "DHCP DORA evidence must cover every eligible host")
    require(bool(arp_matches), "canonical ARP evidence is missing")
    require(all(probe.get("resolved_mac") == eligible_hosts[probe["destination_host_id"]]["canonical_mac"]
                for probe in arp_matches),
            "canonical ARP result differs from the destination host canonical MAC")
    require(icmp_received == icmp_summary and icmp_received >= 6,
            "ICMP probe evidence does not match the gate summary or six-success minimum")
    require(len(icmp_sources) >= 2, "ICMP probe evidence must exercise at least two source hosts")
    require(required_network <= observed_network, "TCP and UDP packet probe evidence is required")


def validate_isolation_observations(artifact: dict[str, Any]) -> None:
    checks = artifact.get("checks")
    expected = {"cross_tenant_access", "forged_source_mac", "forged_source_ip"}
    require(isinstance(checks, list), "tenant isolation evidence checks must be a list")
    found: dict[str, dict[str, Any]] = {}
    for index, check in enumerate(checks):
        require(isinstance(check, dict), f"tenant isolation check[{index}] must be an object")
        name = check.get("kind")
        require(name in expected and name not in found, "tenant isolation evidence has an unknown or duplicate check")
        validate_capture(check, f"tenant isolation {name}")
        require(check.get("result") == "denied", f"tenant isolation {name} was not denied")
        found[name] = check
    require(set(found) == expected, "tenant isolation evidence is incomplete")
    before = artifact.get("foreign_fdb_fingerprint_before")
    after = artifact.get("foreign_fdb_fingerprint_after")
    require(isinstance(before, str) and before and before == after,
            "foreign FDB observation does not prove an unchanged fingerprint")


def validate_mtu_observations(artifact: dict[str, Any], tested: int, expected: int) -> None:
    require(artifact.get("tested_mtu_bytes") == tested and artifact.get("expected_mtu_bytes") == expected,
            "MTU observation differs from the gate summary")
    probes = artifact.get("probes")
    require(isinstance(probes, list), "MTU probes must be a list")
    by_kind: dict[str, dict[str, Any]] = {}
    for index, probe in enumerate(probes):
        require(isinstance(probe, dict), f"MTU probe[{index}] must be an object")
        kind = probe.get("kind")
        require(kind in {"boundary", "oversize"} and kind not in by_kind,
                "MTU evidence must contain one boundary and one oversize probe")
        validate_capture(probe, f"MTU {kind} probe")
        by_kind[kind] = probe
    require(set(by_kind) == {"boundary", "oversize"}, "MTU boundary/oversize evidence is incomplete")
    boundary, oversize = by_kind["boundary"], by_kind["oversize"]
    require(boundary.get("result") == "passed" and boundary.get("packet_size_bytes") == expected,
            "MTU boundary probe did not pass at the configured MTU")
    require(oversize.get("result") == "rejected" and is_int(oversize.get("packet_size_bytes"))
            and oversize["packet_size_bytes"] > expected,
            "MTU oversize probe did not prove rejection above the configured MTU")


def validate_process_observation(artifact: dict[str, Any], kind: str, document: dict[str, Any]) -> dict[str, Any]:
    expected_executables = {
        "controller": "o3kd",
        "postgres": "postgres",
        "compute_agent": "o3k-compute",
        "network_agent": "o3k-network",
    }
    require(kind in expected_executables, "process restart observation kind is unsupported")
    require(artifact.get("schema") == "o3k.pp5-process-restart-observation.v1",
            "process restart observation schema is invalid")
    require(artifact.get("process_kind") == kind, "process restart observation kind is invalid")
    require(artifact.get("owner_type") == "run-owned" and
            artifact.get("owner_run_id") == document["run"]["id"],
            "process restart observation is not bound to a run-owned process")
    require(artifact.get("observer_type") in {"host_procfs_read_only", "sudo_read_only"},
            "process restart observer must be read-only")
    validate_capture(artifact, "process restart observation")
    before, after = artifact.get("before"), artifact.get("after")
    require(isinstance(before, dict) and isinstance(after, dict),
            "process restart observation must contain before and after snapshots")
    for label, snapshot in (("before", before), ("after", after)):
        require(is_int(snapshot.get("pid")) and snapshot["pid"] > 0,
                f"process restart {label} PID must be positive")
        require(isinstance(snapshot.get("start_time"), str) and snapshot["start_time"],
                f"process restart {label} start time is required")
        executable = snapshot.get("executable")
        require(isinstance(executable, str) and pathlib.PurePosixPath(executable).is_absolute(),
                f"process restart {label} executable must be absolute")
        require(pathlib.PurePosixPath(executable).name == expected_executables[kind],
                f"process restart {label} executable does not identify {kind}")
    require(before["pid"] != after["pid"] and before["start_time"] != after["start_time"],
            "process restart observation must prove a new process")
    recovery = artifact.get("recovery")
    require(isinstance(recovery, dict) and recovery.get("ready") is True and
            is_int(recovery.get("consistent_observations")) and recovery["consistent_observations"] >= 2,
            "process restart observation lacks two consistent readiness observations")
    if kind == "postgres":
        require(artifact.get("database_identity") == document["database"]["identity"],
                "PostgreSQL process observation database identity mismatch")
        require(artifact.get("server_version") == document["database"]["server_version"],
                "PostgreSQL process observation server version mismatch")
        require(all(pathlib.PurePosixPath(snapshot["executable"]).name == "postgres"
                    for snapshot in (before, after)),
                "PostgreSQL process observation must identify postgres executables")
        data_identity = artifact.get("data_directory_identity")
        require(isinstance(data_identity, str) and data_identity,
                "PostgreSQL process observation data directory identity is required")
    elif kind == "controller":
        epochs = artifact.get("epochs")
        require(isinstance(epochs, dict) and is_int(epochs.get("before")) and
                is_int(epochs.get("after")) and epochs["after"] > epochs["before"],
                "controller restart observation must prove a newer controller epoch")
    else:
        agent_id = artifact.get("agent_id")
        require(isinstance(agent_id, str) and agent_id, "agent restart observation identity is required")
        allowed_agents = {
            host.get("compute_agent_id" if kind == "compute_agent" else "network_agent_id")
            for host in document["eligible_hosts"]
        }
        require(agent_id in allowed_agents, "agent restart observation is not bound to an eligible agent")
        epochs = artifact.get("epochs")
        require(isinstance(epochs, dict) and is_int(epochs.get("before")) and
                is_int(epochs.get("after")) and epochs["after"] > epochs["before"],
                "agent restart observation must prove a newer agent epoch")
    return artifact


def validate_gate_observations(
    gate: str, observations: dict[str, Any], initial_ids: set[str], final_ids: set[str], expected_hosts: int,
    release: dict[str, Any], database_identity: str, root: pathlib.Path,
    document: dict[str, Any], tier: str,
) -> None:
    """Require the fact appropriate to each lifecycle gate, not a PASS label."""
    def fact(key: str, expected: Any = None) -> Any:
        require(key in observations, f"{gate} evidence is missing observations.{key}")
        value = observations[key]
        if expected is not None:
            require(value == expected, f"{gate} observations.{key} must equal {expected!r}")
        return value

    def nonempty(key: str) -> Any:
        value = fact(key)
        require(isinstance(value, (str, int, list, dict)) and not isinstance(value, bool) and bool(value),
                f"{gate} observations.{key} must be non-empty")
        return value

    def bound_artifact(key: str, schema: str) -> dict[str, Any]:
        return validate_bound_observation(root, observations.get(key), f"{gate}.{key}", schema, document, tier)

    if gate == "release_install":
        expected = {
            "release_tag": release["tag"], "installed_version": release["version"],
            "archive_sha256": release["archive_sha256"], "install_sha256": release["install_sha256"],
            "manifest_sha256": release["manifest_sha256"], "sbom_sha256": release["sbom_sha256"],
            "provenance_sha256": release["provenance_sha256"],
            "signature_bundle_sha256": release["signature_bundle_sha256"],
        }
        for key, value in expected.items():
            fact(key, value)
        fact("archive_round_trip_verified", True)
        fact("signature_verified", True)
    elif gate == "control_plane_init":
        nonempty("controller_identity")
        fact("api_ready", True)
        fact("postgres_backend", True)
    elif gate == "authenticated_joins":
        fact("authenticated_join_count", expected_hosts)
        require(set(string_list(nonempty("eligible_host_ids"), f"{gate}.observations.eligible_host_ids")) == initial_ids,
                "authenticated_joins host identities differ from the eligible host set")
    elif gate == "canonical_topology":
        fact("eligible_host_count", expected_hosts)
        require(set(string_list(nonempty("eligible_host_ids"), f"{gate}.observations.eligible_host_ids")) == initial_ids,
                "canonical_topology identities differ from the eligible host set")
        fact("duplicate_host_identities", 0)
    elif gate == "placement":
        placed = string_list(nonempty("placed_host_ids"), f"{gate}.observations.placed_host_ids")
        require(len(set(placed)) >= 2,
                "placement must prove workloads on at least two distinct hosts")
        require(set(placed) <= initial_ids, "placement references a non-eligible host")
        fact("real_workloads_created", True)
    elif gate == "capacity_change":
        before, after = fact("capacity_before"), fact("capacity_after")
        require(is_int(before) and is_int(after) and after > before,
                "capacity_change must prove capacity increased")
    elif gate == "drain":
        drained = nonempty("drained_host_id")
        require(drained in initial_ids, "drain target must be one of the initially eligible hosts")
        fact("drain_state", "draining")
    elif gate == "placement_rejection":
        drained = nonempty("drained_host_id")
        require(drained in initial_ids, "placement rejection target must be one of the initially eligible hosts")
        fact("placement_on_drained_host_rejected", True)
    elif gate == "resident_blocker":
        fact("resident_workload_blocker_observed", True)
        count = fact("blocker_count")
        require(is_int(count) and count > 0, "resident blocker count must be positive")
    elif gate == "remove":
        nonempty("remove_operation_id")
        fact("remove_succeeded", True)
        removed = nonempty("removed_host_id")
        require(removed in initial_ids, "removed host must belong to the initially eligible set")
    elif gate == "replacement":
        nonempty("replacement_host_id")
        fact("replacement_joined", True)
        fact("eligible_host_count_after_replacement", expected_hosts)
        replacement_id = fact("replacement_host_id")
        before_ids = string_list(nonempty("eligible_host_ids_before_replacement"),
                                 f"{gate}.observations.eligible_host_ids_before_replacement")
        resulting_ids = string_list(nonempty("eligible_host_ids_after_replacement"),
                                    f"{gate}.observations.eligible_host_ids_after_replacement")
        require(len(before_ids) == expected_hosts and len(set(before_ids)) == expected_hosts,
                "replacement pre-state must contain exactly the expected unique hosts")
        require(replacement_id not in before_ids, "replacement must have a new stable host identity")
        require(len(resulting_ids) == expected_hosts and len(set(resulting_ids)) == expected_hosts,
                "replacement eligible host set must contain exactly the expected unique hosts")
        require(replacement_id in resulting_ids and set(resulting_ids) == final_ids,
                "replacement host set differs from the final observed eligible hosts")
    elif gate in ("control_plane_restart", "postgres_restart"):
        for key in ("process_id_before", "process_id_after"):
            value = fact(key)
            require(is_int(value) and value > 0, f"{gate} {key} must be a positive process ID")
        for key in ("start_time_before", "start_time_after"):
            value = fact(key)
            require(isinstance(value, str) and value, f"{gate} {key} must be a non-empty process start identity")
        require(fact("process_id_before") != fact("process_id_after"), f"{gate} must prove a new process ID")
        require(fact("start_time_before") != fact("start_time_after"), f"{gate} must prove a changed process start time")
        fact("recovered_ready", True)
        if gate == "control_plane_restart":
            before, after = fact("controller_epoch_before"), fact("controller_epoch_after")
            require(is_int(before) and is_int(after) and after > before,
                    "control_plane_restart must prove a newer controller epoch")
        else:
            fact("restart_kind", "postgres_process")
            fact("database_identity", database_identity)
            for key in ("process_executable_before", "process_executable_after"):
                executable = nonempty(key)
                executable_path = pathlib.PurePosixPath(executable)
                require(executable_path.is_absolute() and executable_path.name == "postgres",
                        f"{gate} {key} must identify the PostgreSQL server process")
            data_directory_before = nonempty("data_directory_identity_before")
            data_directory_after = nonempty("data_directory_identity_after")
            require(data_directory_before == data_directory_after,
                    "postgres restart must retain the same isolated data directory identity")
            server_version_before = nonempty("server_version_before")
            server_version_after = nonempty("server_version_after")
            require(server_version_before == server_version_after,
                    "postgres restart must retain the same server version")
        process_kind = "controller" if gate == "control_plane_restart" else "postgres"
        process_artifact = validate_process_observation(
            bound_artifact("process_observation_evidence", "o3k.pp5-process-restart-observation.v1"),
            process_kind, document)
        before, after = process_artifact["before"], process_artifact["after"]
        require(fact("process_id_before") == before["pid"] and fact("process_id_after") == after["pid"],
                f"{gate} process IDs differ from the read-only process observation")
        require(fact("start_time_before") == before["start_time"] and
                fact("start_time_after") == after["start_time"],
                f"{gate} process start identities differ from the read-only process observation")
        if gate == "control_plane_restart":
            require(process_artifact["epochs"] == {
                "before": fact("controller_epoch_before"), "after": fact("controller_epoch_after")},
                "controller epochs differ from the read-only process observation")
        else:
            require(process_artifact.get("database_identity") == database_identity,
                    "PostgreSQL process observation does not match the campaign database")
            require(process_artifact.get("data_directory_identity") == fact("data_directory_identity_before") ==
                    fact("data_directory_identity_after"),
                    "PostgreSQL data directory differs from the read-only process observation")
            require(process_artifact.get("server_version") == fact("server_version_before") ==
                    fact("server_version_after"),
                    "PostgreSQL server version differs from the read-only process observation")
    elif gate == "identity_reconstruction":
        fact("stable_host_ids_preserved", True)
        fact("duplicate_identities", 0)
    elif gate == "projection_convergence":
        fact("consecutive_consistent_observations", 2)
        fact("canonical_and_api_projections_equal", True)
    elif gate == "fabric_networking":
        participants = string_list(nonempty("canonical_participant_ids"),
                                   f"{gate}.observations.canonical_participant_ids")
        require(set(participants) == final_ids,
                "Fabric participants must equal the eligible host set")
        fact("dhcp_dora_pass", True)
        fact("canonical_arp_pass", True)
        count = fact("icmp_success_count")
        require(is_int(count) and count >= 6, "Fabric traffic must prove at least six ICMP successes")
        fact("tcp_pass", True)
        fact("udp_pass", True)
        eligible_host_rows = {host["stable_host_id"]: host for host in document["eligible_hosts"]}
        validate_network_observations(bound_artifact("packet_probe_evidence", "o3k.pp5-network-observation.v1"),
                                      eligible_host_rows, count)
    elif gate == "tenant_isolation":
        fact("cross_tenant_access_denied", True)
        fact("forged_source_mac_denied", True)
        fact("forged_source_ip_denied", True)
        fact("foreign_fdb_unchanged", True)
        validate_isolation_observations(bound_artifact("isolation_probe_evidence", "o3k.pp5-isolation-observation.v1"))
    elif gate == "mtu":
        tested, expected = fact("tested_mtu_bytes"), fact("expected_mtu_bytes")
        require(is_int(tested) and is_int(expected) and tested == expected and tested >= 1280,
                "MTU test must match the configured MTU")
        fact("boundary_packet_passed", True)
        fact("oversize_packet_rejected", True)
        validate_mtu_observations(bound_artifact("mtu_probe_evidence", "o3k.pp5-mtu-observation.v1"),
                                  tested, expected)
    elif gate == "endpoint_lifecycle":
        nonempty("endpoint_id")
        fact("created", True)
        fact("attached", True)
        fact("recreated", True)
        fact("released_after_delete", True)
        fact("endpoint_count_after_teardown", 0)
    elif gate == "agent_restart":
        agent_id = nonempty("agent_id")
        process_kind = fact("process_kind")
        require(process_kind in {"compute_agent", "network_agent"},
                "agent_restart process_kind must identify a compute or network agent")
        allowed_agents = {
            host["compute_agent_id" if process_kind == "compute_agent" else "network_agent_id"]
            for host in document["eligible_hosts"]
        }
        require(agent_id in allowed_agents, "agent_restart identity is not an eligible agent")
        for key in ("process_id_before", "process_id_after"):
            value = fact(key)
            require(is_int(value) and value > 0, f"{gate} {key} must be a positive process ID")
        for key in ("start_time_before", "start_time_after"):
            value = fact(key)
            require(isinstance(value, str) and value, f"{gate} {key} must be a non-empty process start identity")
        require(fact("process_id_before") != fact("process_id_after"),
                "agent_restart must prove a new process ID")
        require(fact("start_time_before") != fact("start_time_after"),
                "agent_restart must prove a changed process start time")
        before, after = fact("agent_epoch_before"), fact("agent_epoch_after")
        require(is_int(before) and is_int(after) and after > before,
                "agent_restart must prove a newer registered epoch")
        fact("recovered_ready", True)
        process_artifact = validate_process_observation(
            bound_artifact("process_observation_evidence", "o3k.pp5-process-restart-observation.v1"),
            process_kind, document)
        require(process_artifact.get("agent_id") == agent_id and process_artifact["epochs"] == {
            "before": before, "after": after},
            "agent restart identity or epochs differ from the read-only process observation")
    elif gate == "durable_work_recovery":
        fact("interruption_injected", True)
        fact("work_persisted_before_restart", True)
        fact("work_converged_after_restart", True)
        fact("unresolved_work_after_recovery", 0)
    elif gate == "quota_allocation":
        fact("quota_accounting_consistent", True)
        fact("allocation_accounting_consistent", True)
        fact("quota_leak_count_after_teardown", 0)
        fact("allocation_leak_count_after_teardown", 0)
    elif gate in ("supported_teardown", "owned_leaks_zero"):
        fact("supported_api_teardown", True)
        fact("owned_resources_remaining", 0)
    elif gate == "foreign_state_unchanged":
        before, after = nonempty("foreign_fingerprint_before"), nonempty("foreign_fingerprint_after")
        require(before == after, "foreign-state fingerprints differ")
        fact("foreign_mutations", 0)


def validate_lifecycle_observation_capture(
    artifact: dict[str, Any], gate: str, observations: dict[str, Any],
    document: dict[str, Any], tier: str, root: pathlib.Path,
) -> None:
    """Require a separate retained capture for every lifecycle gate."""
    name = f"lifecycle.{gate}.observation_capture_evidence"
    capture = validate_bound_observation(
        root, artifact.get("observation_capture_evidence"), name,
        "o3k.pp5-lifecycle-observation.v1", document, tier)
    require(capture.get("gate") == gate, f"{name} gate identity mismatch")
    require(capture.get("resource_class") == GATE_RESOURCE_CLASSES.get(gate),
            f"{name} resource_class is invalid")
    require(capture.get("observer_type") in GATE_OBSERVER_TYPES.get(gate, set()),
            f"{name} observer_type is invalid")
    require(capture.get("command_class") == f"pp5_gate_{gate}", f"{name} command_class is invalid")
    validate_capture(capture, name)
    try:
        captured_observations = json.loads(capture["raw_output"])
    except json.JSONDecodeError as error:
        raise ContractError(f"{name}.raw_output must be JSON observations") from error
    require(isinstance(captured_observations, dict), f"{name}.raw_output must be an object")
    summary = {key: value for key, value in observations.items() if not key.endswith("_evidence")}
    require(strict_json_equal(capture.get("observed"), captured_observations, name) and
            strict_json_equal(captured_observations, summary, name),
            f"{name} does not match the lifecycle summary observations")


def validate_lifecycle(document: dict[str, Any], root: pathlib.Path, expected_hosts: int) -> None:
    lifecycle = object_at(document, "lifecycle")
    missing = [field for field in LIFECYCLE_GATES
               if not isinstance(lifecycle.get(field), dict) or lifecycle[field].get("status") != "passed"]
    require(not missing, "lifecycle gate(s) missing or not passed: " + ", ".join(missing))
    gate_observations: dict[str, dict[str, Any]] = {}
    initial_ids = host_ids(document, "initial_eligible_hosts", expected_hosts)
    validate_hosts({"eligible_hosts": document["initial_eligible_hosts"]}, expected_hosts)
    final_ids = {host["stable_host_id"] for host in document["eligible_hosts"]}
    for gate in LIFECYCLE_GATES:
        artifact = load_json_artifact(root, lifecycle[gate].get("evidence"), f"lifecycle.{gate}")
        require(artifact.get("schema") == "o3k.pp5-scale-soak-gate.v1", f"lifecycle.{gate} evidence schema is invalid")
        require(artifact.get("gate") == gate and artifact.get("status") == "passed",
                f"lifecycle.{gate} evidence does not prove the named gate passed")
        observations = artifact.get("observations")
        require(isinstance(observations, dict) and bool(observations),
                f"lifecycle.{gate} evidence has no observations")
        require(artifact.get("run_id") == document["run"]["id"],
                f"lifecycle.{gate} evidence run identity mismatch")
        require(artifact.get("source_sha") == document["source"]["sha"] and
                artifact.get("source_tree") == document["source"]["tree"],
                f"lifecycle.{gate} evidence source identity mismatch")
        require(artifact.get("harness_sha") == document["harness"]["sha"] and
                artifact.get("harness_tree") == document["harness"]["tree"],
                f"lifecycle.{gate} evidence harness identity mismatch")
        require(artifact.get("tier") == document["tier"], f"lifecycle.{gate} evidence tier mismatch")
        validate_lifecycle_observation_capture(
            artifact, gate, observations, document, document["tier"], root)
        validate_gate_observations(gate, observations, initial_ids, final_ids, expected_hosts,
                                   document["release"], document["database"]["identity"],
                                   root, document, document["tier"])
        gate_observations[gate] = observations
    removed_id = gate_observations["remove"].get("removed_host_id")
    require(gate_observations["drain"].get("drained_host_id") == removed_id,
            "drain and remove evidence must target the same host")
    require(gate_observations["placement_rejection"].get("drained_host_id") == removed_id,
            "placement rejection and remove evidence must target the same host")
    replacement = gate_observations["replacement"]
    replacement_id = replacement.get("replacement_host_id")
    resulting = replacement.get("eligible_host_ids_after_replacement")
    original_ids = set(replacement.get("eligible_host_ids_before_replacement", []))
    require(original_ids == initial_ids, "replacement pre-state differs from authenticated initial hosts")
    require(removed_id in original_ids, "remove evidence target must belong to the pre-replacement eligible set")
    require(set(resulting) == (original_ids - {removed_id}) | {replacement_id},
            "replacement evidence must preserve all surviving identities and replace only the removed host")
    require(final_ids == set(resulting),
            "final eligible host identities differ from the replacement observation")
    distribution = lifecycle.get("placement_distribution")
    require(isinstance(distribution, dict), "lifecycle.placement_distribution is required")
    placed_hosts = distribution.get("eligible_host_ids")
    placed_hosts = string_list(placed_hosts, "lifecycle.placement_distribution.eligible_host_ids")
    require(len(placed_hosts) >= 2, "real workloads must be distributed across at least two eligible hosts")
    require(len(set(placed_hosts)) >= 2, "real workloads must occupy at least two distinct eligible hosts")
    require(all(host_id in final_ids for host_id in placed_hosts),
            "placement distribution references a non-eligible host")


def read_jsonl(root: pathlib.Path, reference: Any, name: str) -> list[dict[str, Any]]:
    require(isinstance(reference, dict), f"{name} artifact reference is required")
    path = artifact_path(root, reference.get("path"), reference.get("sha256"), name)
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as artifact:
            for line_number, line in enumerate(artifact, 1):
                if not line.strip():
                    continue
                item = json.loads(line)
                require(isinstance(item, dict), f"{name} line {line_number} must be an object")
                reject_secrets(item, f"{name}[{line_number}]")
                rows.append(item)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{name} artifact is not valid JSONL") from error
    require(bool(rows), f"{name} artifact has no samples")
    return rows


def validate_soak_sample_capture(
    sample: dict[str, Any], index: int, root: pathlib.Path,
    document: dict[str, Any], tier: str,
) -> None:
    name = f"soak.samples[{index}].observation_evidence"
    capture = validate_bound_observation(
        root, sample.get("observation_evidence"), name,
        "o3k.pp5-soak-sample-observation.v1", document, tier)
    require(capture.get("resource_class") == "soak_runtime_sample",
            f"{name} resource_class is invalid")
    observers = capture.get("observer_types")
    require(isinstance(observers, list) and all(isinstance(observer, str) for observer in observers) and
            len(observers) == len(set(observers)) and set(observers) == SOAK_SAMPLE_OBSERVER_TYPES,
            f"{name} observer_types must cover the required independent sources")
    require(capture.get("command_class") == "pp5_soak_sample",
            f"{name} command_class is invalid")
    require(is_int(capture.get("sample_index")) and capture.get("sample_index") == index,
            f"{name} sample_index differs from the JSONL record")
    capture_elapsed = finite_number(capture.get("elapsed_seconds"), f"{name}.elapsed_seconds")
    sample_elapsed = finite_number(sample.get("elapsed_seconds"), f"{name}.sample.elapsed_seconds")
    require(capture_elapsed == sample_elapsed and
            capture.get("captured_at") == sample.get("timestamp"),
            f"{name} timing differs from the JSONL record")
    validate_capture(capture, name)
    try:
        observed = json.loads(capture["raw_output"])
    except json.JSONDecodeError as error:
        raise ContractError(f"{name}.raw_output must be JSON observations") from error
    summary = {key: value for key, value in sample.items() if key != "observation_evidence"}
    require(strict_json_equal(capture.get("observed"), observed, name) and
            strict_json_equal(observed, summary, name),
            f"{name} does not match the soak sample")


def check_sustained_growth(samples: list[dict[str, Any]], key: str, absolute: int, fraction: float) -> dict[str, Any]:
    values = [sample.get(key) for sample in samples]
    require(all(is_int(value) and value >= 0 for value in values), f"resource sample field {key} must be non-negative integers")
    if len(values) < 10:
        raise ContractError("at least ten samples are required for resource trend checks")
    # Five equal chronological buckets distinguish a continuing rise from a
    # one-time allocation that later plateaus. A growth finding needs both a
    # material first-to-last bucket increase and positive movement in at least
    # three of the four bucket transitions.
    buckets: list[list[int]] = [[] for _ in range(5)]
    for index, value in enumerate(values):
        buckets[min(4, index * 5 // len(values))].append(value)
    medians = [statistics.median(bucket) for bucket in buckets]
    baseline = medians[0]
    threshold = max(absolute, math.ceil(baseline * fraction))
    positive_transitions = sum(right > left for left, right in zip(medians, medians[1:]))
    net_growth = medians[-1] - baseline
    sustained = net_growth >= threshold and positive_transitions >= 3
    require(not sustained, f"sustained resource growth {key} exceeded the predeclared threshold")
    return {
        "algorithm": "pp5-five-bucket-sustained-rise-v1",
        "bucket_medians": medians,
        "baseline_median_first_bucket": baseline,
        "final_median_last_bucket": medians[-1],
        "net_growth": net_growth,
        "threshold": threshold,
        "positive_bucket_transitions": positive_transitions,
        "sustained_growth": sustained,
        "growth_exceeded": sustained,
    }


def validate_soak(
    document: dict[str, Any],
    root: pathlib.Path,
    tier: str,
    baseline_root: pathlib.Path | None = None,
) -> None:
    scale, minimum = SOAKS[tier]
    soak = object_at(document, "soak")
    require(soak.get("scale") == scale, f"{tier} scale must be {scale}")
    require(soak.get("required_duration_seconds") == minimum, f"{tier} required duration must be {minimum} seconds")
    elapsed = finite_number(soak.get("monotonic_elapsed_seconds"), "soak.monotonic_elapsed_seconds")
    require(elapsed >= minimum, f"{tier} actual monotonic duration must be at least {minimum} seconds")
    try:
        soak_started = dt.datetime.fromisoformat(soak["started_at"].replace("Z", "+00:00"))
        soak_finished = dt.datetime.fromisoformat(soak["finished_at"].replace("Z", "+00:00"))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ContractError("soak.started_at and finished_at must be ISO-8601 timestamps") from error
    require(soak_started.tzinfo is not None and soak_finished.tzinfo is not None,
            "soak timestamps must include a timezone")
    require(soak_finished >= soak_started and
            abs((soak_finished - soak_started).total_seconds() - elapsed) <= max(30, elapsed * 0.01),
            "soak wall-clock interval does not corroborate monotonic duration")
    campaign_elapsed = finite_number(document["timestamps"].get("monotonic_elapsed_seconds"),
                                     "timestamps.monotonic_elapsed_seconds")
    require(campaign_elapsed >= elapsed, "campaign duration is shorter than the measured soak duration")
    samples = read_jsonl(root, soak.get("samples"), "soak.samples")
    eligible_hosts = document["eligible_hosts"]
    expected_agent_hosts = {
        host["stable_host_id"]: {
            "compute_agent": host["compute_agent_id"],
            "network_agent": host["network_agent_id"],
        }
        for host in eligible_hosts
    }
    agent_series: dict[str, dict[str, dict[str, list[int]]]] = {
        role: {host_id: {"rss_bytes": [], "fd_count": []} for host_id in expected_agent_hosts}
        for role in ("compute_agent", "network_agent")
    }
    previous = -1.0
    previous_counters: dict[str, int] = {}
    for index, sample in enumerate(samples):
        validate_soak_sample_capture(sample, index, root, document, tier)
        for field in SOAK_SAMPLE_FIELDS:
            value = sample.get(field)
            if field == "elapsed_seconds":
                finite_number(value, f"samples[{index}].elapsed_seconds")
            else:
                require(is_int(value) and value >= 0, f"samples[{index}].{field} must be a non-negative integer")
        sample_timestamp = sample.get("timestamp")
        try:
            parsed_sample_timestamp = dt.datetime.fromisoformat(sample_timestamp.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as error:
            raise ContractError(f"samples[{index}].timestamp must be ISO-8601") from error
        require(parsed_sample_timestamp.tzinfo is not None,
                f"samples[{index}].timestamp must include a timezone")
        expected_sample_timestamp = soak_started + dt.timedelta(seconds=float(sample["elapsed_seconds"]))
        require(abs((parsed_sample_timestamp - expected_sample_timestamp).total_seconds()) <= 30,
                f"samples[{index}].timestamp does not match its monotonic offset")
        for role in ("compute_agent", "network_agent"):
            agent_rows = sample.get(f"{role}s")
            require(isinstance(agent_rows, list) and len(agent_rows) == len(expected_agent_hosts),
                    f"samples[{index}].{role}s must cover every eligible host")
            seen_hosts: set[str] = set()
            for agent_index, agent in enumerate(agent_rows):
                require(isinstance(agent, dict),
                        f"samples[{index}].{role}s[{agent_index}] must be an object")
                host_id = agent.get("stable_host_id")
                require(isinstance(host_id, str) and host_id in expected_agent_hosts and host_id not in seen_hosts,
                        f"samples[{index}].{role}s host identities must exactly cover eligible hosts")
                seen_hosts.add(host_id)
                require(agent.get("agent_id") == expected_agent_hosts[host_id][role],
                        f"samples[{index}].{role}s agent identity differs from eligible host evidence")
                require(is_int(agent.get("pid")) and agent["pid"] > 0,
                        f"samples[{index}].{role}s[{agent_index}].pid must be positive")
                require(isinstance(agent.get("epoch"), str) and agent["epoch"],
                        f"samples[{index}].{role}s[{agent_index}].epoch is required")
                for field in ("rss_bytes", "fd_count"):
                    require(is_int(agent.get(field)) and agent[field] >= 0,
                            f"samples[{index}].{role}s[{agent_index}].{field} must be non-negative")
                    agent_series[role][host_id][field].append(agent[field])
            require(seen_hosts == set(expected_agent_hosts),
                    f"samples[{index}].{role}s host identities differ from eligible hosts")
        current = float(sample["elapsed_seconds"])
        require(current > previous, "soak sample elapsed_seconds must increase strictly")
        require(current <= elapsed, "soak sample exceeds measured soak duration")
        if previous >= 0:
            require(current - previous <= 600, "soak samples have a gap greater than ten minutes")
        require(sample["eligible_hosts"] == SCALE_HOSTS[scale], "soak sample eligible host count changed")
        require(sample["operation_failures"] == 0, "soak sample recorded a failed lifecycle operation")
        require(sample["operations_in_flight"] == 0,
                "soak samples must be captured between lifecycle operations")
        require(sample["orphan_endpoints"] == 0, "soak sample recorded an orphan endpoint")
        require(sample["create_successes"] <= sample["create_attempts"], "create successes exceed attempts")
        require(sample["delete_successes"] <= sample["delete_attempts"], "delete successes exceed attempts")
        require(sample["delete_attempts"] <= sample["create_successes"],
                "delete attempts exceed the number of successfully created workloads")
        for field in ("create_attempts", "create_successes", "delete_attempts", "delete_successes", "retries"):
            current_value = sample[field]
            if field in previous_counters:
                require(current_value >= previous_counters[field], f"soak sample counter {field} moved backwards")
            previous_counters[field] = current_value
        previous = current
    require(samples[-1]["create_attempts"] > 0 and samples[-1]["delete_attempts"] > 0,
            "soak samples do not show lifecycle churn")
    require(samples[0]["elapsed_seconds"] <= 600, "first soak sample is more than ten minutes after start")
    require(elapsed - samples[-1]["elapsed_seconds"] <= 600,
            "final soak sample is more than ten minutes before soak finish")
    final = samples[-1]
    require(final.get("phase") == "post_cleanup", "final soak sample must be captured after supported cleanup")
    for field in ("server_count", "quota_usage", "allocation_count", "owned_endpoints",
                  "durable_work_pending", "durable_work_applying", "durable_work_unknown",
                  "durable_work_retryable", "oldest_work_age_seconds"):
        require(final[field] == 0, f"final soak sample {field} must be zero after supported cleanup")
    cleanup = validate_bound_observation(
        root, soak.get("cleanup_evidence"), "soak.cleanup_evidence",
        "o3k.pp5-soak-cleanup-observation.v1", document, tier)
    require(cleanup.get("status") == "passed" and cleanup.get("supported_api_teardown") is True,
            "soak cleanup artifact must prove successful supported API teardown")
    cleanup_elapsed = finite_number(cleanup.get("elapsed_seconds"), "soak cleanup elapsed_seconds")
    require(elapsed <= cleanup_elapsed <= campaign_elapsed,
            "soak cleanup must complete after the full soak and before campaign finish")
    require(abs(float(final["elapsed_seconds"]) - cleanup_elapsed) <= 30,
            "post-cleanup sample does not correspond to the cleanup observation")
    cleanup_counts = object_at(cleanup, "remaining_resources")
    for field in ("servers", "ports", "domains", "quota_usage", "allocations", "owned_endpoints",
                  "orphan_endpoints", "durable_work_pending", "durable_work_applying",
                  "durable_work_unknown", "durable_work_retryable"):
        require(is_int(cleanup_counts.get(field)) and cleanup_counts[field] == 0,
                f"soak cleanup {field} must be zero")
    for field in ("foreign_fingerprint_before", "foreign_fingerprint_after"):
        require(isinstance(cleanup.get(field), str) and cleanup[field],
                f"soak cleanup {field} is required")
    require(cleanup["foreign_fingerprint_before"] == cleanup["foreign_fingerprint_after"],
            "foreign state changed during soak cleanup")
    foreign_gate = load_json_artifact(
        root, document["lifecycle"]["foreign_state_unchanged"].get("evidence"),
        "lifecycle.foreign_state_unchanged")
    foreign_observations = object_at(foreign_gate, "observations")
    require(cleanup["foreign_fingerprint_before"] == foreign_observations.get("foreign_fingerprint_before") and
            cleanup["foreign_fingerprint_after"] == foreign_observations.get("foreign_fingerprint_after"),
            "soak cleanup foreign-state fingerprints differ from the lifecycle baseline")
    analysis = object_at(document, "resource_analysis")
    require(analysis.get("algorithm") == "pp5-five-bucket-sustained-rise-v1",
            "resource growth algorithm is missing or unrecognized")
    require(analysis.get("thresholds") == RESOURCE_LIMITS,
            "resource analysis thresholds differ from the predeclared PP.5 thresholds")
    computed = {
        key: check_sustained_growth(samples, key, limits["absolute"], limits["fraction"])
        for key, limits in RESOURCE_LIMITS.items() if key not in ("agent_rss_bytes", "agent_fd_count")
    }
    for metric, field in (("agent_rss_bytes", "rss_bytes"), ("agent_fd_count", "fd_count")):
        computed[metric] = {
            role: {
                host_id: check_sustained_growth(
                    [{metric: value} for value in values[field]], metric,
                    RESOURCE_LIMITS[metric]["absolute"], RESOURCE_LIMITS[metric]["fraction"],
                )
                for host_id, values in host_series.items()
            }
            for role, host_series in agent_series.items()
        }
    require(analysis.get("results") == computed,
            "reported resource analysis does not match the sampled resource series")
    require(analysis.get("decision") == "bounded", "resource growth analysis did not conclude bounded")

    def growth_is_bounded(result: Any) -> bool:
        if isinstance(result, dict) and "growth_exceeded" in result:
            return result["growth_exceeded"] is False
        return isinstance(result, dict) and all(growth_is_bounded(value) for value in result.values())

    require(growth_is_bounded(computed),
            "resource growth analysis contains an exceeded threshold")
    churn = object_at(document, "churn")
    for field in ("create_attempts", "create_successes", "delete_attempts", "delete_successes", "completed_cycles", "retries", "failures"):
        require(is_int(churn.get(field)) and churn[field] >= 0, f"churn.{field} must be a non-negative integer")
    require(churn["create_attempts"] > 0 and churn["delete_attempts"] > 0, "soak must perform create and delete attempts")
    require(churn["create_successes"] > 0 and churn["delete_successes"] > 0 and churn["completed_cycles"] > 0,
            "soak must complete supported create/ACTIVE/delete/cleanup cycles")
    require(churn["create_successes"] >= churn["completed_cycles"] and churn["delete_successes"] >= churn["completed_cycles"],
            "completed lifecycle count exceeds successful operation counts")
    cycles = churn.get("successful_cycle_elapsed_seconds")
    require(isinstance(cycles, list) and len(cycles) == churn["completed_cycles"], "successful cycle timestamps must match completed_cycles")
    buckets = set()
    previous_cycle = -1.0
    for value in cycles:
        require(isinstance(value, (int, float)) and not isinstance(value, bool) and
                math.isfinite(value) and 0 <= value <= elapsed,
                "successful cycle timestamp is outside the soak")
        require(value > previous_cycle, "successful lifecycle cycle timestamps must increase strictly")
        if previous_cycle >= 0:
            require(value - previous_cycle <= 1800,
                    "successful lifecycle churn has a gap greater than thirty minutes")
        previous_cycle = float(value)
        buckets.add(min(9, int(value * 10 / elapsed)))
    require(buckets == set(range(10)), "successful lifecycle churn must cover every tenth of the soak")
    require(cycles[0] <= 1800 and elapsed - cycles[-1] <= 1800,
            "successful lifecycle churn must begin and end within thirty minutes of soak boundaries")
    for sample in samples:
        completed_by_sample = sum(value <= sample["elapsed_seconds"] for value in cycles)
        require(sample["create_successes"] >= completed_by_sample and
                sample["delete_successes"] >= completed_by_sample,
                "soak samples do not corroborate completed lifecycle cycle timestamps")
    require(churn["failures"] == 0, "soak lifecycle operations recorded failures")
    for field in ("create_attempts", "create_successes", "delete_attempts", "delete_successes", "retries"):
        require(churn[field] == samples[-1][field], f"churn.{field} differs from the final sample")
    events = soak.get("fault_events")
    require(isinstance(events, list), "soak.fault_events must be a list")
    required = Counter({"control_plane_restart": 2, "postgres_process_restart": 1, "building_block_drain_recovery": 1}) if tier == "K-min" else Counter({"control_plane_restart": 1, "postgres_process_restart": 1, "building_block_drain_recovery": 1})
    observed = Counter()
    offsets: list[float] = []
    event_ids: set[str] = set()
    for index, event in enumerate(events):
        require(isinstance(event, dict), f"soak.fault_events[{index}] must be an object")
        kind = event.get("kind")
        require(isinstance(kind, str), f"soak.fault_events[{index}].kind is required")
        require(kind in {"control_plane_restart", "postgres_process_restart",
                         "building_block_drain_recovery", "compute_agent_restart"},
                f"soak.fault_events[{index}] uses an unsupported failure scenario")
        require(event.get("status") == "passed", f"soak.fault_events[{index}] did not pass")
        event_id = event.get("event_id")
        require(isinstance(event_id, str) and event_id and event_id not in event_ids,
                f"soak.fault_events[{index}].event_id must be unique")
        if isinstance(event_id, str):
            event_ids.add(event_id)
        offset = event.get("elapsed_seconds")
        offset = finite_number(offset, f"soak.fault_events[{index}].elapsed_seconds")
        require(offset <= elapsed, f"soak.fault_events[{index}].elapsed_seconds exceeds measured duration")
        offsets.append(offset)
        observed[kind] += 1
        if kind == "postgres_process_restart":
            before, after = event.get("postgres_pid_before"), event.get("postgres_pid_after")
            start_before, start_after = event.get("postgres_start_time_before"), event.get("postgres_start_time_after")
            require(is_int(before) and before > 0 and is_int(after) and after > 0 and before != after,
                    "PostgreSQL process restart must prove distinct positive PIDs")
            require(isinstance(start_before, str) and start_before and isinstance(start_after, str)
                    and start_after and start_before != start_after,
                    "PostgreSQL process restart must prove a changed process start time")
            require(event.get("database_identity") == document["database"]["identity"], "PostgreSQL restart database identity mismatch")
            for field in ("postgres_executable_before", "postgres_executable_after"):
                executable = event.get(field)
                executable_path = pathlib.PurePosixPath(executable) if isinstance(executable, str) else pathlib.PurePosixPath(".")
                require(isinstance(executable, str) and executable_path.is_absolute()
                        and executable_path.name == "postgres",
                        "PostgreSQL process restart must identify the PostgreSQL server executable")
            data_directory_before = event.get("data_directory_identity_before")
            data_directory_after = event.get("data_directory_identity_after")
            require(isinstance(data_directory_before, str) and data_directory_before and
                    isinstance(data_directory_after, str) and data_directory_before == data_directory_after,
                    "PostgreSQL process restart must retain the same isolated data directory identity")
            require(event.get("server_version_before") == document["database"]["server_version"] and
                    event.get("server_version_after") == document["database"]["server_version"],
                    "PostgreSQL process restart must retain the bound server version")
        elif kind == "control_plane_restart":
            before, after = event.get("controller_pid_before"), event.get("controller_pid_after")
            start_before, start_after = event.get("controller_start_time_before"), event.get("controller_start_time_after")
            epoch_before, epoch_after = event.get("controller_epoch_before"), event.get("controller_epoch_after")
            require(is_int(before) and before > 0 and is_int(after) and after > 0 and before != after,
                    "control-plane restart must prove distinct positive process PIDs")
            require(isinstance(start_before, str) and start_before and isinstance(start_after, str)
                    and start_after and start_before != start_after,
                    "control-plane restart must prove a changed process start time")
            require(is_int(epoch_before) and epoch_before > 0 and is_int(epoch_after) and epoch_after > epoch_before,
                    "control-plane restart must prove a newer controller epoch")
        elif kind == "building_block_drain_recovery":
            require(isinstance(event.get("block_id"), str) and event["block_id"], "drain recovery must identify its BuildingBlock")
            require(event.get("drain_observed") is True and event.get("resident_blocker_observed") is True,
                    "drain recovery must prove drain and resident blocker observations")
            require(event.get("recovery_state") == "ready", "drain recovery must end in Ready state")
        elif kind == "compute_agent_restart":
            require(isinstance(event.get("agent_id"), str) and event["agent_id"],
                    "agent restart must identify the restarted agent")
            before, after = event.get("agent_pid_before"), event.get("agent_pid_after")
            start_before, start_after = event.get("agent_start_time_before"), event.get("agent_start_time_after")
            epoch_before, epoch_after = event.get("agent_epoch_before"), event.get("agent_epoch_after")
            require(is_int(before) and before > 0 and is_int(after) and after > 0 and before != after,
                    "agent restart must prove distinct positive process IDs")
            require(isinstance(start_before, str) and start_before and isinstance(start_after, str)
                    and start_after and start_before != start_after,
                    "agent restart must prove a changed process start time")
            require(is_int(epoch_before) and epoch_before > 0 and is_int(epoch_after) and epoch_after > epoch_before,
                    "agent restart must prove a newer agent epoch")
            require(event.get("recovered_ready") is True, "agent restart must prove Ready recovery")
        event_ref = event.get("observation_evidence")
        if kind == "building_block_drain_recovery":
            observation = validate_bound_observation(
                root, event_ref, f"soak.fault_events[{index}].observation_evidence",
                "o3k.pp5-soak-drain-observation.v1", document, tier)
            require(observation.get("event_id") == event_id and
                    observation.get("elapsed_seconds") == offset and
                    observation.get("block_id") == event.get("block_id") and
                    observation.get("drain_observed") is True and
                    observation.get("resident_blocker_observed") is True and
                    observation.get("recovery_state") == "ready",
                    "drain recovery event differs from its bound observation")
            validate_capture(observation, f"soak.fault_events[{index}] drain observation")
        else:
            process_kind = {
                "control_plane_restart": "controller",
                "postgres_process_restart": "postgres",
                "compute_agent_restart": "compute_agent",
            }[kind]
            observation = validate_bound_observation(
                root, event_ref, f"soak.fault_events[{index}].observation_evidence",
                "o3k.pp5-process-restart-observation.v1", document, tier)
            validate_process_observation(observation, process_kind, document)
            require(observation.get("event_id") == event_id and
                    observation.get("elapsed_seconds") == offset,
                    "restart event identity or elapsed time differs from its bound observation")
            before, after = observation["before"], observation["after"]
            event_process_fields = {
                "control_plane_restart": ("controller_pid_before", "controller_pid_after",
                                          "controller_start_time_before", "controller_start_time_after"),
                "postgres_process_restart": ("postgres_pid_before", "postgres_pid_after",
                                             "postgres_start_time_before", "postgres_start_time_after"),
                "compute_agent_restart": ("agent_pid_before", "agent_pid_after",
                                          "agent_start_time_before", "agent_start_time_after"),
            }[kind]
            actuals = (before["pid"], after["pid"], before["start_time"], after["start_time"])
            require(tuple(event.get(field) for field in event_process_fields) == actuals,
                    "restart event process identity differs from its read-only observation")
            executable_fields = {
                "control_plane_restart": ("controller_executable_before", "controller_executable_after"),
                "postgres_process_restart": ("postgres_executable_before", "postgres_executable_after"),
                "compute_agent_restart": ("agent_executable_before", "agent_executable_after"),
            }[kind]
            require(tuple(event.get(field) for field in executable_fields) ==
                    (before["executable"], after["executable"]),
                    "restart event executable differs from its read-only observation")
            if kind == "control_plane_restart":
                require(observation["epochs"] == {
                    "before": event.get("controller_epoch_before"),
                    "after": event.get("controller_epoch_after")},
                    "controller restart epochs differ from the bound observation")
            elif kind == "postgres_process_restart":
                require(observation.get("database_identity") == event.get("database_identity") ==
                        document["database"]["identity"] and
                        observation.get("data_directory_identity") ==
                        event.get("data_directory_identity_before") == event.get("data_directory_identity_after") and
                        observation.get("server_version") == event.get("server_version_before") ==
                        event.get("server_version_after") == document["database"]["server_version"],
                        "PostgreSQL restart details differ from the bound observation")
            else:
                require(observation.get("agent_id") == event.get("agent_id") and
                        observation["epochs"] == {"before": event.get("agent_epoch_before"),
                                                  "after": event.get("agent_epoch_after")},
                        "agent restart details differ from the bound observation")
    require(all(observed[key] >= count for key, count in required.items()),
            "required soak restart/drain recovery events are missing")
    offsets.sort()
    require(all(elapsed * 0.1 <= offset <= elapsed * 0.9 for offset in offsets), "fault events must be distributed away from soak boundaries")
    separation = elapsed * (0.08 if tier == "K-min" else 0.15)
    require(all(right - left >= separation for left, right in zip(offsets, offsets[1:])), "fault events are clustered too closely")
    require(offsets[0] <= elapsed * 0.25 and offsets[-1] >= elapsed * 0.75,
            "fault events must span the soak rather than cluster in its middle")
    require(all(right - left <= elapsed * 0.5 for left, right in zip(offsets, offsets[1:])),
            "fault events have a gap greater than half the soak")
    sweeps = soak.get("orphan_repair_sweeps")
    require(isinstance(sweeps, list) and len(sweeps) >= 5, "orphan-repair sweep history evidence is insufficient")
    sweep_times: list[float] = []
    prior_history = -1
    for index, sweep in enumerate(sweeps):
        require(isinstance(sweep, dict) and is_int(sweep.get("deleted_server_history_size")) and sweep["deleted_server_history_size"] >= 0,
                f"orphan_repair_sweeps[{index}].deleted_server_history_size is invalid")
        finite_number(sweep.get("duration_ms"), f"orphan_repair_sweeps[{index}].duration_ms")
        sweep_elapsed = finite_number(sweep.get("elapsed_seconds"),
                                      f"orphan_repair_sweeps[{index}].elapsed_seconds")
        require(sweep_elapsed <= elapsed,
                f"orphan_repair_sweeps[{index}].elapsed_seconds exceeds measured duration")
        require(sweep["deleted_server_history_size"] >= prior_history,
                "orphan repair deleted-server history size must not move backwards")
        if sweep_times:
            require(sweep["elapsed_seconds"] > sweep_times[-1],
                    "orphan-repair sweep observations must increase strictly")
        prior_history = sweep["deleted_server_history_size"]
        sweep_times.append(sweep_elapsed)
    require(sweep_times[0] <= elapsed * 0.1 and sweep_times[-1] >= elapsed * 0.9,
            "orphan-repair sweep evidence must span the soak")

    baseline = object_at(soak, "scale_baseline")
    baseline_tier = "S10" if tier == "K-min" else "S20"
    require(baseline.get("tier") == baseline_tier,
            f"{tier} must bind its {baseline_tier} operational baseline")
    baseline_root = baseline_root or root
    baseline_run = load_json_artifact(baseline_root, baseline.get("evidence"), f"soak.scale_baseline.{baseline_tier}")
    baseline_path = artifact_path(baseline_root, baseline["evidence"]["path"], baseline["evidence"]["sha256"],
                                  "soak.scale_baseline.evidence")
    baseline_directory = baseline_path.parent.resolve(strict=True).relative_to(
        baseline_root.resolve(strict=True)
    ).as_posix() or "."
    baseline_database = object_at(baseline_run, "database")
    baseline_run_identity = object_at(baseline_run, "run")
    require(isinstance(baseline.get("run_id"), str), "scale baseline run_id is required")
    require(isinstance(baseline_database.get("identity"), str), "scale baseline database identity is required")
    require(baseline.get("database_identity") == baseline_database["identity"],
            "scale baseline database identity differs from its artifact")
    validate_run(
        baseline_run, baseline_tier, baseline_root,
        document["source"]["sha"], document["source"]["tree"],
        document["harness"]["sha"], document["harness"]["tree"], baseline_directory,
        document["release"]["tag"], document["release"]["archive_sha256"],
        baseline_database["identity"], baseline["run_id"],
        artifact_root=baseline_path.parent,
    )
    require(baseline["run_id"] == baseline_run_identity.get("id"),
            "soak scale baseline run identity differs from its artifact")
    baseline_snapshot = baseline_run.get("resource_baseline")
    require(isinstance(baseline_snapshot, dict), "scale baseline lacks operational resource measurements")
    snapshot_digest = hashlib.sha256(
        json.dumps(baseline_snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    require(baseline.get("resource_baseline_sha256") == snapshot_digest,
            "soak scale baseline resource measurements are not digest-bound")
    require(baseline_run.get("run", {}).get("id") != document.get("run", {}).get("id"),
            "soak and scale baseline must be separate run identities")


def validate_run(
    document: Any,
    tier: str,
    root: pathlib.Path,
    expected_source_sha: str | None = None,
    expected_source_tree: str | None = None,
    expected_harness_sha: str | None = None,
    expected_harness_tree: str | None = None,
    expected_run_directory: str | None = None,
    expected_release_tag: str | None = None,
    expected_archive_sha256: str | None = None,
    expected_database_identity: str | None = None,
    expected_run_id: str | None = None,
    artifact_root: pathlib.Path | None = None,
) -> None:
    require(isinstance(tier, str) and (tier in SCALE_HOSTS or tier in SOAKS),
            "tier must be S3, S10, S20, K-min, or K-full")
    require(isinstance(document, dict), "run artifact must be an object")
    validate_identity(document, tier, expected_source_sha, expected_source_tree, expected_harness_sha,
                      expected_harness_tree, expected_run_directory, expected_release_tag,
                      expected_archive_sha256, expected_database_identity, expected_run_id)
    expected_hosts = SCALE_HOSTS[tier] if tier in SCALE_HOSTS else SCALE_HOSTS[SOAKS[tier][0]]
    validate_hosts(document, expected_hosts)
    validate_resource_budget(document, expected_hosts)
    validate_resource_baseline(
        document,
        {host["stable_host_id"] for host in document["eligible_hosts"]},
        object_at(document, "database"),
    )
    local_evidence_root = artifact_root or root
    validate_lifecycle(document, local_evidence_root, expected_hosts)
    require(is_int(document.get("owned_leaks")) and document.get("owned_leaks") == 0,
            "owned_leaks must be integer zero")
    require(is_int(document.get("foreign_mutations")) and document.get("foreign_mutations") == 0,
            "foreign_mutations must be integer zero")
    if tier in SOAKS:
        validate_soak(document, local_evidence_root, tier, baseline_root=root)
    else:
        observed = document.get("observed_eligible_host_count")
        require(observed == expected_hosts, f"observed_eligible_host_count must be {expected_hosts}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=pathlib.Path)
    parser.add_argument("--tier", required=True, choices=(*SCALE_HOSTS, *SOAKS))
    parser.add_argument("--evidence-root", type=pathlib.Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-source-tree")
    parser.add_argument("--expected-harness-sha")
    parser.add_argument("--expected-harness-tree")
    parser.add_argument("--expected-release-tag")
    parser.add_argument("--expected-archive-sha256")
    parser.add_argument("--expected-database-identity")
    parser.add_argument("--expected-run-id")
    parser.add_argument("--expected-run-directory")
    args = parser.parse_args()
    try:
        document = json.loads(args.run.read_text(encoding="utf-8"))
        root = args.evidence_root or args.run.parent
        required_bindings = {
            "expected source SHA": args.expected_source_sha,
            "expected source tree": args.expected_source_tree,
            "expected harness SHA": args.expected_harness_sha,
            "expected harness tree": args.expected_harness_tree,
            "expected release tag": args.expected_release_tag,
            "expected archive SHA-256": args.expected_archive_sha256,
            "expected database identity": args.expected_database_identity,
            "expected run ID": args.expected_run_id,
            "expected evidence directory": args.expected_run_directory,
        }
        missing = [name for name, value in required_bindings.items() if not value]
        require(not missing, "protected validation requires explicit " + ", ".join(missing))
        validate_run(document, args.tier, root, args.expected_source_sha, args.expected_source_tree,
                     args.expected_harness_sha, args.expected_harness_tree, args.expected_run_directory,
                     args.expected_release_tag, args.expected_archive_sha256,
                     args.expected_database_identity, args.expected_run_id)
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError) as error:
        print(f"PP.5 {args.tier} evidence invalid: {error}", file=sys.stderr)
        return 1
    print(f"PP.5 {args.tier} evidence contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
