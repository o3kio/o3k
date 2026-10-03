#!/usr/bin/env python3
"""Classify PP.5 evidence phases without promoting a focused run to campaign pass."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


S5_PHASES = [
    "initial-scale-checkpoint",
    "pre-drain",
    "post-drain",
    "post-remove",
    "post-replacement",
    "post-reboot",
]
S5_COUNTS = [5, 5, 4, 4, 5, 5]
BOUNDARY_TIERS = {"s1-boundary": ("S1", 1), "s2-boundary": ("S2", 2)}


def read(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def s5_result(artifact_dir: Path, source_sha: str) -> dict:
    evidence = []
    counts = []
    reason = ""
    for phase, expected in zip(S5_PHASES, S5_COUNTS):
        path = artifact_dir / f"p15-7-scale-checkpoint-{phase}.json"
        value = read(path)
        if value is None:
            reason = f"missing_or_invalid_checkpoint:{phase}"
            break
        evidence.append(path.name)
        counts.append(value.get("eligible_ready_count"))
        if value.get("phase") != phase or value.get("eligible_ready_count") != expected:
            reason = f"s5_checkpoint_mismatch:{phase}"
            break
    status = "passed" if not reason and counts == S5_COUNTS else "failed"
    if status == "passed":
        reason = "s5_lifecycle_checkpoints_verified"
    return {
        "artifact_type": "o3k-pp5-phase-result",
        "schema_version": 1,
        "phase": "s5_scale",
        "status": status,
        "reason": reason,
        "tested_source_sha": source_sha or None,
        "evidence": evidence,
        "eligible_ready_counts": counts,
        "required_counts": S5_COUNTS,
        "redacted": True,
    }


def crash_result(artifact_dir: Path, source_sha: str) -> dict:
    path = artifact_dir / "p15-7-crash-injection-evidence.json"
    value = read(path)
    if value is None:
        return {
            "artifact_type": "o3k-pp5-phase-result",
            "schema_version": 1,
            "phase": "crash_recovery",
            "status": "not_run",
            "reason": "crash_evidence_not_published",
            "tested_source_sha": source_sha or None,
            "redacted": True,
        }
    status = "passed" if value.get("status") == "passed" and value.get("phase") == "completed" else "failed"
    return {
        "artifact_type": "o3k-pp5-phase-result",
        "schema_version": 1,
        "phase": "crash_recovery",
        "status": status,
        "reason": "crash_recovery_evidence_verified" if status == "passed" else "crash_recovery_evidence_failed",
        "tested_source_sha": source_sha or None,
        "evidence": [path.name],
        "last_crash_phase": value.get("phase"),
        "redacted": True,
    }


def maintenance_result(artifact_dir: Path, source_sha: str) -> dict:
    path = artifact_dir / "p15-7-host-maintenance-evidence.json"
    value = read(path)
    if value is None:
        return {
            "artifact_type": "o3k-pp5-phase-result",
            "schema_version": 1,
            "phase": "host_maintenance",
            "status": "not_run",
            "reason": "host_maintenance_evidence_not_published",
            "tested_source_sha": source_sha or None,
            "redacted": True,
        }
    status = "passed" if value.get("status") == "passed" and value.get("final_eligible_ready_count") == 5 else "failed"
    return {
        "artifact_type": "o3k-pp5-phase-result",
        "schema_version": 1,
        "phase": "host_maintenance",
        "status": status,
        "reason": "host_maintenance_evidence_verified" if status == "passed" else "host_maintenance_evidence_failed",
        "tested_source_sha": source_sha or None,
        "evidence": [path.name],
        "redacted": True,
    }


def not_run_result(phase: str, source_sha: str, reason: str) -> dict:
    return {
        "artifact_type": "o3k-pp5-phase-result",
        "schema_version": 1,
        "phase": phase,
        "status": "not_run",
        "reason": reason,
        "tested_source_sha": source_sha or None,
        "redacted": True,
    }


def boundary_result(artifact_dir: Path, source_sha: str, phase: str) -> dict:
    tier, expected_count = BOUNDARY_TIERS[phase]
    path = artifact_dir / "p15-7-boundary-smoke-evidence.json"
    value = read(path)
    reason = "boundary_smoke_evidence_missing_or_invalid"
    passed = False
    observed_count = None
    if value is not None:
        blocks = value.get("eligible_blocks")
        observed_count = value.get("eligible_ready_count")
        ids = [item.get("block_id") for item in blocks if isinstance(item, dict)] if isinstance(blocks, list) else []
        identities = [item.get("execution_identity") for item in blocks if isinstance(item, dict)] if isinstance(blocks, list) else []
        cleanup = value.get("cleanup")
        guest = value.get("guest_lifecycle")
        additional_ids = value.get("additional_block_ids")
        bootstrap_id = value.get("bootstrap_block_id")
        passed = (
            value.get("artifact_type") == "o3k-pp5-boundary-smoke-evidence"
            and value.get("schema_version") == 1
            and value.get("phase") == phase
            and value.get("status") == "passed"
            and value.get("tier") == tier
            and value.get("profile") == "small-edge-cloud"
            and value.get("execution_environment") == "nested-host-development"
            and value.get("tested_source_sha") == source_sha
            and value.get("redacted") is True
            and value.get("eligible_ready_count") == expected_count
            and len(ids) == expected_count
            and all(isinstance(item, str) and item for item in ids)
            and len(set(ids)) == expected_count
            and all(isinstance(item, str) and item for item in identities)
            and len(set(identities)) == expected_count
            and isinstance(bootstrap_id, str)
            and bootstrap_id in ids
            and isinstance(additional_ids, list)
            and len(additional_ids) == expected_count - 1
            and set(additional_ids) == set(ids) - {bootstrap_id}
            and isinstance(guest, dict)
            and guest.get("status") == "passed"
            and guest.get("created") is True
            and guest.get("active") is True
            and guest.get("deleted") is True
            and isinstance(cleanup, dict)
            and cleanup.get("status") == "passed"
            and cleanup.get("owned_domains_remaining") == 0
            and cleanup.get("owned_resources_remaining") == 0
            and cleanup.get("foreign_state_unchanged") is True
            and value.get("multi_host_transition") is (tier == "S2")
        )
        reason = "boundary_smoke_evidence_verified" if passed else "boundary_smoke_evidence_failed_or_mismatched"
    return {
        "artifact_type": "o3k-pp5-phase-result",
        "schema_version": 1,
        "phase": phase.replace("-", "_"),
        "tier": tier,
        "status": "passed" if passed else "failed",
        "reason": reason,
        "tested_source_sha": source_sha or None,
        "execution_environment": "nested-host-development",
        "eligible_ready_count": expected_count if passed else observed_count,
        "evidence": [path.name] if value is not None else [],
        "redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--source-sha", default="")
    parser.add_argument(
        "--phase",
        choices=("integrated", "s5-scale", "s1-boundary", "s2-boundary", "1035-crash-recovery", "host-maintenance"),
        default="integrated",
    )
    args = parser.parse_args()
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    s5 = s5_result(args.artifact_dir, args.source_sha)
    crash = crash_result(args.artifact_dir, args.source_sha)
    maintenance = maintenance_result(args.artifact_dir, args.source_sha)
    s1_boundary = not_run_result("s1_boundary", args.source_sha, "boundary_smoke_not_selected")
    s2_boundary = not_run_result("s2_boundary", args.source_sha, "boundary_smoke_not_selected")
    if args.phase in BOUNDARY_TIERS:
        s5 = not_run_result("s5_scale", args.source_sha, "boundary_smoke_does_not_run_s5")
        crash = not_run_result("crash_recovery", args.source_sha, "boundary_smoke_does_not_run_crash_recovery")
        maintenance = not_run_result("host_maintenance", args.source_sha, "boundary_smoke_does_not_run_host_maintenance")
        selected_boundary = boundary_result(args.artifact_dir, args.source_sha, args.phase)
        if args.phase == "s1-boundary":
            s1_boundary = selected_boundary
        else:
            s2_boundary = selected_boundary
    elif args.phase == "s5-scale":
        crash = not_run_result("crash_recovery", args.source_sha, "focused_s5_lane")
        maintenance = not_run_result("host_maintenance", args.source_sha, "focused_s5_lane")
    elif args.phase == "1035-crash-recovery":
        maintenance = not_run_result("host_maintenance", args.source_sha, "focused_crash_recovery_lane")
    elif args.phase == "host-maintenance":
        crash = not_run_result("crash_recovery", args.source_sha, "focused_host_maintenance_lane")
    selected = {
        "integrated": None,
        "s5-scale": s5,
        "1035-crash-recovery": crash,
        "host-maintenance": maintenance,
        "s1-boundary": s1_boundary,
        "s2-boundary": s2_boundary,
    }[args.phase]
    if selected is None:
        overall_status = "passed" if all(item["status"] == "passed" for item in (s5, crash, maintenance)) else "failed"
    elif selected["status"] == "passed":
        # A focused lane proves only its requested phase.  Do not present
        # deliberately skipped phases as an integrated certification result.
        overall_status = "not_run"
    else:
        overall_status = "failed"
    overall = {
        "artifact_type": "o3k-pp5-overall-result",
        "schema_version": 1,
        "s5_scale": s5["status"],
        "crash_recovery": crash["status"],
        "host_maintenance": maintenance["status"],
        "s1_boundary_smoke": s1_boundary["status"],
        "s2_boundary_smoke": s2_boundary["status"],
        "overall": overall_status,
        "requested_phase": args.phase,
        "tested_source_sha": args.source_sha or None,
        "redacted": True,
    }
    outputs = {
        "pp5-s5-scale-result.json": s5,
        "pp5-1035-crash-recovery-result.json": crash,
        "pp5-host-maintenance-result.json": maintenance,
        "pp5-s1-boundary-smoke-result.json": s1_boundary,
        "pp5-s2-boundary-smoke-result.json": s2_boundary,
        "pp5-overall-result.json": overall,
    }
    for name, value in outputs.items():
        (args.artifact_dir / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
