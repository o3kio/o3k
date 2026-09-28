#!/usr/bin/env python3
"""Classify the three PP.5 acceptance phases without changing the gate."""

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--source-sha", default="")
    args = parser.parse_args()
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    s5 = s5_result(args.artifact_dir, args.source_sha)
    crash = crash_result(args.artifact_dir, args.source_sha)
    maintenance = maintenance_result(args.artifact_dir, args.source_sha)
    overall_status = "passed" if all(item["status"] == "passed" for item in (s5, crash, maintenance)) else "failed"
    overall = {
        "artifact_type": "o3k-pp5-overall-result",
        "schema_version": 1,
        "s5_scale": s5["status"],
        "crash_recovery": crash["status"],
        "host_maintenance": maintenance["status"],
        "overall": overall_status,
        "tested_source_sha": args.source_sha or None,
        "redacted": True,
    }
    outputs = {
        "pp5-s5-scale-result.json": s5,
        "pp5-1035-crash-recovery-result.json": crash,
        "pp5-host-maintenance-result.json": maintenance,
        "pp5-overall-result.json": overall,
    }
    for name, value in outputs.items():
        (args.artifact_dir / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
