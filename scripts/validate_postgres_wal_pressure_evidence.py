#!/usr/bin/env python3
"""Fail-closed validator for the PP.6 disposable PostgreSQL WAL lane."""

import json
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def validate(
    record: object,
    *,
    check_worktree: bool = True,
    repository: Path | None = None,
) -> None:
    if not isinstance(record, dict):
        raise ValueError("evidence root must be an object")
    required = {
        "artifact_type": "o3k-pp6-postgres-wal-pressure",
        "schema_version": 1,
        "disposition": "passed",
        "issue": 1089,
        "profile": "o3k-small-edge-v1",
    }
    for key, value in required.items():
        if record.get(key) != value:
            raise ValueError(f"{key} must be {value!r}")

    source = record.get("source")
    if not isinstance(source, dict) or not re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))) or not re.fullmatch(r"[0-9a-f]{40}", str(source.get("tree", ""))):
        raise ValueError("exact source commit and tree are required")
    repository = repository or Path(__file__).resolve().parents[1]
    try:
        observed_tree = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", f"{source['commit']}^{{tree}}"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        observed_head = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (KeyError, subprocess.CalledProcessError) as error:
        raise ValueError("source commit must exist in the checked-out repository") from error
    if observed_tree != source["tree"] or observed_head != source["commit"]:
        raise ValueError("evidence must be bound to the exact checked-out commit and tree")
    if check_worktree:
        dirty = subprocess.check_output(
            ["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=all"],
            text=True,
        ).strip()
        if dirty:
            raise ValueError("evidence must be produced from a clean source checkout")
    harness = record.get("harness")
    if not isinstance(harness, dict) or harness.get("path") != "tests/postgres-wal-pressure.sh":
        raise ValueError("exact WAL harness identity is required")
    harness_sha = harness.get("sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(harness_sha or "")):
        raise ValueError("WAL harness SHA-256 is required")
    actual_harness_sha = hashlib.sha256((repository / harness["path"]).read_bytes()).hexdigest()
    if harness_sha != actual_harness_sha:
        raise ValueError("evidence harness digest does not match the checked-out source")
    environment = record.get("environment")
    if not isinstance(environment, dict) or not str(environment.get("postgres_server_version", "")).startswith("16.4"):
        raise ValueError("observed PostgreSQL 16.4 server version is required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(environment.get("postgres_image_id", ""))):
        raise ValueError("immutable PostgreSQL container image digest is required")
    fault = record.get("fault_injection")
    if not isinstance(fault, dict) or fault.get("database_panic_after_enospc") is not True:
        raise ValueError("observed PostgreSQL ENOSPC/PANIC is required")
    if fault.get("crash_recovery_log_observed") is not True:
        raise ValueError("PostgreSQL crash recovery after PANIC must be observed")
    if fault.get("observed_sqlstate") != "53100":
        raise ValueError("pressure write must fail with PostgreSQL disk-full SQLSTATE 53100")
    rows = fault.get("successful_pressure_rows")
    if not isinstance(rows, int) or not 1 <= rows <= 12000:
        raise ValueError("bounded successful pressure writes must precede disk-full")
    if fault.get("pg_isready_failed_while_reserve_held") is not True:
        raise ValueError("PostgreSQL unavailability while the reserve is held must be observed")
    if fault.get("reserve_verified") is not True or fault.get("reserve_bytes") != 50331648:
        raise ValueError("exact owned WAL reserve must be verified")
    free_before = fault.get("wal_tmpfs_free_bytes_before_pressure")
    free_after = fault.get("wal_tmpfs_free_bytes_after_failure")
    if not isinstance(free_before, int) or not 0 < free_before <= 80 * 1024 * 1024:
        raise ValueError("WAL tmpfs free space before pressure is outside the bounded range")
    if not isinstance(free_after, int) or not 0 <= free_after <= 8 * 1024 * 1024:
        raise ValueError("WAL tmpfs must be nearly exhausted at the observed failure")
    if fault.get("recovery_mode") not in {
        "postgres_automatic_restart",
        "harness_restart",
        "postgres_automatic_then_harness_restart",
    }:
        raise ValueError("recovery mode must identify who restarted PostgreSQL")
    initial_ready = fault.get("initial_ready_at_epoch_ms")
    unavailable_at = fault.get("unavailable_observed_at_epoch_ms")
    recovered_at = fault.get("ready_after_recovery_at_epoch_ms")
    if not all(isinstance(value, int) and value > 0 for value in (initial_ready, unavailable_at, recovered_at)):
        raise ValueError("readiness transition timestamps are required")
    if not initial_ready <= unavailable_at <= recovered_at:
        raise ValueError("readiness transition timestamps are not ordered")
    if fault.get("readiness_at_reserve_release") not in {"ready", "unavailable"}:
        raise ValueError("readiness state immediately before reserve release is required")
    if fault.get("postmaster_at_reserve_release") not in {"running", "stopped"}:
        raise ValueError("postmaster state immediately before reserve release is required")
    if fault["recovery_mode"] == "harness_restart" and fault["postmaster_at_reserve_release"] != "stopped":
        raise ValueError("harness restart requires a stopped postmaster before reserve release")
    if fault["recovery_mode"] in {
        "postgres_automatic_restart",
        "postgres_automatic_then_harness_restart",
    } and fault["postmaster_at_reserve_release"] != "running":
        raise ValueError("automatic PostgreSQL restart requires a running postmaster at reserve release")
    observations = record.get("observations")
    if not isinstance(observations, dict):
        raise ValueError("observations are required")
    for key in ("baseline_rows_recovered", "primary_recovered_after_restart", "post_restart_canonical_write_readback"):
        if observations.get(key) is not True:
            raise ValueError(f"{key} must be true")
    for key in ("baseline_resource_id", "baseline_operation_id", "post_restart_resource_id"):
        if not re.fullmatch(r"[0-9a-f-]{36}", str(observations.get(key, ""))):
            raise ValueError(f"{key} must identify the observed record")
    foreign = record.get("foreign_state")
    if foreign != {
        "status": "not_exercised",
        "reason": "isolated store-only lane invokes no provider or external-state operations",
    }:
        raise ValueError("foreign-state scope must remain explicitly not exercised")
    if record.get("secrets", {}).get("scan") != "passed":
        raise ValueError("secret scan must pass")
    if record.get("cleanup", {}).get("status") != "passed":
        raise ValueError("run-owned container and temporary data cleanup must pass")
    serialized = json.dumps(record, sort_keys=True)
    if re.search(r"postgres://[^\s\"']*:[^@\s\"']+@|(?:password|token)[=:][^\s]+|private[_ -]?key", serialized, re.I):
        raise ValueError("evidence contains a credential-like value")


def self_test() -> None:
    source_repository = Path(__file__).resolve().parents[1]
    temporary = tempfile.TemporaryDirectory(prefix="o3k-wal-validator-")
    repository = Path(temporary.name)
    (repository / "tests").mkdir()
    shutil.copyfile(
        source_repository / "tests/postgres-wal-pressure.sh",
        repository / "tests/postgres-wal-pressure.sh",
    )
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "add", "tests/postgres-wal-pressure.sh"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "-c",
            "user.name=Validator Self Test",
            "-c",
            "user.email=validator-self-test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    commit = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()
    valid = {
        "artifact_type": "o3k-pp6-postgres-wal-pressure",
        "schema_version": 1,
        "disposition": "passed",
        "issue": 1089,
        "profile": "o3k-small-edge-v1",
        "source": {
            "commit": commit,
            "tree": tree,
        },
        "harness": {
            "path": "tests/postgres-wal-pressure.sh",
            "sha256": hashlib.sha256((repository / "tests/postgres-wal-pressure.sh").read_bytes()).hexdigest(),
            "run_id": "self-test",
        },
        "environment": {"postgres_server_version": "16.4", "postgres_image_id": "sha256:" + "c" * 64},
        "fault_injection": {
            "database_panic_after_enospc": True,
            "crash_recovery_log_observed": True,
            "observed_sqlstate": "53100",
            "successful_pressure_rows": 20,
            "pg_isready_failed_while_reserve_held": True,
            "reserve_verified": True,
            "reserve_bytes": 50331648,
            "wal_tmpfs_free_bytes_before_pressure": 50 * 1024 * 1024,
            "wal_tmpfs_free_bytes_after_failure": 4 * 1024 * 1024,
            "recovery_mode": "harness_restart",
            "initial_ready_at_epoch_ms": 100,
            "unavailable_observed_at_epoch_ms": 200,
            "readiness_at_reserve_release": "unavailable",
            "postmaster_at_reserve_release": "stopped",
            "ready_after_recovery_at_epoch_ms": 300,
        },
        "observations": {
            "baseline_resource_id": "11111111-1111-4111-8111-111111111111",
            "baseline_operation_id": "22222222-2222-4222-8222-222222222222",
            "baseline_rows_recovered": True,
            "primary_recovered_after_restart": True,
            "post_restart_resource_id": "33333333-3333-4333-8333-333333333333",
            "post_restart_canonical_write_readback": True,
        },
        "foreign_state": {
            "status": "not_exercised",
            "reason": "isolated store-only lane invokes no provider or external-state operations",
        },
        "secrets": {"scan": "passed"},
        "cleanup": {"status": "passed"},
    }
    validate(valid, repository=repository)
    invalid = json.loads(json.dumps(valid))
    invalid["source"]["commit"] = "0" * 40
    expect_rejected(invalid, repository, "mismatched source commit")
    invalid = json.loads(json.dumps(valid))
    invalid["source"]["tree"] = "0" * 40
    expect_rejected(invalid, repository, "mismatched source tree")
    invalid = json.loads(json.dumps(valid))
    invalid["harness"]["sha256"] = "0" * 64
    expect_rejected(invalid, repository, "mismatched harness digest")
    (repository / "untracked-dirty-state").write_text("dirty", encoding="utf-8")
    expect_rejected(valid, repository, "dirty source checkout")
    (repository / "untracked-dirty-state").unlink()
    invalid = json.loads(json.dumps(valid))
    invalid["fault_injection"]["database_panic_after_enospc"] = False
    try:
        validate(invalid, repository=repository)
    except ValueError:
        pass
    else:
        raise AssertionError("validator accepted missing ENOSPC/PANIC")
    invalid = json.loads(json.dumps(valid))
    invalid["fault_injection"]["crash_recovery_log_observed"] = False
    try:
        validate(invalid, repository=repository)
    except ValueError:
        pass
    else:
        raise AssertionError("validator accepted missing crash recovery")
    invalid = json.loads(json.dumps(valid))
    invalid["fault_injection"]["observed_sqlstate"] = "08006"
    try:
        validate(invalid, repository=repository)
    except ValueError:
        pass
    else:
        raise AssertionError("validator accepted a non-disk-full SQLSTATE")
    invalid = json.loads(json.dumps(valid))
    invalid["environment"]["postgres_image_id"] = "sha256:short"
    try:
        validate(invalid, repository=repository)
    except ValueError:
        pass
    else:
        raise AssertionError("validator accepted a non-immutable image identifier")
    temporary.cleanup()


def expect_rejected(record: object, repository: Path, description: str) -> None:
    try:
        validate(record, repository=repository)
    except ValueError:
        return
    raise AssertionError(f"validator accepted {description}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 1:
        raise SystemExit("usage: validate_postgres_wal_pressure_evidence.py [--self-test|EVIDENCE.json]")
    elif len(sys.argv) == 2:
        validate(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
    else:
        raise SystemExit("usage: validate_postgres_wal_pressure_evidence.py [--self-test|EVIDENCE.json]")
