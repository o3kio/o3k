#!/usr/bin/env python3
"""Run and record the accepted P13.2-P13.4 baseline gate set.

The emitted JSON is intentionally shaped like the ``existing_p13_baseline``
object consumed by ``validate_p13_5b_evidence.py``.  A P13.5B runner can load
the manifest directly without converting human-readable gate output into
evidence.

Every gate is run against the same HEAD.  Gates are not short-circuited: a
failure is recorded and the remaining gates still run so that the artifact
always describes the complete 11-gate baseline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid


BASELINE_GATES = [
    "tests/p13_2_core_lifecycle.sh",
    "tests/p13_2b_subnet_lifecycle.sh",
    "tests/p13_2c_port_lifecycle.sh",
    "tests/p13_2d_server_lifecycle.sh",
    "tests/p13_3_security_group_provider.sh",
    "tests/p13_3_security_group_port_provider.sh",
    "tests/p13_3_router_provider.sh",
    "tests/p13_3_floating_ip_provider.sh",
    "tests/p13_4_provider_volume_smoke.sh",
    "tests/p13_4_provider_volume_attachment_smoke.sh",
    "tests/p13_4_storage_lifecycle.sh",
]

GENERATED_BASELINE_ARTIFACTS = [
    "docs/compatibility/p13-2/p13-2c-provider-port-lifecycle-evidence.json",
    "docs/compatibility/p13-3/p13-3b3-port-security-group-provider-lifecycle-evidence.json",
    "docs/compatibility/p13-3/p13-3e-floating-ip-provider-lifecycle-evidence.json",
]


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest_without_self(document: dict[str, object]) -> str:
    unsigned = dict(document)
    unsigned.pop("evidence_sha256", None)
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


def classify(exit_code: int | None, error: str | None) -> str:
    if error is not None or exit_code is None:
        return "blocked"
    if exit_code == 0:
        return "passed"
    # A non-zero gate prevents baseline verification.  Keep the controlled
    # result vocabulary small; the exit code/reason preserves the diagnosis.
    return "blocked"


def run_gate(
    root: Path,
    gate_path: str,
    source_commit: str,
    log_path: Path,
    timeout_seconds: int | None,
) -> dict[str, object]:
    started = utc_now()
    started_epoch = time.monotonic()
    record: dict[str, object] = {
        "path": gate_path,
        "command": ["bash", gate_path],
        "head_sha": source_commit,
        "started_at": started,
        "log_path": str(log_path),
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if git(root, "rev-parse", "HEAD") != source_commit:
        record.update(
            result="blocked",
            reason="head_changed_before_gate",
            exit_code=None,
            duration_seconds=0.0,
            finished_at=utc_now(),
        )
        log_path.write_text("HEAD changed before gate execution\n", encoding="utf-8")
        return record

    error: str | None = None
    try:
        with log_path.open("w", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                ["bash", gate_path],
                cwd=root,
                env=os.environ.copy(),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                exit_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                error = f"timeout_after_{timeout_seconds}_seconds"
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                exit_code = None
                with log_path.open("a", encoding="utf-8") as log_file:
                    log_file.write(f"\nmanifest runner: {error}\n")
            except KeyboardInterrupt:
                error = "interrupted"
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait()
                exit_code = None
                with log_path.open("a", encoding="utf-8") as log_file:
                    log_file.write("\nmanifest runner: interrupted\n")
    except OSError as exc:
        exit_code = None
        error = f"launch_error: {exc}"

    after_commit = git(root, "rev-parse", "HEAD")
    if after_commit != source_commit:
        error = "head_changed_after_gate"
        exit_code = None
    record.update(
        result=classify(exit_code, error),
        exit_code=exit_code,
        duration_seconds=round(time.monotonic() - started_epoch, 3),
        finished_at=utc_now(),
    )
    if error is not None:
        record["reason"] = error
    return record


def blocked_record(gate_path: str, source_commit: str, log_path: Path, reason: str) -> dict[str, object]:
    return {
        "path": gate_path,
        "command": ["bash", gate_path],
        "head_sha": source_commit,
        "started_at": None,
        "finished_at": utc_now(),
        "duration_seconds": 0.0,
        "exit_code": None,
        "result": "blocked",
        "reason": reason,
        "log_path": str(log_path),
    }


def restore_generated_artifacts(root: Path) -> None:
    """Keep upstream gate evidence side effects out of the caller's checkout."""

    subprocess.run(
        ["git", "-C", str(root), "restore", "--", *GENERATED_BASELINE_ARTIFACTS],
        check=True,
    )


def reset_postgres_schema() -> None:
    """Give each PostgreSQL gate an empty explicitly opted-in disposable DB."""

    database_url = os.environ.get("O3K_DATABASE_URL")
    if os.environ.get("O3K_DATABASE_BACKEND", "sqlite") != "postgres" or not database_url:
        return
    if os.environ.get("O3K_P13_ALLOW_DESTRUCTIVE_POSTGRES_RESET") != "1":
        raise RuntimeError("postgres_schema_reset_requires_explicit_opt_in")
    guard = Path(__file__).resolve().with_name("assert_disposable_postgres_test_database.py")
    subprocess.run([sys.executable, str(guard)], check=True)
    result = subprocess.run(
        [
            "psql",
            database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().replace("\n", " ")
        raise RuntimeError(f"postgres_schema_reset_failed: {detail}")


def build_manifest(root: Path, output: Path, timeout_seconds: int | None) -> dict[str, object]:
    run_id = str(uuid.uuid4())
    source_commit = git(root, "rev-parse", "HEAD")
    working_tree_clean_before = not bool(git(root, "status", "--porcelain"))
    log_dir = output.parent / f"{output.stem}.gates.{run_id}"
    gates: list[dict[str, object]] = []
    head_changed = False

    for gate_path in BASELINE_GATES:
        if head_changed:
            gates.append(blocked_record(gate_path, source_commit, log_dir / (Path(gate_path).stem + ".log"), "head_changed_during_run"))
            continue
        if git(root, "rev-parse", "HEAD") != source_commit:
            head_changed = True
            gates.append(blocked_record(gate_path, source_commit, log_dir / (Path(gate_path).stem + ".log"), "head_changed_before_gate"))
            continue
        try:
            reset_postgres_schema()
        except (OSError, RuntimeError) as exc:
            gates.append(
                blocked_record(
                    gate_path,
                    source_commit,
                    log_dir / (Path(gate_path).stem + ".log"),
                    str(exc),
                )
            )
            continue
        record = run_gate(root, gate_path, source_commit, log_dir / (Path(gate_path).stem + ".log"), timeout_seconds)
        gates.append(record)
        if record.get("reason") in {"head_changed_before_gate", "head_changed_after_gate"}:
            head_changed = True

    if working_tree_clean_before:
        restore_generated_artifacts(root)

    all_passed = all(gate["result"] == "passed" for gate in gates)
    current_commit = git(root, "rev-parse", "HEAD")
    status = "verified" if all_passed and current_commit == source_commit else "blocked"
    document: dict[str, object] = {
        "artifact_type": "o3k-p13-2-4-baseline-gate-manifest",
        "schema_version": 1,
        "phase": "P13.2-P13.4",
        "status": status,
        "run_id": run_id,
        "source_commit": source_commit,
        "required_gates": BASELINE_GATES,
        "gates": gates,
        "gate_count": len(gates),
        "toolchain": {
            "opentofu": "1.12.6",
            "provider": "terraform-provider-openstack/openstack 3.4.0",
            "provider_modified": False,
        },
        "execution": {
            "working_tree_clean_before": working_tree_clean_before,
            "working_tree_clean_after": not bool(git(root, "status", "--porcelain")),
            "head_after_run": current_commit,
            "environment_inherited": True,
            "timeout_seconds": timeout_seconds,
            "postgres_schema_reset_between_gates": os.environ.get("O3K_DATABASE_BACKEND", "sqlite")
            == "postgres",
        },
        "consumer": {
            "p13_5b_field": "existing_p13_baseline",
            "validator_shape": "validate_verified_baseline",
        },
    }
    document["evidence_sha256"] = digest_without_self(document)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="JSON manifest path")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to this checkout)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=None,
        help="optional per-gate timeout; timed-out gates are recorded as blocked",
    )
    parser.add_argument("--list-gates", action="store_true", help="print the ordered 11-gate set and exit")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.list_gates:
        print("\n".join(BASELINE_GATES))
        return 0
    if args.output is None:
        parser.error("--output is required unless --list-gates is used")
    if args.timeout_seconds is not None and args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    if len(BASELINE_GATES) != 11 or len(set(BASELINE_GATES)) != 11:
        raise SystemExit("internal error: baseline gate set is not exactly 11 unique gates")
    if not (root / ".git").exists():
        raise SystemExit(f"repository root is not a Git checkout: {root}")

    try:
        manifest = build_manifest(root, args.output.resolve(), args.timeout_seconds)
    except KeyboardInterrupt:
        # A signal during a child gate cannot safely produce a complete result
        # list here; the normal shell/CI wrapper should rerun the manifest.
        print("baseline manifest interrupted; rerun to produce a complete artifact", file=sys.stderr)
        return 130
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_bytes(canonical_json(manifest))
    print(json.dumps({"status": manifest["status"], "source_commit": manifest["source_commit"], "output": str(args.output.resolve())}, sort_keys=True))
    return 0 if manifest["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
