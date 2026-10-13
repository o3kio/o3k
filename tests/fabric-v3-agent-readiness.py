#!/usr/bin/env python3
"""Validate current compute-agent readiness before supported teardown."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import pathlib
import sys
import time
from typing import Any

MAX_OBSERVATION_AGE_MS = 15_000
REQUIRED_HOSTS = ("host-a", "host-b")


def _mapping(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _timestamp_ms(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return int(parsed.timestamp() * 1000)


def _post_restart_registrations(controller_log: str, controller_start_ms: int) -> dict[tuple[str, str], int]:
    registrations: dict[tuple[str, str], int] = {}
    for line in controller_log.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        fields = _mapping(event.get("fields")) or {}
        timestamp = _timestamp_ms(event.get("timestamp"))
        agent_id = fields.get("agent_id")
        epoch = fields.get("epoch")
        if (
            fields.get("message") == "compute agent registered"
            and isinstance(timestamp, int)
            and timestamp >= controller_start_ms
            and isinstance(agent_id, str)
            and isinstance(epoch, str)
            and agent_id
            and epoch
        ):
            registrations[(agent_id, epoch)] = timestamp
    return registrations


def evaluate(
    manifest: dict[str, Any],
    providers_doc: dict[str, Any],
    readiness_by_host: dict[str, Any],
    now_ms: int,
    *,
    controller_log: str,
    controller_start_ms: int,
    consecutive_observations: int = 1,
) -> dict[str, Any]:
    """Return redacted readiness evidence for one controller observation."""
    agents: list[dict[str, Any]] = []
    failure: tuple[str, str] | None = None
    expected_agents = _mapping(manifest.get("compute_agents")) or {}
    items = providers_doc.get("items")
    if not isinstance(items, list):
        items = []
        failure = ("read_compute_agent_registry", "provider diagnostics has no items list")

    provider_items: dict[str, dict[str, Any]] = {}
    duplicate_ids: set[str] = set()
    for item in items:
        item = _mapping(item)
        if item is None:
            continue
        provider_id = item.get("provider_id")
        if not isinstance(provider_id, str) or not provider_id:
            continue
        if provider_id in provider_items:
            duplicate_ids.add(provider_id)
        provider_items[provider_id] = item
    registrations = _post_restart_registrations(controller_log, controller_start_ms)

    for host in REQUIRED_HOSTS:
        expected = _mapping(expected_agents.get(host)) or {}
        expected_id = expected.get("agent_id")
        expected_epoch = expected.get("agent_epoch")
        ready = _mapping(readiness_by_host.get(host))
        entry: dict[str, Any] = {
            "host": host,
            "expected_agent_id": expected_id,
            "expected_agent_epoch": expected_epoch,
        }
        if not isinstance(expected_id, str) or not expected_id or not isinstance(expected_epoch, str) or not expected_epoch:
            failure = failure or ("load_frozen_compute_agent_identity", f"manifest identity missing for {host}")
            entry["identity_valid"] = False
        else:
            entry["identity_valid"] = True

        provider = provider_items.get(expected_id) if isinstance(expected_id, str) else None
        if isinstance(expected_id, str) and expected_id in duplicate_ids:
            failure = failure or ("read_compute_agent_registry", f"duplicate provider diagnostic for {expected_id}")
        if provider is None:
            failure = failure or ("read_compute_agent_registry", f"provider diagnostic missing for {expected_id}")
            entry["registry"] = {"present": False}
        else:
            status = provider.get("status")
            availability = provider.get("availability")
            observed = provider.get("observed_at_unix_ms")
            valid_timestamp = isinstance(observed, int) and not isinstance(observed, bool)
            age_ms = now_ms - observed if valid_timestamp else None
            fresh = valid_timestamp and 0 <= age_ms <= MAX_OBSERVATION_AGE_MS
            observed_after_restart = valid_timestamp and observed >= controller_start_ms
            entry["registry"] = {
                "present": True,
                "provider_id": expected_id,
                "status": status,
                "availability": availability,
                "observed_at_unix_ms": observed if valid_timestamp else None,
                "age_ms": age_ms,
                "fresh": bool(fresh),
                "observed_after_controller_start": bool(observed_after_restart),
            }
            if status != "healthy" or availability != "available" or not fresh or not observed_after_restart:
                failure = failure or ("read_compute_agent_registry", f"provider {expected_id} is not healthy, available, and fresh")

        if ready is None:
            ready = {}
        current_id = ready.get("agent_id")
        current_epoch = ready.get("agent_epoch")
        guest_ready = (
            ready.get("status") == "ready"
            and current_id == expected_id
            and isinstance(current_epoch, str)
            and bool(current_epoch)
        )
        entry["guest_ready"] = {
            "status": ready.get("status"),
            "agent_id": current_id,
            "agent_epoch": current_epoch,
            "matches_stable_agent_identity": bool(guest_ready),
        }
        if not guest_ready:
            failure = failure or ("read_compute_agent_readyz", f"guest readiness identity is not current for {host}")
        registration_ms = registrations.get((expected_id, current_epoch)) if isinstance(expected_id, str) and isinstance(current_epoch, str) else None
        entry["agent_epoch"] = current_epoch
        entry["bootstrap_agent_epoch"] = expected_epoch
        entry["epoch_changed_from_bootstrap"] = bool(
            isinstance(current_epoch, str) and isinstance(expected_epoch, str) and current_epoch != expected_epoch
        )
        entry["post_restart_registration_unix_ms"] = registration_ms
        if registration_ms is None:
            failure = failure or (
                "observe_compute_agent_registration_after_restart",
                f"controller did not record current identity/epoch for {host}",
            )
        agents.append(entry)

    observation_valid = failure is None
    status = "failed" if not observation_valid else (
        "passed" if consecutive_observations >= 2 else "pending"
    )
    return {
        "artifact_type": "fabric-v3-compute-agent-readiness",
        "phase": "post-controller-restart-before-supported-teardown",
        "status": status,
        "classification": None if observation_valid else "HARNESS_GAP",
        "failed_operation": None if failure is None else failure[0],
        "diagnostic": None if failure is None else failure[1],
        "observer_type": "api_observation+runner_executable_guest_readyz",
        "controller_start_unix_ms": controller_start_ms,
        "observation_valid": observation_valid,
        "consecutive_observations": consecutive_observations,
        "max_observation_age_ms": MAX_OBSERVATION_AGE_MS,
        "agents": agents,
    }


def _read_json(path: str) -> dict[str, Any]:
    with pathlib.Path(path).open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value must be an object")
    return value


def _failure(operation: str, diagnostic: str, *, controller_start_ms: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "artifact_type": "fabric-v3-compute-agent-readiness",
        "phase": "post-controller-restart-before-supported-teardown",
        "status": "failed",
        "classification": "HARNESS_GAP",
        "failed_operation": operation,
        "diagnostic": diagnostic,
        "observer_type": "api_observation+runner_executable_guest_readyz",
        "observation_valid": False,
    }
    if controller_start_ms is not None:
        result["controller_start_unix_ms"] = controller_start_ms
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--providers", required=True)
    validate.add_argument("--ready-a", required=True)
    validate.add_argument("--ready-b", required=True)
    validate.add_argument("--controller-log", required=True)
    validate.add_argument("--controller-start", required=True)
    validate.add_argument("--now-ms", type=int)
    validate.add_argument("--consecutive-observations", type=int, default=1)
    validate.add_argument("--output", required=True)
    args = parser.parse_args()

    result: dict[str, Any]
    try:
        start_doc = _read_json(args.controller_start)
        controller_start_ms = _timestamp_ms(start_doc.get("start_requested_at_utc"))
        if controller_start_ms is None:
            result = _failure("read_controller_restart_start_time", "start timestamp is missing or invalid")
        else:
            try:
                controller_log = pathlib.Path(args.controller_log).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError as exc:
                result = _failure(
                    "read_controller_restart_log",
                    type(exc).__name__,
                    controller_start_ms=controller_start_ms,
                )
            else:
                try:
                    manifest = _read_json(args.manifest)
                    providers = _read_json(args.providers)
                    readiness = {
                        "host-a": _read_json(args.ready_a),
                        "host-b": _read_json(args.ready_b),
                    }
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    result = _failure(
                        "read_compute_agent_readiness_inputs",
                        type(exc).__name__,
                        controller_start_ms=controller_start_ms,
                    )
                else:
                    result = evaluate(
                        manifest,
                        providers,
                        readiness,
                        int(args.now_ms if args.now_ms is not None else time.time() * 1000),
                        controller_log=controller_log,
                        controller_start_ms=controller_start_ms,
                        consecutive_observations=args.consecutive_observations,
                    )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = _failure("read_controller_restart_start_time", type(exc).__name__)
    result["consecutive_observations"] = args.consecutive_observations
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if result.get("observation_valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
