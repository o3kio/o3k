#!/usr/bin/env python3
"""Evaluate Fabric v3 evidence without conflating deferral and success."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STATES = {"PASS", "FAIL", "DEFERRED_BY_POLICY", "NOT_RUN"}
REQUIRED_AUTOMATED = (
    "product_unit_integration",
    "sqlite_lifecycle",
    "postgresql_lifecycle",
)


def evaluate(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("status record must be an object")
    evidence = record.get("evidence")
    authorizations = record.get("authorized_deferrals")
    if not isinstance(evidence, dict) or not isinstance(authorizations, dict):
        raise ValueError("evidence and authorized_deferrals must be objects")

    for name, state in evidence.items():
        if not isinstance(state, str) or state not in STATES:
            raise ValueError(f"{name}: unsupported state {state!r}")
        if state == "DEFERRED_BY_POLICY":
            authorization = authorizations.get(name)
            if not isinstance(authorization, str) or not authorization.strip():
                raise ValueError(f"{name}: deferral lacks explicit authorization")

    missing = [name for name in REQUIRED_AUTOMATED if evidence.get(name) != "PASS"]
    physical = evidence.get("physical_three_host_gate_b", "NOT_RUN")
    nested = evidence.get("real_host_nested_microgate", "NOT_RUN")

    if (
        not isinstance(physical, str)
        or physical not in STATES
        or not isinstance(nested, str)
        or nested not in STATES
    ):
        raise ValueError("physical evidence has an unsupported state")

    physical_validation_blocked = any(
        state in {"FAIL", "NOT_RUN"} for state in (physical, nested)
    )

    return {
        "automated_product_validation": "PASS" if not missing else "FAIL",
        "missing_automated_passes": missing,
        "real_host_nested_microgate": nested,
        "physical_three_host_gate_b": physical,
        "merge_blocked_by_physical_validation": physical_validation_blocked,
        "final_physical_certification_claimed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "status_file",
        nargs="?",
        type=Path,
        default=Path("docs/evidence/fabric-v3-validation-status.json"),
    )
    args = parser.parse_args()
    try:
        record = json.loads(args.status_file.read_text(encoding="utf-8"))
        result = evaluate(record)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return (
        0
        if result["automated_product_validation"] == "PASS"
        and not result["merge_blocked_by_physical_validation"]
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
