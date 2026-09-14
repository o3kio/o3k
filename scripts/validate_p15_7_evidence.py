#!/usr/bin/env python3
"""Validate the protected P15.7 scale/composition evidence contract.

This validator intentionally accepts only a completed real-host artifact.  A
missing, skipped, fake-provider, or fixture result is not evidence of P15.7.
The runner-specific journey is supplied by the protected host; this file only
validates its redacted, machine-readable result. Araf is an optional external
consumer and is recorded separately without becoming a mandatory gate.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any


SHA = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_CLAIMS = re.compile(
    r"(?i)(?:datacenter[- ]scale|multi[- ]region|\bHA\b|high availability|"
    r"live migration|evacuation|production ready|production readiness)"
)
REQUIRED_STEPS = {
    "fresh_deployment",
    "init",
    "multiple_authenticated_joins",
    "topology",
    "capacity",
    "constrained_placement",
    "add_block_capacity_growth",
    "drain",
    "remove_rejoin_replace",
    "restart_recovery",
    "projections_convergent",
}
CLAIM_VALIDATION_SOURCES = {
    "README.md",
    "docs/ROADMAP.md",
    "docs/status/current-state.yaml",
    "compatibility/product-profiles.yaml",
    "docs/compatibility/matrix.yaml",
    "docs/architecture/p15-e2d-gap-register.md",
}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def mapping(value: Any, name: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        fail(errors, f"{name} must be an object")
        return None
    return value


def passed(value: Any, name: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        value = value.get("status")
    if value is not True and value != "passed":
        fail(errors, f"{name} must be true or 'passed'")


def validate(
    document: Any,
    expected_sha: str | None = None,
    expected_profile: str | None = None,
) -> list[str]:
    errors: list[str] = []
    root = mapping(document, "evidence", errors)
    if root is None:
        return errors

    if root.get("artifact_type") != "o3k-p15-7-scale-composition-evidence":
        fail(errors, "invalid artifact_type")
    if root.get("schema_version") != 1:
        fail(errors, "schema_version must be 1")
    if root.get("phase") != "P15.7":
        fail(errors, "phase must be P15.7")
    if root.get("status") != "passed":
        fail(errors, "status must be passed; skipped/ready/not-executed is not evidence")
    if root.get("evidence_tier") != "protected-real-host":
        fail(errors, "evidence_tier must be protected-real-host")
    if root.get("profile") not in {"native-rust-testlab", "small-edge-cloud"}:
        fail(errors, "profile must be an accepted native-rust-testlab or small-edge-cloud profile")
    if expected_profile and root.get("profile") != expected_profile:
        fail(errors, f"profile does not match expected profile {expected_profile}")

    source_sha = root.get("tested_source_sha")
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        fail(errors, "tested_source_sha must be a lowercase 40-character commit SHA")
    elif expected_sha and source_sha != expected_sha:
        fail(errors, f"tested_source_sha does not match expected source {expected_sha}")

    execution = mapping(root.get("execution"), "execution", errors)
    if execution is not None:
        for key in ("real_o3kd", "real_auth", "real_execution_boundary", "multiple_real_hosts", "sqlite_parity"):
            passed(execution.get(key), f"execution.{key}", errors)
        if execution.get("provider") != "agent":
            fail(errors, "execution.provider must be agent (fake providers are forbidden)")
        if execution.get("hypervisor") != "libvirt":
            fail(errors, "execution.hypervisor must be libvirt (the real execution boundary)")
        if execution.get("database_backend") != "postgres":
            fail(errors, "execution.database_backend must be postgres for the production composition gate")
        if not isinstance(execution.get("block_count"), int) or execution["block_count"] < 2:
            fail(errors, "execution.block_count must be at least 2")

    journey = mapping(root.get("journey"), "journey", errors)
    if journey is not None:
        missing = sorted(REQUIRED_STEPS - set(journey))
        for step in missing:
            fail(errors, f"journey.{step} is required")
        for step in sorted(REQUIRED_STEPS - {"drain", "multiple_authenticated_joins", "projections_convergent"}):
            if step in journey:
                passed(journey[step], f"journey.{step}", errors)
        joins = mapping(journey.get("multiple_authenticated_joins"), "journey.multiple_authenticated_joins", errors)
        if joins is not None:
            passed(joins.get("status"), "journey.multiple_authenticated_joins.status", errors)
            if not isinstance(joins.get("count"), int) or joins["count"] < 2:
                fail(errors, "journey.multiple_authenticated_joins.count must be at least 2")
            passed(joins.get("each_authenticated"), "journey.multiple_authenticated_joins.each_authenticated", errors)
        drain = mapping(journey.get("drain"), "journey.drain", errors)
        if drain is not None:
            passed(drain.get("status"), "journey.drain.status", errors)
            passed(drain.get("no_new_placement"), "journey.drain.no_new_placement", errors)
            passed(drain.get("blockers_observed"), "journey.drain.blockers_observed", errors)
            if drain.get("evacuation_claimed") is not False:
                fail(errors, "journey.drain.evacuation_claimed must be false")
        projections = mapping(journey.get("projections_convergent"), "journey.projections_convergent", errors)
        if projections is not None:
            # Native and OpenStack projections are mandatory P15.7 evidence.
            # Araf is an external, optional consumer and is deliberately not a
            # TestLab or P15 dependency.  Its state is recorded honestly, but
            # it must never be allowed to manufacture mandatory convergence.
            for name in ("native", "openstack"):
                passed(projections.get(name), f"journey.projections_convergent.{name}", errors)
            araf = mapping(projections.get("araf"), "journey.projections_convergent.araf", errors)
            if araf is not None:
                if araf.get("required") is not False:
                    fail(errors, "journey.projections_convergent.araf.required must be false")
                if araf.get("status") not in {"passed", "reachable", "not_configured", "not_applicable", "unavailable"}:
                    fail(errors, "journey.projections_convergent.araf.status is invalid")
                if not isinstance(araf.get("reason"), str) or not araf["reason"].strip():
                    fail(errors, "journey.projections_convergent.araf.reason must be explicit")

    security = mapping(root.get("security_negatives"), "security_negatives", errors)
    if security is not None:
        for name in (
            "unauthenticated_join_rejected",
            "replay_join_rejected",
            "cross_tenant_concealment",
            "foreign_state_preserved",
        ):
            passed(security.get(name), f"security_negatives.{name}", errors)

    recovery = mapping(root.get("restart_recovery"), "restart_recovery", errors)
    if recovery is not None:
        passed(recovery.get("status"), "restart_recovery.status", errors)
        passed(recovery.get("canonical_state_survived"), "restart_recovery.canonical_state_survived", errors)
        passed(recovery.get("postgres"), "restart_recovery.postgres", errors)
        passed(recovery.get("sqlite_parity"), "restart_recovery.sqlite_parity", errors)

    timing = mapping(root.get("bootstrap_timing"), "bootstrap_timing", errors)
    if timing is not None:
        passed(timing.get("measured"), "bootstrap_timing.measured", errors)
        passed(timing.get("excludes_preprovisioned_external_work"), "bootstrap_timing.excludes_preprovisioned_external_work", errors)
        if not isinstance(timing.get("sample_count"), int) or timing["sample_count"] < 1:
            fail(errors, "bootstrap_timing.sample_count must be positive")
        if not isinstance(timing.get("boundary"), str) or not timing["boundary"].strip():
            fail(errors, "bootstrap_timing.boundary must be explicit")
        if timing.get("claim_scope") != "profile-specific-measurement-only":
            fail(errors, "bootstrap_timing.claim_scope must remain profile-specific")

    leaks = mapping(root.get("leak_check"), "leak_check", errors)
    if leaks is not None:
        if leaks.get("status") != "passed":
            fail(errors, "leak_check.status must be passed")
        for key in ("owned_leaks", "owned_inconsistencies", "foreign_state_changes"):
            if leaks.get(key) != 0:
                fail(errors, f"leak_check.{key} must be zero")

    defects = mapping(root.get("defect_ledger"), "defect_ledger", errors)
    if defects is not None:
        if defects.get("status") != "passed":
            fail(errors, "defect_ledger.status must be passed")
        for key in ("blockers", "high", "medium"):
            if defects.get(key) != 0:
                fail(errors, f"defect_ledger.{key} must be zero")

    claims = mapping(root.get("claim_validation"), "claim_validation", errors)
    if claims is not None:
        if claims.get("status") != "passed":
            fail(errors, "claim_validation.status must be passed")
        sources = claims.get("sources")
        if not isinstance(sources, list):
            fail(errors, "claim_validation.sources must be a list")
            sources = []
        elif not all(isinstance(source, str) for source in sources):
            fail(errors, "claim_validation.sources must contain strings")
        if len(sources) != len(CLAIM_VALIDATION_SOURCES) or (
            all(isinstance(source, str) for source in sources)
            and set(sources) != CLAIM_VALIDATION_SOURCES
        ):
            fail(errors, "claim_validation.sources must name the six public claim inputs")
        if claims.get("unsupported_claims_preserved") is not True:
            fail(errors, "claim_validation.unsupported_claims_preserved must be true")
        claim_list = claims.get("claims")
        if not isinstance(claim_list, list):
            fail(errors, "claim_validation.claims must be a list")
            claim_list = []
        for claim in claim_list:
            if not isinstance(claim, str):
                fail(errors, "claim_validation.claims must contain strings")
            elif FORBIDDEN_CLAIMS.search(claim):
                fail(errors, f"unsupported broad claim present: {claim!r}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-profile")
    args = parser.parse_args()
    try:
        document = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"P15.7 evidence validation FAILED: {exc}", file=sys.stderr)
        return 1
    errors = validate(document, args.expected_source_sha, args.expected_profile)
    if errors:
        print("P15.7 evidence validation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("P15.7 protected real-host scale/composition evidence validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
