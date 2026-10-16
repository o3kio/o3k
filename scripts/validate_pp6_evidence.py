#!/usr/bin/env python3
"""Validate a #1089 PP.6 lane artifact and write a normalized evidence envelope.

Each PP.6 resource-pressure lane writes its own artifact format. This script
maps every lane's fields onto one envelope (`o3k.pp6.evidence.v1`) so that
each run is bound to the same facts: case, passing disposition, source and
execution commits, backend kind and version, product profile, fixture
identity and foreign-state disposition. It also scans the raw artifact text
for credential shapes. Any missing or invalid fact fails closed.

Usage:
    validate_pp6_evidence.py --case CASE ARTIFACT [--envelope OUT]
    validate_pp6_evidence.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

SCHEMA = "o3k.pp6.evidence.v1"
ISSUE = 1089
PROFILE_BY_BACKEND = {"postgresql": "o3k-small-edge-v1", "sqlite": "o3k-demo-v1"}
FOREIGN_STATUSES = {"not_exercised", "preserved"}
COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

# Credential shapes, not words: artifacts legitimately describe their scans.
SECRET_PATTERNS = {
    "url_with_password": re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@\"]+:[^@\s\"]+@", re.IGNORECASE),
    "private_key_pem": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "secret_valued_field": re.compile(
        r'"(?:[A-Za-z0-9]+_)*(?:password|passwd|secret|token|api_key|private_key)"\s*:\s*"[^"]+"',
        re.IGNORECASE,
    ),
    "bearer_token": re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
}

# Per-lane field mapping. Paths are dotted keys into the lane artifact.
CASES = {
    "postgres-outage": {
        "lane_schema": ("evidence_schema", "o3k.pp6.postgres-outage.v1"),
        "disposition": ("disposition", "PASS"),
        "source": "source.change_head_commit",
        "execution": "source.checkout_commit",
        "backend": ("postgresql", "harness.backend_version"),
        "profile": "harness.profile",
        "fixture": ["harness.backend_image", "fixture.container_id"],
        "foreign_state": ("tested_flag", "observed.foreign_state_mutation_tested"),
    },
    "postgres-resource-pressure": {
        "lane_schema": ("evidence_schema", "o3k.pp6.postgres-resource-pressure.v1"),
        "disposition": ("disposition", "PASS"),
        "source": "source.change_head_commit",
        "execution": "source.checkout_commit",
        "backend": ("postgresql", "harness.server_version"),
        "profile": "harness.profile",
        "fixture": ["harness.database", "harness.schema_name"],
        "foreign_state": ("object", "observations.foreign_state"),
    },
    "postgres-server-pressure": {
        "lane_schema": ("schema", "o3k.pp6.postgres-server-pressure.v1"),
        "disposition": ("disposition", "PASS"),
        "source": "source_head",
        "execution": "execution_head",
        "backend": ("postgresql", "server_version"),
        "profile": "profile",
        "fixture": ["harness", "container_parameters"],
        "foreign_state": ("object", "foreign_state"),
    },
    "postgres-tablespace-pressure": {
        "lane_schema": ("schema", "o3k.pp6.postgres-tablespace-pressure.v1"),
        "disposition": ("final_disposition", "PASS"),
        "source": "source_sha",
        "execution": "execution_sha",
        "backend": ("postgresql", "postgres_server_version"),
        "profile": "profile",
        "fixture": ["harness.evidence_tier", "tablespace"],
        "foreign_state": ("object", "foreign_state"),
    },
    "postgres-wal-pressure": {
        "lane_schema": None,
        "disposition": ("disposition", "passed"),
        "source": "source.commit",
        "execution": None,
        "backend": ("postgresql", "environment.postgres_server_version"),
        "profile": "profile",
        "fixture": ["environment.postgres_image_id", "environment.wal_filesystem"],
        "foreign_state": ("object", "foreign_state"),
    },
    "sqlite-disk-pressure": {
        "lane_schema": None,
        "disposition": ("disposition", "PASS"),
        "source": "source_commit",
        "execution": "execution_commit",
        "backend": ("sqlite", "sqlite_version"),
        "profile": "profile",
        "fixture": ["filesystem_type", "filesystem_size_bytes", "evidence_tier"],
        "foreign_state": ("object", "foreign_state"),
    },
}


class EvidenceError(ValueError):
    pass


_MISSING = object()


def lookup(document: object, path: str) -> object:
    value = document
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return _MISSING
        value = value[key]
    return value


def required(document: object, path: str) -> object:
    value = lookup(document, path)
    if value is _MISSING or value is None or value == "" or value == [] or value == {}:
        raise EvidenceError(f"missing required field: {path}")
    return value


def commit(document: object, path: str) -> str:
    value = required(document, path)
    if not isinstance(value, str) or not COMMIT.match(value):
        raise EvidenceError(f"{path} is not a full commit id")
    return value


def foreign_state(document: object, mapping: tuple[str, str]) -> dict:
    kind, path = mapping
    if kind == "tested_flag":
        if lookup(document, path) is not False:
            raise EvidenceError(f"{path} must be false for a store-only lane")
        return {
            "status": "not_exercised",
            "reason": "store-only lane invokes no provider or external-state operations",
        }
    value = required(document, path)
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must be an object with status and reason")
    status, reason = value.get("status"), value.get("reason")
    if status not in FOREIGN_STATUSES or not isinstance(reason, str) or not reason:
        raise EvidenceError(f"{path} needs status in {sorted(FOREIGN_STATUSES)} and a reason")
    return {"status": status, "reason": reason}


def scan_secrets(text: str) -> None:
    found = [name for name, pattern in SECRET_PATTERNS.items() if pattern.search(text)]
    if found:
        raise EvidenceError(f"artifact contains credential-shaped content: {', '.join(found)}")


def build_envelope(case: str, text: str, artifact_name: str) -> dict:
    if case not in CASES:
        raise EvidenceError(f"unknown case: {case}")
    spec = CASES[case]
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"artifact is not valid JSON: {error.msg}") from None
    if not isinstance(document, dict):
        raise EvidenceError("artifact must be a JSON object")
    if spec["lane_schema"] is not None:
        key, expected = spec["lane_schema"]
        if lookup(document, key) != expected:
            raise EvidenceError(f"{key} must be {expected}")
    key, passing = spec["disposition"]
    if lookup(document, key) != passing:
        raise EvidenceError(f"{key} is not the passing value {passing!r}")
    backend_kind, version_path = spec["backend"]
    version = required(document, version_path)
    if not isinstance(version, str):
        raise EvidenceError(f"{version_path} must be a string")
    profile = required(document, spec["profile"])
    if profile != PROFILE_BY_BACKEND[backend_kind]:
        raise EvidenceError(
            f"{spec['profile']} must be {PROFILE_BY_BACKEND[backend_kind]} for {backend_kind}"
        )
    fixture = {path: required(document, path) for path in spec["fixture"]}
    scan_secrets(text)
    return {
        "schema": SCHEMA,
        "issue": ISSUE,
        "case": case,
        "disposition": "PASS",
        "source": {
            "commit": commit(document, spec["source"]),
            "execution_commit": commit(document, spec["execution"]) if spec["execution"] else None,
        },
        "backend": {"kind": backend_kind, "version": version},
        "profile": profile,
        "fixture": fixture,
        "foreign_state": foreign_state(document, spec["foreign_state"]),
        "secret_scan": {
            "status": "passed",
            "scope": "full artifact text",
            "patterns": sorted(SECRET_PATTERNS),
        },
        "lane_artifact": {
            "name": artifact_name,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        },
    }


def _set(document: dict, path: str, value: object) -> None:
    keys = path.split(".")
    for key in keys[:-1]:
        document = document.setdefault(key, {})
    document[keys[-1]] = value


def _sample(case: str) -> dict:
    spec = CASES[case]
    document: dict = {}
    if spec["lane_schema"]:
        _set(document, *spec["lane_schema"])
    _set(document, *spec["disposition"])
    _set(document, spec["source"], "a" * 40)
    if spec["execution"]:
        _set(document, spec["execution"], "b" * 40)
    backend_kind, version_path = spec["backend"]
    _set(document, version_path, "16.4" if backend_kind == "postgresql" else "3.46.0")
    _set(document, spec["profile"], PROFILE_BY_BACKEND[backend_kind])
    for path in spec["fixture"]:
        _set(document, path, "fixture-value")
    kind, path = spec["foreign_state"]
    if kind == "tested_flag":
        _set(document, path, False)
    else:
        _set(document, path, {"status": "not_exercised", "reason": "store-only lane"})
    return document


def self_test() -> None:
    for case, spec in CASES.items():
        good = _sample(case)
        envelope = build_envelope(case, json.dumps(good), "sample.json")
        assert envelope["case"] == case and envelope["disposition"] == "PASS", case

        def mutated(change):
            document = json.loads(json.dumps(good))
            change(document)
            return json.dumps(document)

        failing = {
            "failed disposition": mutated(lambda d: _set(d, spec["disposition"][0], "FAIL")),
            "short commit": mutated(lambda d: _set(d, spec["source"], "abc")),
            "wrong profile": mutated(lambda d: _set(d, spec["profile"], "SPEC-0024 bounded")),
            "missing fixture": mutated(lambda d: _set(d, spec["fixture"][0], "")),
            "credential url": mutated(
                lambda d: _set(d, spec["fixture"][0], "postgres://o3k:hunter2@db/o3k")
            ),
            "private key": mutated(
                lambda d: _set(d, spec["fixture"][0], "-----BEGIN PRIVATE KEY-----")
            ),
            "secret field": mutated(lambda d: d.__setitem__("db_password", "hunter2")),
        }
        if spec["foreign_state"][0] == "object":
            failing["foreign state claim"] = mutated(
                lambda d: _set(d, spec["foreign_state"][1], "untouched")
            )
        else:
            failing["foreign state tested"] = mutated(
                lambda d: _set(d, spec["foreign_state"][1], True)
            )
        for label, text in failing.items():
            try:
                build_envelope(case, text, "sample.json")
            except EvidenceError:
                continue
            raise AssertionError(f"{case}: {label} was accepted")
    # Descriptive scan text and a postgres URL without a password are fine.
    scan_secrets('{"in_harness_secret_scan": "PASS (password assignments scanned)",'
                 ' "dsn_shape": "postgres://o3k@127.0.0.1/o3k"}')
    try:
        build_envelope("unknown-case", "{}", "x.json")
    except EvidenceError:
        pass
    else:
        raise AssertionError("unknown case was accepted")
    with tempfile.TemporaryDirectory() as directory:
        artifact = Path(directory) / "sample.json"
        artifact.write_text(json.dumps(_sample("sqlite-disk-pressure")), encoding="utf-8")
        envelope_path = Path(directory) / "sample.envelope.json"
        main(["--case", "sqlite-disk-pressure", str(artifact), "--envelope", str(envelope_path)])
        assert json.loads(envelope_path.read_text(encoding="utf-8"))["schema"] == SCHEMA
    print("validate_pp6_evidence self-test passed")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--case", choices=sorted(CASES))
    parser.add_argument("artifact", nargs="?")
    parser.add_argument("--envelope", help="write the normalized envelope here")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.case or not args.artifact:
        parser.error("--case and ARTIFACT are required")
    artifact = Path(args.artifact)
    try:
        envelope = build_envelope(args.case, artifact.read_text(encoding="utf-8"), artifact.name)
    except (OSError, EvidenceError) as error:
        print(f"PP.6 evidence for {args.case}: FAIL: {error}", file=sys.stderr)
        return 1
    if args.envelope:
        Path(args.envelope).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(f"PP.6 evidence for {args.case}: PASS ({artifact.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
