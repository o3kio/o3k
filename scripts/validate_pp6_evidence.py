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
        r'"[A-Za-z0-9_]*(?:password|passwd|secret|token|api_?key|private_?key)"\s*:\s*"[^"]+"',
        re.IGNORECASE,
    ),
    # libpq keyword/value DSNs and environment assignments (password=, PGPASSWORD=).
    "password_assignment": re.compile(
        r"(?:password|passwd)\s*[=:]\s*[^\s\"',}\]]", re.IGNORECASE
    ),
    "bearer_token": re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
}

# Per-lane field mapping. Paths are dotted keys into the lane artifact.
CASES = {
    "postgres-outage": {
        "harness": "harness.test",
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
        "harness": "harness.test",
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
        "harness": "test",
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
        "harness": "harness.test",
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
        "harness": "harness.path",
        "lane_schema": None,
        "disposition": ("disposition", "passed"),
        # The lane records only the commit it executed; CI passes the
        # change head explicitly with --source-commit.
        "source": None,
        "execution": "source.commit",
        "backend": ("postgresql", "environment.postgres_server_version"),
        "profile": "profile",
        "fixture": ["environment.postgres_image_id", "environment.wal_filesystem"],
        "foreign_state": ("object", "foreign_state"),
    },
    "sqlite-disk-pressure": {
        "harness": "test",
        "lane_schema": None,
        "disposition": ("disposition", "PASS"),
        "source": "source_commit",
        "execution": "execution_commit",
        "backend": ("sqlite", "sqlite_version"),
        "profile": "profile",
        "fixture": ["filesystem_type", "filesystem_size_bytes", "evidence_tier"],
        "foreign_state": ("object", "foreign_state"),
    },
    "sqlite-memory-pressure": {
        "harness": "harness",
        "lane_schema": ("schema", "o3k.pp6.sqlite-memory-pressure.v1"),
        "disposition": ("disposition", "PASS"),
        "source": "source_commit",
        "execution": "execution_commit",
        "backend": ("sqlite", "sqlite_version"),
        "profile": "profile",
        "fixture": ["container_id", "image_ref", "image_id", "cgroup_memory_max", "oom_kill_count"],
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
    # Also scan with JSON string escapes undone, so JSON embedded in a string
    # value is checked like the outer document.
    candidates = (text, text.replace('\\"', '"'))
    found = [
        name
        for name, pattern in SECRET_PATTERNS.items()
        if any(pattern.search(candidate) for candidate in candidates)
    ]
    if found:
        raise EvidenceError(f"artifact contains credential-shaped content: {', '.join(found)}")


def build_envelope(
    case: str, text: str, artifact_name: str, source_commit: str | None = None
) -> dict:
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
    actual_disposition = lookup(document, key)
    if case == "sqlite-memory-pressure" and actual_disposition in {"NOT_RUN", "INFRASTRUCTURE_BLOCKED"}:
        source_tree = required(document, "source_tree")
        execution_tree = required(document, "execution_tree")
        if not isinstance(source_tree, str) or not COMMIT.match(source_tree) or not isinstance(execution_tree, str) or not COMMIT.match(execution_tree):
            raise EvidenceError("NOT_RUN source/execution trees must be full commit ids")
        scan_secrets(text)
        return {
            "schema": SCHEMA, "issue": ISSUE, "case": case,
            "disposition": actual_disposition, "reason": required(document, "reason"),
            "source": {"commit": commit(document, "source_commit"), "tree": source_tree, "execution_commit": commit(document, "execution_commit"), "execution_tree": execution_tree},
            "harness": required(document, "harness"), "profile": required(document, "profile"),
            "foreign_state": foreign_state(document, spec["foreign_state"]),
            "secret_scan": {"status": "passed", "scope": "full artifact text", "patterns": sorted(SECRET_PATTERNS)},
        }
    if actual_disposition != passing:
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
    if case == "sqlite-memory-pressure":
        image_ref = fixture["image_ref"]
        if not isinstance(image_ref, str) or not re.fullmatch(r"rust@sha256:[0-9a-f]{64}", image_ref):
            raise EvidenceError("image_ref must identify the immutable official Rust image digest")
    harness = required(document, spec["harness"])
    if not isinstance(harness, str):
        raise EvidenceError(f"{spec['harness']} must be a string")
    if spec["source"] is None:
        if source_commit is None or not COMMIT.match(source_commit):
            raise EvidenceError(f"{case} needs --source-commit with the change head commit")
        change_commit = source_commit
    else:
        if source_commit is not None:
            raise EvidenceError(f"{case} records its own source commit; drop --source-commit")
        change_commit = commit(document, spec["source"])
    scan_secrets(text)
    return {
        "schema": SCHEMA,
        "issue": ISSUE,
        "case": case,
        "disposition": "PASS",
        "source": {
            "commit": change_commit,
            "execution_commit": commit(document, spec["execution"]) if spec["execution"] else None,
        },
        "harness": harness,
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
    if spec["source"]:
        _set(document, spec["source"], "a" * 40)
    _set(document, spec["harness"], "harness-identity")
    if spec["execution"]:
        _set(document, spec["execution"], "b" * 40)
    backend_kind, version_path = spec["backend"]
    _set(document, version_path, "16.4" if backend_kind == "postgresql" else "3.46.0")
    _set(document, spec["profile"], PROFILE_BY_BACKEND[backend_kind])
    for path in spec["fixture"]:
        _set(document, path, "fixture-value")
    if case == "sqlite-memory-pressure":
        _set(document, "image_ref", "rust@sha256:" + "a" * 64)
    kind, path = spec["foreign_state"]
    if kind == "tested_flag":
        _set(document, path, False)
    else:
        _set(document, path, {"status": "not_exercised", "reason": "store-only lane"})
    return document


def self_test() -> None:
    for case, spec in CASES.items():
        good = _sample(case)
        override = None if spec["source"] else "c" * 40
        envelope = build_envelope(case, json.dumps(good), "sample.json", override)
        assert envelope["case"] == case and envelope["disposition"] == "PASS", case
        assert envelope["source"]["commit"] == (override or "a" * 40), case

        def mutated(change):
            document = json.loads(json.dumps(good))
            change(document)
            return json.dumps(document)

        commit_path = spec["source"] or spec["execution"]
        failing = {
            "failed disposition": mutated(lambda d: _set(d, spec["disposition"][0], "FAIL")),
            "short commit": mutated(lambda d: _set(d, commit_path, "abc")),
            "missing harness": mutated(lambda d: _set(d, spec["harness"], "")),
            "wrong profile": mutated(lambda d: _set(d, spec["profile"], "SPEC-0024 bounded")),
            "missing fixture": mutated(lambda d: _set(d, spec["fixture"][0], "")),
            "credential url": mutated(
                lambda d: _set(d, spec["fixture"][0], "postgres://o3k:hunter2@db/o3k")
            ),
            "private key": mutated(
                lambda d: _set(d, spec["fixture"][0], "-----BEGIN PRIVATE KEY-----")
            ),
            "secret field": mutated(lambda d: d.__setitem__("db_password", "hunter2")),
            "camel secret field": mutated(lambda d: d.__setitem__("dbPassword", "hunter2")),
            "libpq dsn": mutated(
                lambda d: _set(d, spec["fixture"][0], "host=127.0.0.1 user=o3k password=hunter2")
            ),
            "pgpassword": mutated(lambda d: _set(d, spec["fixture"][0], "PGPASSWORD=hunter2")),
            "escaped json secret": mutated(
                lambda d: _set(d, spec["fixture"][0], json.dumps({"password": "hunter2"}))
            ),
        }
        if case == "sqlite-memory-pressure":
            failing["mutable image tag"] = mutated(lambda d: _set(d, "image_ref", "rust:1.97.1-bookworm"))
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
                build_envelope(case, text, "sample.json", override)
            except EvidenceError:
                continue
            raise AssertionError(f"{case}: {label} was accepted")
    not_run = _sample("sqlite-memory-pressure")
    not_run.update({"disposition": "NOT_RUN", "reason": "capability unavailable", "source_tree": "a" * 40, "execution_tree": "b" * 40})
    assert build_envelope("sqlite-memory-pressure", json.dumps(not_run), "not-run.json")["disposition"] == "NOT_RUN"
    not_run["disposition"] = "INFRASTRUCTURE_BLOCKED"
    assert build_envelope("sqlite-memory-pressure", json.dumps(not_run), "blocked.json")["disposition"] == "INFRASTRUCTURE_BLOCKED"
    for value in ("postgres://user:password@host/db", "-----BEGIN PRIVATE KEY-----"):
        bad = dict(not_run)
        bad["reason"] = value
        try:
            build_envelope("sqlite-memory-pressure", json.dumps(bad), "not-run.json")
        except EvidenceError:
            pass
        else:
            raise AssertionError("credential-bearing NOT_RUN was accepted")
    # Descriptive scan text and a postgres URL without a password are fine.
    scan_secrets('{"in_harness_secret_scan": "PASS (password assignments scanned)",'
                 ' "dsn_shape": "postgres://o3k@127.0.0.1/o3k",'
                 ' "artifact_secret_scan": {"status": "passed"}}')
    # --source-commit is required exactly when the lane does not record one.
    wal = json.dumps(_sample("postgres-wal-pressure"))
    for bad in (None, "short"):
        try:
            build_envelope("postgres-wal-pressure", wal, "x.json", bad)
        except EvidenceError:
            continue
        raise AssertionError(f"postgres-wal-pressure accepted source commit {bad!r}")
    try:
        build_envelope(
            "postgres-outage", json.dumps(_sample("postgres-outage")), "x.json", "c" * 40
        )
    except EvidenceError:
        pass
    else:
        raise AssertionError("an override was accepted for a lane that records its source")
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
    parser.add_argument(
        "--source-commit",
        help="change head commit, for lanes that record only the executed commit",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.case or not args.artifact:
        parser.error("--case and ARTIFACT are required")
    artifact = Path(args.artifact)
    try:
        envelope = build_envelope(
            args.case, artifact.read_text(encoding="utf-8"), artifact.name, args.source_commit
        )
    except (OSError, EvidenceError) as error:
        print(f"PP.6 evidence for {args.case}: FAIL: {error}", file=sys.stderr)
        return 1
    if args.envelope:
        Path(args.envelope).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(f"PP.6 evidence for {args.case}: {envelope['disposition']} ({artifact.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
