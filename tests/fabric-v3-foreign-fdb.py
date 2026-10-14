#!/usr/bin/env python3
"""Compare foreign FDB observations while excluding explicit run-owned devices."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def normalized(path: Path, excluded: set[str]) -> list[str]:
    text = path.read_text()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        if path.suffix == ".json":
            raise ValueError(f"malformed JSON observation: {path}") from error
        payload = None
    if isinstance(payload, list):
        rows = []
        for row in payload:
            if not isinstance(row, dict):
                raise ValueError(f"non-object FDB row: {path}")
            if row.get("ifname") in excluded or row.get("dev") in excluded:
                continue
            rows.append(json.dumps(row, sort_keys=True, separators=(",", ":")))
        return sorted(rows)
    rows = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    rows = [line for line in rows if not any(f" dev {device} " in f" {line} " for device in excluded)]
    return sorted(rows)


def compare(before: Path, after: Path, excluded: set[str]) -> None:
    if not before.is_file() or not after.is_file():
        raise FileNotFoundError(f"missing FDB scope: {before} or {after}")
    if normalized(before, excluded) != normalized(after, excluded):
        raise AssertionError({"before": normalized(before, excluded), "after": normalized(after, excluded)})


def namespaces(path: Path, excluded: set[str]) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return sorted(line.split()[0] for line in path.read_text().splitlines() if line.strip()
                  and line.split()[0] not in excluded)


def compare_namespaces(before: Path, after: Path, excluded: set[str]) -> None:
    old, new = namespaces(before, excluded), namespaces(after, excluded)
    if old != new:
        raise AssertionError({"before": old, "after": new})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--owned-device", action="append", default=[])
    parser.add_argument("--before-namespaces", type=Path)
    parser.add_argument("--after-namespaces", type=Path)
    parser.add_argument("--owned-namespace", action="append", default=[])
    args = parser.parse_args()
    try:
        if bool(args.before) != bool(args.after):
            raise ValueError("both FDB observations are required")
        if args.before:
            compare(args.before, args.after, set(args.owned_device))
        if bool(args.before_namespaces) != bool(args.after_namespaces):
            raise ValueError("both namespace observations are required")
        if args.before_namespaces:
            compare_namespaces(args.before_namespaces, args.after_namespaces, set(args.owned_namespace))
    except (AssertionError, FileNotFoundError, ValueError) as error:
        print(f"foreign FDB mismatch: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
