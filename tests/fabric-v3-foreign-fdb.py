#!/usr/bin/env python3
"""Compare foreign FDB observations while excluding explicit run-owned devices."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def normalized(path: Path, excluded: set[str]) -> list[str]:
    text = path.read_text()
    parsed_json = False
    try:
        payload = json.loads(text)
        parsed_json = True
    except json.JSONDecodeError as error:
        if path.suffix == ".json":
            raise ValueError(f"malformed JSON observation: {path}") from error
        payload = None
    if parsed_json:
        if not isinstance(payload, list):
            raise ValueError(f"FDB observation is not a JSON list: {path}")
        def canonical(value):
            if isinstance(value, dict):
                return {key: canonical(item) for key, item in sorted(value.items())}
            if isinstance(value, list):
                values = [canonical(item) for item in value]
                return sorted(values, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
            return value
        rows = []
        for row in payload:
            if not isinstance(row, dict):
                raise ValueError(f"non-object FDB row: {path}")
            if row.get("ifname") in excluded or row.get("dev") in excluded:
                continue
            rows.append(json.dumps(canonical(row), sort_keys=True, separators=(",", ":")))
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
        if not args.before and not args.before_namespaces:
            raise ValueError("at least one comparison is required")
    except AssertionError as error:
        print(f"foreign FDB mismatch: {error}")
        return 1
    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"foreign FDB observation error: {error}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
