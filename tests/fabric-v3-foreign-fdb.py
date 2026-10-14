#!/usr/bin/env python3
"""Compare foreign FDB observations while excluding explicit run-owned devices."""
from __future__ import annotations

import argparse
from pathlib import Path


def normalized(path: Path, excluded: set[str]) -> list[str]:
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not any(f" dev {device} " in f" {line} " for device in excluded):
            rows.append(" ".join(line.split()))
    return sorted(rows)


def compare(before: Path, after: Path, excluded: set[str]) -> None:
    if not before.is_file() or not after.is_file():
        raise FileNotFoundError(f"missing FDB scope: {before} or {after}")
    if normalized(before, excluded) != normalized(after, excluded):
        raise AssertionError({"before": normalized(before, excluded), "after": normalized(after, excluded)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--owned-device", action="append", default=[])
    args = parser.parse_args()
    try:
        compare(args.before, args.after, set(args.owned_device))
    except (AssertionError, FileNotFoundError) as error:
        print(f"foreign FDB mismatch: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
