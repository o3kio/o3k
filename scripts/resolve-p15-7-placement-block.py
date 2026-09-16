#!/usr/bin/env python3
"""Resolve a placed compute host to its unique ready canonical block."""

import json
import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: resolve-p15-7-placement-block.py BLOCKS_JSON EXECUTION_IDENTITY", file=sys.stderr)
        return 2

    blocks_path = pathlib.Path(sys.argv[1])
    execution_identity = sys.argv[2]
    try:
        items = json.loads(blocks_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"cannot read canonical BuildingBlock list: {error}", file=sys.stderr)
        return 2
    if not isinstance(items, list):
        print("canonical BuildingBlock list has an invalid shape", file=sys.stderr)
        return 2

    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        block = item.get("block")
        if not isinstance(block, dict):
            continue
        providers = block.get("resource_provider_ids")
        if (
            block.get("execution_identity") == execution_identity
            and isinstance(providers, list)
            and execution_identity in providers
            and block.get("state") == "ready"
            and isinstance(block.get("id"), str)
            and block["id"]
        ):
            matches.append(block["id"])

    if len(matches) != 1:
        print("placement host does not map to one ready canonical BuildingBlock/provider", file=sys.stderr)
        return 1
    print(matches[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
