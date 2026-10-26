#!/usr/bin/env python3
"""Bind an extracted PP.5 release manifest to an independently pinned source."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def validate(path: Path, source_sha: str, source_tree: str, version: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        raise ValueError("expected source SHA is malformed")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_tree):
        raise ValueError("expected source tree is malformed")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+", version):
        raise ValueError("expected release version is malformed")
    if path.is_symlink() or not path.is_file():
        raise ValueError("release manifest must be a regular non-symlink file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("release manifest is unreadable") from error
    if not isinstance(document, dict):
        raise ValueError("release manifest root must be an object")
    if document.get("source_commit") != source_sha:
        raise ValueError("release manifest source_commit does not match candidate")
    if document.get("source_tree") != source_tree:
        raise ValueError("release manifest source_tree does not match candidate")
    if document.get("version") not in (version, f"v{version}"):
        raise ValueError("release manifest version does not match candidate")


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print("usage: validate_pp5_release_manifest.py MANIFEST SOURCE_SHA SOURCE_TREE VERSION", file=sys.stderr)
        return 2
    try:
        validate(Path(argv[1]), argv[2], argv[3], argv[4])
    except ValueError as error:
        print(f"PP.5 release manifest validation failed: {error}", file=sys.stderr)
        return 1
    print("PP.5 release manifest source identity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
