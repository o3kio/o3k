#!/usr/bin/env python3
"""Verify the installed public-release manifest without jq or shell eval."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_manifest.py VERSION SOURCE_SHA")
    document = json.loads(Path("/usr/local/share/o3k/release-manifest.json").read_text())
    expected_version = sys.argv[1].removeprefix("v")
    if document.get("version") != expected_version or document.get("source_commit") != sys.argv[2]:
        raise SystemExit("installed release manifest does not match the selected public release")
    print("public release manifest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
