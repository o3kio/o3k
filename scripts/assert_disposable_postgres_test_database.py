#!/usr/bin/env python3
"""Fail closed before destructive PostgreSQL test database operations."""

from __future__ import annotations

import os
import re
import sys
from urllib.parse import unquote, urlsplit


def main() -> int:
    purpose = os.environ.get("O3K_TEST_DATABASE_PURPOSE")
    database_url = os.environ.get("O3K_DATABASE_URL", "")
    prefixes = {"workspace": "o3k_workspace_test_", "endpoint": "o3k_endpoint_test_", "p13": "o3k_p13_test_", "p137": "o3k_p137_"}
    if purpose not in prefixes:
        print("O3K_TEST_DATABASE_PURPOSE must identify a supported disposable test database", file=sys.stderr)
        return 2
    named_database = os.environ.get("O3K_TEST_DATABASE_NAME")
    if named_database and purpose == "p137":
        database = named_database
        valid_source = True
    elif named_database:
        print("O3K_TEST_DATABASE_NAME override is only valid for P13.7", file=sys.stderr)
        return 2
    else:
        parsed = urlsplit(database_url)
        database = unquote(parsed.path.lstrip("/"))
        valid_source = parsed.scheme in {"postgres", "postgresql"}
    suffix = database[len(prefixes[purpose]):] if database.startswith(prefixes[purpose]) else ""
    if not valid_source or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", suffix):
        print(f"refusing destructive PostgreSQL {purpose} reset for database {database!r}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
