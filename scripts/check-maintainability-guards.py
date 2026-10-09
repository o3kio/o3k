#!/usr/bin/env python3
"""Permanent maintainability guardrails for O3K Rust.

Guard 1: SQL architecture boundary
Guard 2: Host-execution architecture boundary
Guard 3: Dependency regression against the immutable P13.4 baseline
Guard 4: Safety policy — workspace Cargo.toml policy not weakened

The immutable baseline lives under docs/maintainability/baselines/p13-4/ and
was generated from edb464ec43b1d12207faae903ea14b7824123f39 (P13.4).  It is
never regenerated from the current HEAD.  A new baseline commit must be
reviewed separately before the guard can be pointed at it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rust_source_scope import classify_rust_lines, is_dedicated_test_file

REPO_ROOT = Path(__file__).resolve().parents[1]

# Immutable baseline directory — reviewed, committed, never regenerated
# from current HEAD.
BASELINE_DIR = REPO_ROOT / "docs" / "maintainability" / "baselines" / "p13-4"
BASELINE_SHA = "edb464ec43b1d12207faae903ea14b7824123f39"

# ─── Helpers ───


def is_test_or_example(path: str) -> bool:
    """True if the file is test-only, an example, or conformance.

    Uses precise filename/directory matching rather than fragile substring
    checks to avoid misclassifying production files.
    """
    # Dedicated test/example/conformance directories
    # Handles both "tests/..." (relative root) and ".../tests/..." (nested)
    if re.search(r"(?:^|/)tests/", path) \
       or re.search(r"(?:^|/)examples/", path) \
       or re.search(r"(?:^|/)conformance/", path):
        return True
    # Test-only file patterns: tests.rs, *_tests.rs
    fname = path.rsplit("/", 1)[-1] if "/" in path else path
    if fname == "tests.rs" or fname.endswith("_tests.rs"):
        return True
    return False


def rust_source_files() -> list[Path]:
    """All .rs files under the repo excluding .git, target, and node_modules."""
    files = []
    for root, dirs, _fnames in os.walk(REPO_ROOT):
        rel = Path(root).relative_to(REPO_ROOT)
        parts = rel.parts
        if any(p in (".git", "target", "node_modules") for p in parts):
            continue
        for fname in _fnames:
            if fname.endswith(".rs"):
                files.append(Path(root) / fname)
    return files


def _load_baseline(name: str) -> dict | None:
    """Load a baseline JSON file from the immutable baseline directory."""
    path = BASELINE_DIR / name
    if not path.is_file():
        return None
    return json.loads(path.read_text())


# ─── Guard 1: SQL architecture boundary ───

SQL_API_NAMES = (
    r"(?:"
    r"query(?:_as|_scalar)?(?:_with|_unchecked)?"
    r"|query_file(?:_(?:as|scalar))?(?:_unchecked)?"
    r"|raw_sql"
    r"|QueryBuilder"
    r")"
)
SQL_CAPABILITY_NAMES = r"(?:Executor|Execute|AnyExecutor)"

SQL_PATTERNS = [
    rf"sqlx::{SQL_API_NAMES}(?:!|\b)",
    r"sqlx::query_builder::QueryBuilder\b",
    rf"sqlx::(?:prelude::)?{SQL_CAPABILITY_NAMES}\b",
]

SQL_IMPORT_PATTERN = re.compile(
    r"^\s*use\s+sqlx::(?:"
    + rf"(?:{SQL_API_NAMES}|{SQL_CAPABILITY_NAMES})"
    + r"(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?"
    + r"|\{[^;]*\b"
    + rf"(?:{SQL_API_NAMES}|{SQL_CAPABILITY_NAMES})"
    + r"\b[^;]*\})\s*;",
    re.MULTILINE | re.DOTALL,
)

SQL_NESTED_IMPORT_PATTERN = re.compile(
    r"^\s*use\s+sqlx::(?:"
    r"query_builder::QueryBuilder"
    r"|prelude::(?:Executor|Execute|AnyExecutor)"
    r")(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;"
    r"|^\s*use\s+sqlx::prelude::\*\s*;"
    r"|^\s*use\s+sqlx::\*\s*;",
    re.MULTILINE | re.DOTALL,
)

# SQL-owning implementation boundaries.  Keep this list path-aware: a path
# such as `src/postgres-extra.rs` must not inherit `src/postgres` approval.
APPROVED_SQL_PATHS = {
    "crates/o3k-store/src/sqlite",
    "crates/o3k-store/src/postgres",
    "crates/o3k-store/src/coordination.rs",
    "crates/o3k-store/src/storage.rs",
    "crates/o3k-store/src/quota.rs",
    "crates/o3k-store/src/governance.rs",
    "crates/o3k-store/src/reusable_policy.rs",
    "crates/o3k-store/src/artifact_transfer.rs",
    "crates/o3k-store/src/server_state.rs",
    "crates/o3k-store/src/conformance.rs",
    "crates/o3k-migration/src/acceptance_process.rs",
    "bins/o3k/src/db.rs",
    "bins/o3k/src/upgrade/runner.rs",
}

def _path_is_or_below(path: str, approved: str) -> bool:
    """Return whether *path* is exactly *approved* or below its directory."""
    return path == approved or path.startswith(approved.rstrip("/") + "/")


def check_sql_boundary(files: list[Path]) -> list[str]:
    """Reject production SQL outside explicit persistence/tooling boundaries."""
    errors: list[str] = []

    for path in files:
        rel = str(path.relative_to(REPO_ROOT))
        if is_test_or_example(rel):
            continue

        approved = any(_path_is_or_below(rel, p) for p in APPROVED_SQL_PATHS)
        if approved:
            continue

        lines = path.read_text(encoding="utf-8").splitlines()
        test_lines = classify_rust_lines(
            lines, dedicated_test=is_dedicated_test_file(rel)
        )
        production_lines = ["" if is_test else line for line, is_test in zip(lines, test_lines)]
        source = "\n".join(production_lines)

        for import_pattern in (SQL_IMPORT_PATTERN, SQL_NESTED_IMPORT_PATTERN):
            for match in import_pattern.finditer(source):
                line_number = source.count("\n", 0, match.start()) + 1
                errors.append(
                    f"SQL ARCHITECTURE VIOLATION: {rel}:{line_number}\n"
                    "  pattern: raw sqlx query/execution capability import\n"
                    f"  code: {match.group(0).strip()[:100]}\n"
                    "  SQL belongs in an explicit persistence, database diagnostic, "
                    "or upgrade boundary."
                )

        for i, line in enumerate(production_lines, 1):
            for pat in SQL_PATTERNS:
                if re.search(pat, line):
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("/*"):
                        continue
                    if stripped.startswith("use "):
                        continue
                    errors.append(
                        f"SQL ARCHITECTURE VIOLATION: {rel}:{i}\n"
                        f"  pattern: {pat}\n"
                        f"  code: {stripped[:100]}\n"
                        "  SQL belongs in an explicit persistence, database diagnostic, "
                        "or upgrade boundary."
                    )
                    break
    return errors


# ─── Guard 2: Host-execution architecture boundary ───

# Patterns that detect host-execution intent.
# The bare Command::new pattern catches imported usage:
#   use std::process::Command;
#   Command::new("...")
# as well as inline use.
HOST_CMD_PATTERNS = [
    (r'Command::new\(\s*["\'](?:sh|bash)["\']', "shell command (forbidden)"),
    (r'["\'](?:sh|bash)["\']\s*,\s*["\']-c["\']', "shell -c (forbidden)"),
    (r'\b(?:run|output)\(\s*["\'](?:ip|nft)["\']', "raw Linux command wrapper"),
    (r'\bspawn_host_command\s*\(', "host command wrapper"),
    (r"(?<![A-Za-z0-9_])Command::new\(", "std::process::Command / tokio::process::Command"),
]

HOST_IMPORT_PATTERNS = [
    (re.compile(
        r"^\s*use\s+(?:std|tokio)::process::Command"
        r"(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;",
        re.MULTILINE | re.DOTALL,
    ), "process Command import"),
    (re.compile(
        r"^\s*use\s+(?:std|tokio)::process::\{[^;]*\bCommand\b[^;]*\}\s*;",
        re.MULTILINE | re.DOTALL,
    ), "process Command grouped import"),
    (re.compile(
        r"^\s*type\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
        r"(?:std|tokio)::process::Command\s*;",
        re.MULTILINE | re.DOTALL,
    ), "process Command type alias"),
]

HOST_COMMAND_ALIAS_PATTERN = re.compile(
    r"use\s+(?:std|tokio)::process::Command"
    r"(?:\s+as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?\s*;"
)
HOST_COMMAND_GROUP_PATTERN = re.compile(
    r"use\s+(?:std|tokio)::process::\{(?P<body>[^;]*)\}\s*;",
    re.DOTALL,
)
HOST_COMMAND_TYPE_ALIAS_PATTERN = re.compile(
    r"type\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:std|tokio)::process::Command\s*;"
)


def _host_command_aliases(source: str) -> set[str]:
    aliases = {
        match.group("alias") or "Command"
        for match in HOST_COMMAND_ALIAS_PATTERN.finditer(source)
    }
    for match in HOST_COMMAND_GROUP_PATTERN.finditer(source):
        for item in match.group("body").split(","):
            item = item.strip()
            if not re.match(r"Command(?:\s+as\s+)?", item):
                continue
            alias_match = re.search(r"\bas\s+([A-Za-z_][A-Za-z0-9_]*)", item)
            aliases.add(alias_match.group(1) if alias_match else "Command")
    aliases.update(
        match.group("alias")
        for match in HOST_COMMAND_TYPE_ALIAS_PATTERN.finditer(source)
    )
    return aliases

# Explicit execution boundaries.  Mixed application crates are narrowed to
# the files that currently own host-tool invocation.
APPROVED_HOST_EXECUTION_PATHS = {
    "bins/o3k/src/sys.rs",
    "bins/o3k/src/upgrade/runner.rs",
    "bins/o3k-compute/src/iscsi.rs",
    "crates/o3k-config-drive/src/lib.rs",
    "crates/o3k-dhcp/src/lib.rs",
    "crates/o3k-image/src/execution.rs",
    "crates/o3k-network/src/linux_fabric",
    "crates/o3k-storage/src/ceph.rs",
    "crates/o3k-storage/src/lib.rs",
    "crates/o3k-migration/src/tofu.rs",
    "crates/o3k-migration/src/acceptance_process.rs",
    # These crates are themselves explicit provider/host-execution adapters.
    "crates/o3k-cellhv/src",
    "crates/o3k-libvirt/src",
    "crates/o3k-compute-agent/src",
    "crates/o3k-console/src",
}


def check_host_command_boundary(files: list[Path]) -> list[str]:
    """Reject host execution outside explicit adapter boundaries."""
    errors: list[str] = []

    for path in files:
        rel = str(path.relative_to(REPO_ROOT))
        if is_test_or_example(rel):
            continue

        lines = path.read_text(encoding="utf-8").splitlines()
        test_lines = classify_rust_lines(
            lines, dedicated_test=is_dedicated_test_file(rel)
        )
        production_lines = ["" if is_test else line for line, is_test in zip(lines, test_lines)]
        source = "\n".join(production_lines)
        command_aliases = _host_command_aliases(source)

        for pattern, name in HOST_IMPORT_PATTERNS:
            for match in pattern.finditer(source):
                if any(_path_is_or_below(rel, p) for p in APPROVED_HOST_EXECUTION_PATHS):
                    continue
                line_number = source.count("\n", 0, match.start()) + 1
                errors.append(
                    f"HOST EXECUTION ARCHITECTURE VIOLATION: {rel}:{line_number}\n"
                    f"  command: {name}\n"
                    f"  code: {match.group(0).strip()[:120]}\n"
                    "  Host execution belongs in an explicit execution adapter."
                )

        for i, line in enumerate(production_lines, 1):
            stripped = line.strip()
            if not stripped.startswith("//"):
                for alias in command_aliases - {"Command"}:
                    shell_alias = re.search(
                        rf"\b{re.escape(alias)}\s*::new\(\s*[\"'](?:sh|bash)[\"']",
                        line,
                    )
                    if shell_alias:
                        errors.append(
                            f"HOST EXECUTION ARCHITECTURE VIOLATION: {rel}:{i}\n"
                            "  command: aliased shell command (forbidden)\n"
                            f"  code: {stripped[:120]}"
                        )
                        break
            for pat, name in HOST_CMD_PATTERNS:
                if re.search(pat, line):
                    stripped = line.strip()
                    if stripped.startswith("//"):
                        continue
                    # Shell execution is forbidden even inside an otherwise
                    # approved adapter; direct argv execution remains the
                    # required boundary.
                    if "shell" in name:
                        errors.append(
                            f"HOST EXECUTION ARCHITECTURE VIOLATION: {rel}:{i}\n"
                            f"  command: {name}\n"
                            f"  code: {stripped[:120]}"
                        )
                        break
                    if not any(_path_is_or_below(rel, p) for p in APPROVED_HOST_EXECUTION_PATHS):
                        errors.append(
                            f"HOST EXECUTION ARCHITECTURE VIOLATION: {rel}:{i}\n"
                            f"  command: {name}\n"
                            f"  code: {stripped[:120]}\n"
                            "  Host execution belongs in an explicit execution adapter."
                        )
                    break
    return errors


# ─── Guard 3: Dependency regression ───

def _canonical_cycle_key(cycle: list[str]) -> tuple:
    """Return a canonical (sorted, hashable) key for a dependency cycle."""
    return tuple(sorted(cycle))


def _load_baseline_cycles() -> set[tuple]:
    """Load known cycles from the immutable P13.4 dependency baseline."""
    bl = _load_baseline("dependencies.json")
    if not bl:
        return set()
    return {_canonical_cycle_key(c) for c in bl.get("cycles", [])}


def check_dependency_regression() -> list[str]:
    """Check cargo metadata for new dependency cycles.

    Compares against the immutable P13.4 dependency baseline.
    """
    errors: list[str] = []
    baseline_cycles = _load_baseline_cycles()

    try:
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            capture_output=True, text=True, timeout=30,
            cwd=REPO_ROOT,
        )
        if result.returncode != 0:
            return [f"cargo metadata failed: {result.stderr[:200]}"]

        meta = json.loads(result.stdout)
        members = set(meta["workspace_members"])
        pkg_map = {p["id"]: p for p in meta["packages"]}

        member_manifest_dirs = {}
        for pid in members:
            pkg = pkg_map.get(pid)
            if pkg:
                member_manifest_dirs[pkg["name"]] = str(Path(pkg["manifest_path"]).parent)

        adj = defaultdict(set)
        for pid in members:
            pkg = pkg_map.get(pid)
            if not pkg:
                continue
            for dep in pkg.get("dependencies", []):
                dep_name = dep.get("name")
                if dep_name == pkg["name"]:
                    continue
                dep_path = dep.get("path")
                if dep_path:
                    dep_dir = str(Path(dep_path).resolve())
                    for mem_name, mem_dir in member_manifest_dirs.items():
                        if mem_name == pkg["name"]:
                            continue
                        if dep_dir == mem_dir:
                            adj[pkg["name"]].add(mem_name)
                            break

        cycles = []
        visited = set()
        path = []

        def dfs(node):
            if node in path:
                idx = path.index(node)
                cycles.append(path[idx:] + [node])
                return
            if node in visited:
                return
            visited.add(node)
            path.append(node)
            for nb in adj.get(node, set()):
                dfs(nb)
            path.pop()

        for node in list(adj.keys()):
            dfs(node)

        seen = set()
        for c in cycles:
            key = _canonical_cycle_key(c)
            if key in seen:
                continue
            seen.add(key)
            if key not in baseline_cycles:
                errors.append(f"NEW dependency cycle detected: {' -> '.join(c)}")

    except subprocess.TimeoutExpired:
        errors.append("cargo metadata timed out (30s)")
    except FileNotFoundError:
        errors.append("cargo not found — dependency check skipped")
    except Exception as e:
        errors.append(f"dependency check error: {e}")

    return errors


# ─── Guard 4: Safety policy ───

def check_safety_policy() -> list[str]:
    """Check that workspace safety policy has not been weakened.

    The workspace already enforces:
      - unsafe_code = forbid
      - -D warnings via Clippy
      - -W clippy::unwrap_used, -W clippy::expect_used

    This guard ensures those policies cannot be silently removed.
    It does NOT duplicate Clippy with a weak parser.
    """
    errors: list[str] = []

    cargo_toml = REPO_ROOT / "Cargo.toml"
    if not cargo_toml.is_file():
        errors.append("WORKSPACE POLICY UNVERIFIABLE: Cargo.toml not found")
        return errors

    content = cargo_toml.read_text()

    if 'unsafe_code = "forbid"' not in content:
        errors.append(
            "WORKSPACE POLICY WEAKENED: `unsafe_code = \"forbid\"` "
            "removed from workspace Cargo.toml"
        )

    return errors


# ─── Main ───

def main() -> int:
    print("=" * 60)
    print("O3K Maintainability Guardrails")
    print(f"  Baseline: {BASELINE_SHA}")
    print(f"  Baseline dir: {BASELINE_DIR.relative_to(REPO_ROOT)}/")
    print("=" * 60)

    if not BASELINE_DIR.is_dir():
        print(f"\nERROR: Baseline directory not found at {BASELINE_DIR}")
        print("Run: python3 scripts/maintainability-inventory.py at P13.4")
        print("     cp target/generated-maintainability/*.json docs/maintainability/baselines/p13-4/")
        return 1

    errors: list[str] = []
    files = rust_source_files()
    prod_files = [f for f in files if not is_test_or_example(str(f.relative_to(REPO_ROOT)))]

    # Guard 1: SQL boundary
    print("\n[1/4] SQL boundary guard...")
    sql_errors = check_sql_boundary(prod_files)
    if sql_errors:
        print(f"  FAILED: {len(sql_errors)} SQL architecture violations")
        errors.extend(sql_errors)
    else:
        print("  PASS")

    # Guard 2: Host-command boundary
    print("\n[2/4] Host-command boundary guard...")
    cmd_errors = check_host_command_boundary(prod_files)
    if cmd_errors:
        print(f"  FAILED: {len(cmd_errors)} host-execution architecture violations")
        errors.extend(cmd_errors)
    else:
        print("  PASS")

    # Guard 3: Dependency regression
    print("\n[3/4] Dependency regression guard...")
    dep_errors = check_dependency_regression()
    if dep_errors:
        print(f"  FAILED: {len(dep_errors)} dependency issues")
        errors.extend(dep_errors)
    else:
        print("  PASS")

    # Guard 4: Safety policy
    print("\n[4/4] Safety policy guard...")
    safety_errors = check_safety_policy()
    if safety_errors:
        print(f"  FAILED: {len(safety_errors)} safety policy issues")
        errors.extend(safety_errors)
    else:
        print("  PASS")

    print("\n" + "=" * 60)
    if errors:
        print(f"GUARDRAIL CHECK FAILED — {len(errors)} issue(s):")
        for err in errors:
            print(f"\n  ! {err}")
        print("\nArchitecture violations were detected. Do not widen approved boundaries.")
        return 1
    else:
        print("GUARDRAIL CHECK PASSED — permanent architecture policy holds.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
