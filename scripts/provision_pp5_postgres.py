#!/usr/bin/env python3
"""Provision and verify the four isolated PostgreSQL databases used by PP.5.

The campaign database is deliberately separate from every destructive-test
database.  This script only operates on the exact run-scoped names recorded in
its manifest; it never scans or drops databases by prefix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path


PURPOSES = ("campaign", "workspace", "endpoint", "p13")
PREFIXES = {
    "campaign": "o3k_pp5_s5_",
    "workspace": "o3k_workspace_test_",
    "endpoint": "o3k_endpoint_test_",
    "p13": "o3k_p13_test_",
}
ENV_NAMES = {
    "campaign": "O3K_PP5_CAMPAIGN_DATABASE_URL",
    "workspace": "O3K_PP5_WORKSPACE_DATABASE_URL",
    "endpoint": "O3K_PP5_ENDPOINT_DATABASE_URL",
    "p13": "O3K_PP5_P13_DATABASE_URL",
}
SCHEMA = "o3k.pp5-postgres-purpose-map.v1"
SENTINEL_TABLE = "pp5_purpose_sentinel"


def die(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(2)


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def run_id() -> str:
    value = env("O3K_PP5_RUN_ID") or env("GITHUB_RUN_ID")
    if not value or not all(c.isalnum() or c in "-_" for c in value):
        die("O3K_PP5_RUN_ID/GITHUB_RUN_ID must be a non-empty run-safe identifier")
    return value


def source_sha() -> str:
    value = env("O3K_PP5_SOURCE_SHA") or env("TARGET_SHA") or env("GITHUB_SHA")
    if len(value) != 40 or any(c not in "0123456789abcdefABCDEF" for c in value):
        die("an exact 40-character source SHA is required")
    return value.lower()


def manifest_path() -> Path:
    root = Path(env("O3K_PP5_ARTIFACT_DIR", "target/real-host-workflow-artifacts"))
    root.mkdir(parents=True, exist_ok=True)
    return root / "pp5-postgres-purpose-map.json"


def env_file() -> Path:
    return Path(env("O3K_PP5_ENV_FILE", "target/pp5-postgres.env"))


def quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def admin_url() -> str:
    configured = env("O3K_PP5_POSTGRES_ADMIN_URL")
    if not configured:
        return ""
    parsed = urllib.parse.urlsplit(configured)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname:
        die("O3K_PP5_POSTGRES_ADMIN_URL must be a PostgreSQL URL")
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, "/postgres", parsed.query, parsed.fragment)
    )


def psql(sql: str, database_url: str = "") -> str:
    if database_url:
        command = ["psql", database_url, "-v", "ON_ERROR_STOP=1", "-Atqc", sql]
    else:
        command = ["sudo", "-n", "-u", "postgres", "psql", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-Atqc", sql]
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "")
        die(f"PostgreSQL command failed: {detail[-400:].strip()}")
    return result.stdout.strip()


def db_psql(sql: str, url: str) -> str:
    return psql(sql, url)


def atomic_write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_target(url: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "127.0.0.1"
    if host == "localhost":
        host = "127.0.0.1"
    port = parsed.port or 5432
    return host, port


def build_url(base: str, role: str, password: str, database: str) -> str:
    parsed = urllib.parse.urlsplit(base or "postgresql://127.0.0.1:5432/postgres")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 5432
    host_for_url = f"[{host}]" if ":" in host and not host.startswith("[") else host
    userinfo = f"{urllib.parse.quote(role, safe='')}:{urllib.parse.quote(password, safe='')}"
    return urllib.parse.urlunsplit(
        (parsed.scheme or "postgresql", f"{userinfo}@{host_for_url}:{port}", f"/{database}", parsed.query, parsed.fragment)
    )


def expected_names(run: str) -> dict[str, str]:
    names = {purpose: f"{prefix}{run}" for purpose, prefix in PREFIXES.items()}
    if len(set(names.values())) != len(names):
        die("database purpose names are not distinct")
    return names


def validate_names(names: dict[str, str], run: str) -> None:
    if set(names) != set(PURPOSES) or len(set(names.values())) != 4:
        die("database purpose map is incomplete or names are not distinct")
    for purpose, name in names.items():
        if not name.startswith(PREFIXES[purpose]) or not name.endswith(run):
            die(f"database {purpose} has an invalid run-owned name")


def provision() -> None:
    run = run_id()
    sha = source_sha()
    names = expected_names(run)
    admin = admin_url()
    role = f"o3k_pp5_{run.replace('-', '_')}"
    if len(role) > 63:
        role = role[:63]
    password = secrets.token_urlsafe(32)
    for name in names.values():
        if psql(f"SELECT 1 FROM pg_database WHERE datname={quote_literal(name)}", admin):
            die(f"refusing to reuse existing run database {name}")
    if psql(f"SELECT 1 FROM pg_roles WHERE rolname={quote_literal(role)}", admin):
        die(f"refusing to reuse existing run role {role}")
    base = admin or "postgresql://127.0.0.1:5432/postgres"
    host, port = parse_target(base)
    if host not in ("127.0.0.1", "::1"):
        die("PP.5 external PostgreSQL must be reachable through loopback for fault injection")
    script_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    manifest = {
        "artifact_type": "pp5-postgres-purpose-map",
        "schema": SCHEMA,
        "schema_version": 1,
        "run_id": run,
        "source_sha": sha,
        "harness_digest": script_digest,
        "server": {"host": host, "port": port, "external": True},
        "role": role,
        "sentinel": {"table": SENTINEL_TABLE, "id": 1},
        "databases": {
            purpose: {"name": names[purpose], "prefix": PREFIXES[purpose], "redacted": True}
            for purpose in PURPOSES
        },
        "all_distinct": True,
    }
    # Write the ownership ledger before the first mutation.  If a later
    # CREATE DATABASE or sentinel step fails, the always-cleanup phase still
    # has the exact names and role it may safely remove.
    atomic_write(manifest_path(), json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    psql(f"CREATE ROLE {quote_ident(role)} LOGIN PASSWORD {quote_literal(password)}", admin)
    for name in names.values():
        psql(f"CREATE DATABASE {quote_ident(name)} OWNER {quote_ident(role)}", admin)
    urls = {purpose: build_url(base, role, password, name) for purpose, name in names.items()}
    for purpose, url in urls.items():
        db_psql(
            "CREATE TABLE pp5_purpose_sentinel (id integer PRIMARY KEY, purpose text NOT NULL, run_id text NOT NULL, source_sha text NOT NULL);"
            f" INSERT INTO pp5_purpose_sentinel (id,purpose,run_id,source_sha) VALUES (1,{quote_literal(purpose)},{quote_literal(run)},{quote_literal(sha)});",
            url,
        )
    # Rewrite the same ledger after all sentinels are present so an observer
    # can distinguish a fully provisioned map from an interrupted one.
    manifest["provisioning"] = {"status": "completed", "finished_at": int(time.time())}
    atomic_write(manifest_path(), json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    lines = [
        f"O3K_PP5_RUN_ID={run}\n",
        f"O3K_PP5_SOURCE_SHA={sha}\n",
        f"O3K_PP5_POSTGRES_TARGET={host}:{port}\n",
        f"O3K_PP5_POSTGRES_ROLE={role}\n",
    ]
    for purpose in PURPOSES:
        lines.append(f"{ENV_NAMES[purpose]}={urls[purpose]}\n")
    atomic_write(env_file(), "".join(lines), 0o600)
    github_env = env("GITHUB_ENV")
    if github_env:
        with open(github_env, "a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line)
        for value in urls.values():
            print(f"::add-mask::{value}")
        print(f"::add-mask::{password}")
    print(f"provisioned PP.5 PostgreSQL purpose map run={run} databases={','.join(names.values())}")


def load_manifest() -> dict:
    path = manifest_path()
    if not path.is_file():
        die(f"missing PP.5 PostgreSQL manifest: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"invalid PP.5 PostgreSQL manifest: {exc}")
    if value.get("schema") != SCHEMA or value.get("schema_version") != 1:
        die("unsupported PP.5 PostgreSQL manifest schema")
    if value.get("run_id") != run_id() or value.get("source_sha") != source_sha():
        die("PP.5 PostgreSQL manifest run/source mismatch")
    names = {purpose: value.get("databases", {}).get(purpose, {}).get("name", "") for purpose in PURPOSES}
    validate_names(names, run_id())
    if value.get("all_distinct") is not True:
        die("PP.5 PostgreSQL manifest does not prove distinct databases")
    return value


def urls_from_env(manifest: dict) -> dict[str, str]:
    urls: dict[str, str] = {}
    for purpose in PURPOSES:
        value = env(ENV_NAMES[purpose])
        if not value:
            die(f"missing {ENV_NAMES[purpose]} for PP.5 verification")
        parsed = urllib.parse.urlsplit(value)
        actual = (parsed.path or "").lstrip("/")
        expected = manifest["databases"][purpose]["name"]
        if actual != expected:
            die(f"{purpose} database URL does not target its manifest database")
        urls[purpose] = value
    return urls


def verify() -> None:
    manifest = load_manifest()
    if manifest.get("provisioning", {}).get("status") != "completed":
        die("PP.5 PostgreSQL provisioning did not complete")
    urls = urls_from_env(manifest)
    run = manifest["run_id"]
    sha = manifest["source_sha"]
    for purpose, url in urls.items():
        row = db_psql(f"SELECT purpose,run_id,source_sha FROM {SENTINEL_TABLE} WHERE id=1", url)
        if row != f"{purpose}|{run}|{sha}":
            die(f"{purpose} database sentinel changed or is missing")
    print(f"verified PP.5 PostgreSQL purpose isolation run={run}")


def cleanup() -> None:
    manifest = load_manifest()
    names = {purpose: manifest["databases"][purpose]["name"] for purpose in PURPOSES}
    admin = admin_url()
    joined = ",".join(quote_literal(name) for name in names.values())
    psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ({joined}) AND pid <> pg_backend_pid()", admin)
    for name in names.values():
        psql(f"DROP DATABASE IF EXISTS {quote_ident(name)}", admin)
    role = manifest["role"]
    psql(f"DROP ROLE IF EXISTS {quote_ident(role)}", admin)
    manifest["cleanup"] = {"status": "completed", "finished_at": int(time.time())}
    atomic_write(manifest_path(), json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    try:
        env_file().unlink()
    except FileNotFoundError:
        pass
    print(f"cleaned PP.5 PostgreSQL purpose map run={manifest['run_id']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("provision", "verify", "cleanup"))
    args = parser.parse_args()
    {"provision": provision, "verify": verify, "cleanup": cleanup}[args.command]()


if __name__ == "__main__":
    main()
