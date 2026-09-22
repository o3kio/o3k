#!/usr/bin/env python3
"""Small, secret-safe client for the PP.4 Core native campaign.

The campaign deliberately keeps authentication and JSON construction in one
typed helper.  It uses the documented native IAM password path to obtain a
project-scoped credential.  Tokens are only read/written through mode-0600
files; they are never command-line arguments or normal output.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class ClientError(RuntimeError):
    pass


def _private_file(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise ClientError(f"secret file is not private: {path}")


def _write_private(path: Path, value: str) -> None:
    _private_file(path)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.write("\n")
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _read_private(path: Path) -> str:
    _private_file(path)
    value = path.read_text(encoding="utf-8").rstrip("\n")
    if not value:
        raise ClientError(f"secret file is empty: {path}")
    return value


def _admin_env(path: Path) -> dict[str, str]:
    """Read only simple export assignments from the installer-owned file."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"export ([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match:
            continue
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] == "'":
            value = value[1:-1].replace("'\\''", "'")
        elif len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        values[match.group(1)] = value
    required = ("OS_AUTH_URL", "OS_USERNAME", "OS_PASSWORD", "OS_PROJECT_NAME")
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise ClientError(f"admin-openrc is missing required settings: {','.join(missing)}")
    return values


def _json_request(
    url: str,
    method: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    data = None
    request_headers = dict(headers)
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        body = error.read()
        # The body is useful to the caller but the exception must not include
        # request headers or payloads, which could contain credentials.
        return error.code, dict(error.headers.items()), body
    except (urllib.error.URLError, TimeoutError) as error:
        raise ClientError(f"HTTP request failed: {type(error).__name__}") from error


def _json_body(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise ClientError("response was not JSON") from error
    if not isinstance(value, dict):
        raise ClientError("response JSON was not an object")
    return value


def issue_native_token(admin_openrc: Path, token_file: Path, base_url: str | None = None) -> dict[str, Any]:
    env = _admin_env(admin_openrc)
    auth_url = (base_url or env["OS_AUTH_URL"]).rstrip("/")
    parsed = urllib.parse.urlsplit(auth_url)
    if not parsed.scheme or not parsed.netloc:
        raise ClientError("OS_AUTH_URL is not an absolute URL")
    native_root = f"{parsed.scheme}://{parsed.netloc}"
    # The installer publishes a Keystone-compatible, project-scoped credential
    # path.  Use it to authenticate the operator by name/domain first, then
    # exchange that scoped token at the native identity adapter.  This avoids
    # guessing a durable IAM user UUID from the human-readable admin-openrc
    # name while retaining the native API's own bearer contract.
    keystone_status, keystone_headers, keystone_body = _json_request(
        f"{auth_url}/auth/tokens",
        "POST",
        {"Accept": "application/json"},
        {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": env["OS_USERNAME"],
                            "domain": {"name": env.get("OS_USER_DOMAIN_NAME", "Default")},
                            "password": env["OS_PASSWORD"],
                        }
                    },
                },
                "scope": {
                    "project": {
                        "name": env["OS_PROJECT_NAME"],
                        "domain": {"name": env.get("OS_PROJECT_DOMAIN_NAME", "Default")},
                    }
                },
            }
        },
    )
    if keystone_status not in (200, 201):
        raise ClientError(f"project credential issuance returned HTTP {keystone_status}")
    subject_token = next(
        (value for key, value in keystone_headers.items() if key.lower() == "x-subject-token"),
        None,
    )
    if not subject_token:
        raise ClientError("project credential response did not contain X-Subject-Token")
    # The native password DTO deliberately requires a durable IAM user ID.
    # Keystone's public response is the supported way to resolve the
    # human-readable openrc name without inspecting O3K's store.
    try:
        keystone_json = _json_body(keystone_body)
        user_id = keystone_json["token"]["user"]["id"]
        project_id = keystone_json["token"]["project"]["id"]
    except (ClientError, KeyError, TypeError):
        user_id = project_id = None
    if not isinstance(user_id, str) or not user_id:
        raise ClientError("project credential response did not contain user.id")
    if not isinstance(project_id, str) or not project_id:
        raise ClientError("project credential response did not contain project.id")
    native_status, _, native_body = _json_request(
        f"{native_root}/o3k/v1/identity/tokens",
        "POST",
        {"Accept": "application/json"},
        {
            "auth": {
                "method": "password",
                "password": {"user_id": user_id, "password": env["OS_PASSWORD"]},
                "project_id": project_id,
            }
        },
    )
    if native_status not in (200, 201):
        raise ClientError(f"native token issuance returned HTTP {native_status}")
    response = _json_body(native_body)
    token = response.get("token", {}).get("id")
    if not isinstance(token, str) or not token:
        raise ClientError("native token response did not contain token.id")
    _write_private(token_file, token)
    return {
        "project_id": response.get("token", {}).get("project", {}).get("id"),
        "expires_at": response.get("token", {}).get("expires_at"),
    }


def request(
    token_file: Path,
    url: str,
    method: str,
    request_file: Path | None = None,
    output_file: Path | None = None,
    expected: set[int] | None = None,
    idempotency_key: str | None = None,
) -> tuple[int, dict[str, str]]:
    token = _read_private(token_file)
    payload = None
    if request_file is not None:
        payload = _json_body(request_file.read_bytes())
    status, headers, body = _json_request(
        url,
        method,
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            **({"Idempotency-Key": idempotency_key} if idempotency_key else {}),
        },
        payload,
    )
    if output_file is not None:
        output_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        output_file.write_bytes(body)
        os.chmod(output_file, 0o600)
    if expected is not None and status not in expected:
        raise ClientError(f"native request returned HTTP {status}")
    return status, _json_body(body) if body else {}


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    auth = sub.add_parser("auth")
    auth.add_argument("--admin-openrc", type=Path, required=True)
    auth.add_argument("--token-file", type=Path, required=True)
    auth.add_argument("--base-url")
    call = sub.add_parser("request")
    call.add_argument("--token-file", type=Path, required=True)
    call.add_argument("--url", required=True)
    call.add_argument("--method", choices=("GET", "POST", "PUT", "DELETE"), required=True)
    call.add_argument("--request-file", type=Path)
    call.add_argument("--output-file", type=Path)
    call.add_argument("--expect", action="append", type=int)
    call.add_argument("--idempotency-key")
    args = parser.parse_args()
    try:
        if args.command == "auth":
            print(json.dumps(issue_native_token(args.admin_openrc, args.token_file, args.base_url)))
        else:
            status, body = request(
                args.token_file,
                args.url,
                args.method,
                args.request_file,
                args.output_file,
                set(args.expect) if args.expect else None,
                args.idempotency_key,
            )
            print(json.dumps({"status": status, "body": body}, sort_keys=True))
    except ClientError as error:
        print(f"native campaign helper: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
