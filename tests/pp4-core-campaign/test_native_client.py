#!/usr/bin/env python3
"""Self-tests for the PP.4 Core native campaign helper."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("native_client", Path(__file__).with_name("native_client.py"))
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_private_token_file_and_request_redaction() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        token_file = root / "private" / "token"
        request_file = root / "request.json"
        request_file.write_text(json.dumps({"spec": {"name": "quotes ' \" $HOME", "network_ids": ["id"]}}))
        request_file.chmod(0o600)
        MODULE._write_private(token_file, "opaque-secret")
        assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
        seen = {}

        def fake(url, method, headers, payload=None):
            seen.update({"url": url, "method": method, "headers": headers, "payload": payload})
            return 202, {}, b'{"operation_id":"op-1","resource_id":"srv-1"}'

        with patch.object(MODULE, "_json_request", side_effect=fake):
            status, body = MODULE.request(token_file, "http://127.0.0.1:1/o3k/v1/compute/servers", "POST", request_file, expected={202})
        assert status == 202
        assert body["operation_id"] == "op-1"
        assert seen["headers"]["Authorization"] == "Bearer opaque-secret"
        assert seen["payload"]["spec"]["network_ids"] == ["id"]


def test_admin_openrc_parser_does_not_need_shell_eval() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "admin-openrc"
        path.write_text(
            "export OS_AUTH_URL=http://127.0.0.1:18080/v3\n"
            "export OS_USERNAME=admin\n"
            "export OS_PASSWORD='has spaces; and $ signs'\n"
            "export OS_PROJECT_NAME=admin\n"
        )
        path.chmod(0o600)
        values = MODULE._admin_env(path)
        assert values["OS_PASSWORD"] == "has spaces; and $ signs"


def test_project_credential_is_exchanged_at_native_endpoint() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        openrc = root / "admin-openrc"
        openrc.write_text(
            "export OS_AUTH_URL=http://127.0.0.1:18080/v3\n"
            "export OS_USERNAME=admin\nexport OS_PASSWORD=pw\nexport OS_PROJECT_NAME=admin\n"
        )
        openrc.chmod(0o600)
        calls = []

        def fake(url, method, headers, payload=None):
            calls.append((url, method, payload))
            if url.endswith("/v3/auth/tokens"):
                return 201, {"X-Subject-Token": "keystone-token"}, b'{"token":{"user":{"id":"user-1"},"project":{"id":"project-1"}}}'
            return 201, {}, b'{"token":{"id":"native-token","project":{"id":"project-1"}}}'

        token_file = root / "token"
        with patch.object(MODULE, "_json_request", side_effect=fake):
            result = MODULE.issue_native_token(openrc, token_file)
        assert result["project_id"] == "project-1"
        assert token_file.read_text().strip() == "native-token"
        assert calls[0][0] == "http://127.0.0.1:18080/v3/auth/tokens"
        assert calls[0][2]["auth"]["identity"]["methods"] == ["password"]
        assert calls[1] == (
            "http://127.0.0.1:18080/o3k/v1/identity/tokens",
            "POST",
            {
                "auth": {
                    "method": "password",
                    "password": {"user_id": "user-1", "password": "pw"},
                    "project_id": "project-1",
                }
            },
        )


if __name__ == "__main__":
    test_private_token_file_and_request_redaction()
    test_admin_openrc_parser_does_not_need_shell_eval()
    test_project_credential_is_exchanged_at_native_endpoint()
    print("native campaign helper self-tests: PASS")
