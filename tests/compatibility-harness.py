#!/usr/bin/env python3
"""Run public-HTTP OpenStack contract fixtures against a selected target.

The harness intentionally knows only HTTP paths, headers, JSON schemas, and
reviewed public sources. It does not import any target implementation.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import pathlib
import socketserver
import threading
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_PATH = pathlib.Path(
    os.environ.get(
        "O3K_COMPATIBILITY_FIXTURES",
        str(ROOT / "docs/compatibility/contract-fixtures.json"),
    )
)
INVENTORY_PATH = ROOT / "docs/compatibility/capability-inventory.json"
BASELINE_PATH = ROOT / "docs/specs/testlab-api-baseline.json"


def load_fixtures() -> dict[str, Any]:
    source = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    for client, version in source.get("client_versions", {}).items():
        source_url = source.get("client_sources", {}).get(client, "")
        if not version or not source_url.startswith("https://pypi.org/project/"):
            raise ValueError(f"client {client} lacks a pinned public source")
    inventory_ids = {entry["id"] for entry in inventory["operations"]}
    baseline_operations = {
        entry["id"]: entry for entry in baseline.get("operations", [])
    }
    required_ids = {
        operation_id
        for operation_id, operation in baseline_operations.items()
        if operation.get("status") == "required"
    }
    fixtures = source.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("contract fixtures must be a non-empty array")
    seen: set[str] = set()
    for fixture in fixtures:
        fixture_id = fixture.get("id")
        if fixture_id in seen:
            raise ValueError(f"duplicate fixture id: {fixture_id}")
        seen.add(fixture_id)
        if fixture_id not in inventory_ids:
            raise ValueError(f"fixture {fixture_id} is absent from capability inventory")
        if baseline_operations.get(fixture_id, {}).get("status") != "required":
            raise ValueError(f"fixture {fixture_id} is not required by the normative baseline")
        if fixture.get("method") not in {"DELETE", "GET", "POST", "PUT"}:
            raise ValueError(f"fixture {fixture_id} has invalid method")
        if not isinstance(fixture.get("path"), str) or not fixture["path"].startswith("/"):
            raise ValueError(f"fixture {fixture_id} has invalid path")
        if not fixture.get("official_sources") or any(
            not url.startswith("https://docs.openstack.org/") for url in fixture["official_sources"]
        ):
            raise ValueError(f"fixture {fixture_id} lacks an official OpenStack source")
    missing = sorted(required_ids - seen)
    if missing:
        raise ValueError(
            "contract fixtures do not cover every required baseline operation: "
            + ", ".join(missing)
        )
    return source


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name.lower(): "<redacted>" for name in sorted(headers)}


def response_schema(body: bytes) -> dict[str, Any]:
    if not body:
        return {"content_length": 0}
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        return {"content_length": len(body), "content_type": "non-json"}
    if isinstance(decoded, dict):
        return {"content_length": len(body), "top_level_keys": sorted(decoded)}
    if isinstance(decoded, list):
        return {"content_length": len(body), "json_type": "array", "length": len(decoded)}
    return {"content_length": len(body), "json_type": type(decoded).__name__}


def make_request(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    token: str | None,
    raw_body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes, dict[str, Any]]:
    encoded = raw_body if raw_body is not None else (
        None if body is None else json.dumps(body, sort_keys=True).encode("utf-8")
    )
    headers = {"Accept": "application/json"}
    if raw_body is not None:
        headers["Content-Type"] = "application/octet-stream"
    elif encoded is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Auth-Token"] = token
    request = urllib.request.Request(base_url.rstrip("/") + path, data=encoded, headers=headers, method=method)
    request_record = {
        "method": method,
        "path": path,
        "headers": redact_headers(headers),
        "body": "<redacted>" if encoded is not None else None,
    }
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read(1_048_576)
            return response.status, dict(response.headers), payload, request_record
    except urllib.error.HTTPError as error:
        payload = error.read(1_048_576)
        return error.code, dict(error.headers), payload, request_record
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError(f"request failed for {method} {path}: {type(error).__name__}") from error


def check_json_keys(body: bytes, required: list[str]) -> list[str]:
    if not required:
        return []
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        return ["response is not JSON"]
    if not isinstance(decoded, dict):
        return ["response JSON is not an object"]
    return [f"missing JSON key: {key}" for key in required if key not in decoded]


def render(value: Any, project_id: str, keypair_name: str, variables: dict[str, str] | None = None) -> Any:
    replacements = {"project_id": project_id, "keypair_name": keypair_name}
    if variables:
        replacements.update(variables)
    if isinstance(value, str):
        return value.format(**replacements)
    if isinstance(value, dict):
        return {key: render(item, project_id, keypair_name, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, project_id, keypair_name, variables) for item in value]
    return value


def run_target(
    fixtures: list[dict[str, Any]],
    target: str,
    base_url: str,
    source_commit: str,
    project_id: str,
    keypair_name: str,
    token: str | None,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    variables: dict[str, str] = {
        "auth_password": os.environ.get("O3K_COMPATIBILITY_PASSWORD", "password")
    }
    for fixture in fixtures:
        try:
            path = render(fixture["path"], project_id, keypair_name, variables)
        except (KeyError, ValueError) as error:
            results.append(
                {
                    "fixture": fixture["id"],
                    "name": fixture["name"],
                    "source": fixture["official_sources"],
                    "request": {"method": fixture["method"], "path": fixture["path"]},
                    "status": "error",
                    "failures": [f"fixture variable resolution failed: {error}"],
                }
            )
            continue
        record: dict[str, Any] = {
            "fixture": fixture["id"],
            "name": fixture["name"],
            "source": fixture["official_sources"],
            "request": {"method": fixture["method"], "path": path},
        }
        try:
            status, headers, body, request_record = make_request(
                base_url,
                fixture["method"],
                path,
                render(fixture.get("request_json"), project_id, keypair_name, variables),
                token,
                fixture.get("request_bytes", "").encode("utf-8") if "request_bytes" in fixture else None,
            )
            record["request"] = request_record
            record["response"] = {
                "status": status,
                "headers": sorted(name.lower() for name in headers),
                "schema": response_schema(body),
            }
            failures = []
            if status not in fixture["expected_status"]:
                failures.append(f"expected status {fixture['expected_status']}, got {status}")
            failures.extend(check_json_keys(body, fixture.get("required_json_keys", [])))
            if not failures:
                try:
                    decoded = json.loads(body)
                except json.JSONDecodeError:
                    decoded = None
                captures = {
                    "image.collection_create": ("image_id", ("id",)),
                    "network.network_collection_create": ("network_id", ("network", "id")),
                    "network.subnet_collection_create": ("subnet_id", ("subnet", "id")),
                    "network.port_collection_create": ("port_id", ("port", "id")),
                    "compute.flavor_collection_create": ("flavor_id", ("flavor", "id")),
                    "compute.server_collection_create": ("server_id", ("server", "id")),
                }
                if fixture["id"] in captures and isinstance(decoded, dict):
                    name, path_parts = captures[fixture["id"]]
                    captured: Any = decoded
                    for part in path_parts:
                        captured = captured.get(part) if isinstance(captured, dict) else None
                    if isinstance(captured, str) and captured:
                        variables[name] = captured
            cleanup = fixture.get("cleanup")
            if cleanup:
                cleanup_path = render(cleanup["path"], project_id, keypair_name, variables)
                cleanup_status, cleanup_headers, cleanup_body, cleanup_request = make_request(
                    base_url, cleanup["method"], cleanup_path, None, token
                )
                record["cleanup"] = {
                    "request": cleanup_request,
                    "response": {
                        "status": cleanup_status,
                        "headers": sorted(name.lower() for name in cleanup_headers),
                        "schema": response_schema(cleanup_body),
                    },
                }
                if cleanup_status not in cleanup["expected_status"]:
                    failures.append(f"cleanup expected status {cleanup['expected_status']}, got {cleanup_status}")
            record["status"] = "failed" if failures else "passed"
            if failures:
                record["failures"] = failures
        except RuntimeError as error:
            record["status"] = "error"
            record["failures"] = [str(error)]
        except (KeyError, ValueError) as error:
            record["status"] = "error"
            record["failures"] = [f"fixture variable resolution failed: {error}"]
        results.append(record)
    return {
        "schema_version": 1,
        "target": target,
        "source_commit": source_commit,
        "portable": True,
        "results": results,
        "passed": all(result["status"] == "passed" for result in results),
    }


def write_junit(report: dict[str, Any], path: pathlib.Path) -> None:
    suite = ET.Element("testsuite", name=f"o3k-compatibility-{report['target']}")
    for result in report["results"]:
        case = ET.SubElement(suite, "testcase", name=result["name"])
        if result["status"] in {"failed", "error"}:
            ET.SubElement(case, result["status"], message="; ".join(result.get("failures", [])))
    path.write_text(ET.tostring(suite, encoding="unicode") + "\n", encoding="utf-8")


def compare_targets(
    fixtures: list[dict[str, Any]],
    targets: list[str],
    project_id: str,
    keypair_name: str,
    token: str | None,
) -> dict[str, Any]:
    reports = []
    for target_spec in targets:
        try:
            target_specifier, base_url = target_spec.split("=", 1)
        except ValueError as error:
            raise ValueError("--compare values must use target=base-url") from error
        target, _, source_commit = target_specifier.partition("@")
        if target not in {"rust", "go", "openstack"} or not base_url:
            raise ValueError(f"invalid comparison target: {target_spec}")
        reports.append(run_target(fixtures, target, base_url, source_commit or "unknown", project_id, keypair_name, token))
    by_fixture = {
        report["target"]: {result["fixture"]: result for result in report["results"]} for report in reports
    }
    differences = []
    for fixture in fixtures:
        observations = {
            target: (results[fixture["id"]]["status"], results[fixture["id"]].get("response", {}).get("schema"))
            for target, results in by_fixture.items()
        }
        if len(set(json.dumps(value, sort_keys=True) for value in observations.values())) > 1:
            differences.append({"fixture": fixture["id"], "observations": observations})
    return {
        "schema_version": 1,
        "comparison": {
            "targets": [report["target"] for report in reports],
            "agreement": not differences,
            "standards_compliant": all(report["passed"] for report in reports),
            "differences": differences,
        },
        "client_versions": json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))["client_versions"],
        "reports": reports,
    }


class SelfTestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/":
            self.send_json(300, {"versions": {"values": [{"id": "v3"}]}})
        elif self.path == "/v3":
            self.send_json(200, {"version": {"id": "v3"}})
        elif self.path == "/v3/auth/projects":
            self.send_json(200, {"projects": []})
        elif self.path == "/v2.0/networks":
            self.send_json(200, {"networks": []})
        elif self.path == "/v2.0/subnets":
            self.send_json(200, {"subnets": []})
        elif self.path == "/v2.0/ports":
            self.send_json(200, {"ports": []})
        elif self.path.endswith("/flavors") or self.path.endswith("/flavors/detail"):
            self.send_json(200, {"flavors": [{"id": "self-test-flavor"}]})
        elif self.path.endswith("/os-keypairs"):
            self.send_json(200, {"keypairs": []})
        elif "/os-keypairs/" in self.path:
            self.send_json(200, {"keypair": {"name": "contract-harness-key"}})
        elif self.path == "/v2/images":
            self.send_json(200, {"images": []})
        elif self.path.endswith("/file") and self.path.startswith("/v2/images/"):
            self.send_bytes(200, b"contract-image")
        elif self.path.startswith("/v2.0/networks/"):
            self.send_json(200, {"network": {"id": "network-id"}})
        elif self.path.startswith("/v2.0/subnets/"):
            self.send_json(200, {"subnet": {"id": "subnet-id"}})
        elif self.path.startswith("/v2.0/ports/"):
            self.send_json(200, {"port": {"id": "port-id"}})
        elif "/flavors/" in self.path:
            self.send_json(200, {"flavor": {"id": "flavor-id"}})
        elif self.path.endswith("/servers"):
            self.send_json(200, {"servers": []})
        elif "/servers/" in self.path and self.path.endswith("/action"):
            self.send_json(200, {})
        elif "/servers/" in self.path:
            self.send_json(200, {"server": {"id": "server-id"}})
        else:
            self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path.endswith("/os-keypairs"):
            self.send_json(200, {"keypair": {"name": "contract-harness-key"}})
        elif self.path == "/v3/auth/tokens":
            self.send_json(201, {"token": {"expires_at": "2099-01-01T00:00:00Z"}})
        elif self.path == "/v2/images":
            self.send_json(201, {"id": "image-id"})
        elif self.path == "/v2.0/networks":
            self.send_json(201, {"network": {"id": "network-id"}})
        elif self.path == "/v2.0/subnets":
            self.send_json(201, {"subnet": {"id": "subnet-id"}})
        elif self.path == "/v2.0/ports":
            self.send_json(201, {"port": {"id": "port-id"}})
        elif self.path.endswith("/action"):
            self.send_response(202)
            self.end_headers()
        elif self.path.endswith("/flavors"):
            self.send_json(201, {"flavor": {"id": "flavor-id"}})
        elif self.path.endswith("/servers"):
            self.send_json(202, {"server": {"id": "server-id"}})
        else:
            self.send_error(405)

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path.startswith("/v2/images/") and self.path.endswith("/file"):
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404)

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        if "/os-keypairs/" in self.path or "/flavors/" in self.path or "/servers/" in self.path or self.path.startswith("/v2.0/") or self.path.startswith("/v2/images/"):
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404)

    def send_json(self, status: int, value: dict[str, Any]) -> None:
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_bytes(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class FlavorMismatchHandler(SelfTestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path.endswith("/flavors") and not self.path.endswith("/flavors/detail"):
            self.send_error(405)
            return
        super().do_GET()


def self_test(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    with socketserver.TCPServer(("127.0.0.1", 0), SelfTestHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        report = run_target(
            fixtures,
            "self-test",
            f"http://127.0.0.1:{server.server_address[1]}",
            "self-test-source",
            "demo",
            "contract-harness-key",
            None,
        )
        server.shutdown()
    if not report["passed"]:
        raise RuntimeError(json.dumps(report, sort_keys=True))
    return report


def self_test_mismatch(fixtures: list[dict[str, Any]]) -> None:
    flavor_fixture = next(fixture for fixture in fixtures if fixture["name"] == "flavor-list")
    with socketserver.TCPServer(("127.0.0.1", 0), FlavorMismatchHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        report = run_target(
            [flavor_fixture],
            "self-test-mismatch",
            f"http://127.0.0.1:{server.server_address[1]}",
            "self-test-source",
            "demo",
            "contract-harness-key",
            None,
        )
        server.shutdown()
    if report["passed"] or "expected status" not in " ".join(report["results"][0].get("failures", [])):
        raise RuntimeError("method/path mismatch was not detected")


def self_test_compare(fixtures: list[dict[str, Any]]) -> None:
    with socketserver.TCPServer(("127.0.0.1", 0), SelfTestHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        report = compare_targets(
            fixtures,
            [f"rust={base_url}", f"go={base_url}"],
            "demo",
            "contract-harness-key",
            None,
        )
        server.shutdown()
    if not report["comparison"]["agreement"] or not report["comparison"]["standards_compliant"]:
        raise RuntimeError("comparison self-test did not report agreement")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-mismatch", action="store_true")
    parser.add_argument("--self-test-compare", action="store_true")
    parser.add_argument("--target", choices=["rust", "go", "openstack"], default="rust")
    parser.add_argument("--base-url")
    parser.add_argument("--source-commit", default="unknown")
    parser.add_argument("--project-id", default="test-project")
    parser.add_argument("--keypair-name", default="contract-harness-key")
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--compare", action="append", default=[])
    parser.add_argument("--json-out", type=pathlib.Path)
    parser.add_argument("--junit-out", type=pathlib.Path)
    args = parser.parse_args()
    try:
        source = load_fixtures()
        fixtures = source["fixtures"]
        if args.validate:
            print(f"validated {len(fixtures)} contract fixtures")
        if args.self_test:
            report = self_test(fixtures)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if args.junit_out:
                args.junit_out.parent.mkdir(parents=True, exist_ok=True)
                write_junit(report, args.junit_out)
            print("self-test passed")
        if args.self_test_mismatch:
            self_test_mismatch(fixtures)
            print("method/path mismatch self-test passed")
        if args.self_test_compare:
            self_test_compare(fixtures)
            print("comparison self-test passed")
        if args.base_url:
            selected = [fixture for fixture in fixtures if not args.cases or fixture["id"] in args.cases]
            if not selected:
                raise ValueError("no selected contract fixtures")
            report = run_target(
                selected,
                args.target,
                args.base_url,
                args.source_commit,
                args.project_id,
                args.keypair_name,
                os.environ.get("OS_AUTH_TOKEN"),
            )
            report["client_versions"] = source["client_versions"]
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if args.junit_out:
                args.junit_out.parent.mkdir(parents=True, exist_ok=True)
                write_junit(report, args.junit_out)
            print(json.dumps({"target": args.target, "passed": report["passed"], "count": len(selected)}))
            return 0 if report["passed"] else 1
        if args.compare:
            report = compare_targets(
                fixtures,
                args.compare,
                args.project_id,
                args.keypair_name,
                os.environ.get("OS_AUTH_TOKEN"),
            )
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(report["comparison"], sort_keys=True))
            return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"compatibility harness: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
