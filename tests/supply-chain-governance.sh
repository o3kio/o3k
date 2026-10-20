#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT_DIR}/docs/supply-chain/advisory-exceptions.yaml"
DENY="${ROOT_DIR}/deny.toml"
WORKFLOW="${ROOT_DIR}/.github/workflows/ci.yml"

python3 - "${POLICY}" "${DENY}" "${WORKFLOW}" <<'PY'
import pathlib
import re
import sys

try:
    import yaml
except ImportError as error:
    raise SystemExit("tests/supply-chain-governance.sh requires Python PyYAML") from error


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping
)


def fail(message):
    raise AssertionError(message)


def mapping(value, path, keys):
    if type(value) is not dict:
        fail(f"{path}: expected mapping")
    actual = set(value)
    expected = set(keys)
    if actual != expected:
        fail(f"{path}: expected keys {sorted(expected)}, got {sorted(actual)}")
    return value


def string(value, path):
    if type(value) is not str or not value:
        fail(f"{path}: expected non-empty string")


policy_path, deny_path, workflow_path = map(pathlib.Path, sys.argv[1:])
try:
    policy = yaml.load(policy_path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
except (OSError, ValueError, yaml.YAMLError) as error:
    raise SystemExit(f"cannot parse {policy_path}: {error}") from error

policy = mapping(policy, "policy", ("schema_version", "advisory_database", "exceptions"))
if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
    fail("policy.schema_version must be 1")

database = mapping(
    policy["advisory_database"],
    "policy.advisory_database",
    ("repository", "commit", "fetch_mode"),
)
if database["repository"] != "https://github.com/RustSec/advisory-db.git":
    fail("policy.advisory_database.repository must be the RustSec advisory database")
if not re.fullmatch(r"[0-9a-f]{40}", database["commit"]):
    fail("policy.advisory_database.commit must be a 40-character lowercase commit")
if database["fetch_mode"] != "pinned":
    fail("policy.advisory_database.fetch_mode must be pinned")

exceptions = policy["exceptions"]
expected_exceptions = [
    {
        "id": "RUSTSEC-2023-0071",
        "package": "rsa",
        "affected_version": "0.9.10",
        "owner": "O3K maintainers",
        "rationale": (
            "Retained only in the lockfile through SQLx's optional MySQL support; "
            "this workspace enables SQLite only and cargo tree has no active RSA path."
        ),
        "review_trigger": "Reconsider if another SQLx database feature is enabled.",
    },
    {
        "id": "RUSTSEC-2026-0381",
        "package": "webpki-roots",
        "affected_version": "0.26.11",
        "owner": "O3K maintainers",
        "rationale": (
            "SQLx's webpki-roots 0.26.11 dependency is the upstream semver shim and "
            "re-exports webpki-roots 1.0.10. Cargo.lock resolves the certificate data "
            "to webpki-root-certs 1.0.10, which removes the affected root. The advisory "
            "range flags the shim package version even though the resolved certificate "
            "data is fixed."
        ),
        "review_trigger": (
            "Remove when SQLx no longer resolves the 0.26 semver shim or when its "
            "certificate-data resolution changes."
        ),
    },
]
if type(exceptions) is not list or len(exceptions) != len(expected_exceptions):
    fail("policy.exceptions must contain exactly the reviewed exceptions")
for index, expected in enumerate(expected_exceptions):
    exception = mapping(
        exceptions[index],
        f"policy.exceptions[{index}]",
        ("id", "package", "affected_version", "owner", "rationale", "review_trigger"),
    )
    for key, value in expected.items():
        string(exception[key], f"policy.exceptions[{index}].{key}")
        if exception[key] != value:
            fail(f"policy.exceptions[{index}].{key} does not match the documented exception")

deny = deny_path.read_text(encoding="utf-8")
deny_ids = re.findall(r'(?m)^\s*id\s*=\s*"([A-Z0-9-]+)"\s*,?\s*$', deny)
expected_ids = {exception["id"] for exception in expected_exceptions[1:]}
if set(deny_ids) != expected_ids or len(deny_ids) != len(expected_ids):
    fail("deny.toml advisory ignores must exactly match reviewed exceptions")

workflow = workflow_path.read_text(encoding="utf-8")
if workflow.count(database["commit"]) != 1:
    fail("CI must contain exactly one occurrence of the pinned advisory DB commit")
for advisory_id in (exception["id"] for exception in expected_exceptions):
    if workflow.count(f"--ignore {advisory_id}") != 1:
        fail(f"CI must ignore exactly one machine-readable exception for {advisory_id}")
if workflow.count("cargo audit") != 1:
    fail("CI must contain exactly one cargo audit invocation")
audit_line = next(line for line in workflow.splitlines() if "cargo audit" in line)
for required in ('--db "${advisory_db}"', "--no-fetch", "--stale"):
    if required not in audit_line:
        fail(f"cargo audit invocation is missing {required}")
for advisory_id in (exception["id"] for exception in expected_exceptions):
    if f"--ignore {advisory_id}" not in audit_line:
        fail(f"cargo audit invocation is missing --ignore {advisory_id}")

print("supply-chain advisory governance passed")
PY
