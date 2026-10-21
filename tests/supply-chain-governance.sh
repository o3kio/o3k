#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT_DIR}/docs/supply-chain/advisory-exceptions.yaml"
DENY="${ROOT_DIR}/deny.toml"
WORKFLOW="${ROOT_DIR}/.github/workflows/ci.yml"
CARGO_LOCK="${O3K_SUPPLY_CHAIN_CARGO_LOCK:-${ROOT_DIR}/Cargo.lock}"

python3 - "${POLICY}" "${DENY}" "${WORKFLOW}" "${CARGO_LOCK}" <<'PY'
import pathlib
import re
import sys
import tomllib

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


policy_path, deny_path, workflow_path, cargo_lock_path = map(pathlib.Path, sys.argv[1:])
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
            "re-exports webpki-roots 1.0.10. RUSTSEC-2026-0381 marks 0.26.11 unaffected "
            "and requires the shim's resolved 1.x dependency to be at least 1.0.10. "
            "Cargo.lock pins that exact safe edge; the governance test rejects a stale "
            "or changed resolution."
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

try:
    cargo_lock = tomllib.loads(cargo_lock_path.read_text(encoding="utf-8"))
except (OSError, tomllib.TOMLDecodeError) as error:
    raise SystemExit(f"cannot parse {cargo_lock_path}: {error}") from error

# RUSTSEC-2026-0381 is ignored only for the reviewed SQLx compatibility shim.
# Keep its exception precondition tied to the actual lock graph so a dependency
# update cannot silently broaden this waiver to a new shim or payload version.
shim_exception = expected_exceptions[1]
shim_packages = [
    package
    for package in cargo_lock.get("package", [])
    if package.get("name") == shim_exception["package"]
    and package.get("version") == shim_exception["affected_version"]
]
if len(shim_packages) != 1:
    fail("RUSTSEC-2026-0381 exception requires exactly one locked webpki-roots 0.26.11 shim")
shim_package = shim_packages[0]
if "webpki-roots 1.0.10" not in shim_package.get("dependencies", []):
    fail("RUSTSEC-2026-0381 exception requires the shim to resolve to webpki-roots 1.0.10")
if not any(
    package.get("name") == "webpki-roots" and package.get("version") == "1.0.10"
    for package in cargo_lock.get("package", [])
):
    fail("RUSTSEC-2026-0381 exception requires the fixed webpki-roots 1.0.10 package")

deny = deny_path.read_text(encoding="utf-8")
deny_ids = re.findall(r'(?m)^\s*id\s*=\s*"([A-Z0-9-]+)"\s*,?\s*$', deny)
expected_ids = set()
if set(deny_ids) != expected_ids or len(deny_ids) != len(expected_ids):
    fail("deny.toml must not suppress advisories for unaffected locked packages")

workflow = workflow_path.read_text(encoding="utf-8")
if workflow.count(database["commit"]) != 1:
    fail("CI must contain exactly one occurrence of the pinned advisory DB commit")
if workflow.count("--ignore RUSTSEC-2023-0071") != 1:
    fail("CI must ignore exactly one machine-readable exception for RUSTSEC-2023-0071")
if "--ignore RUSTSEC-2026-0381" in workflow:
    fail("CI must not suppress RUSTSEC-2026-0381 for the unaffected locked package")
if workflow.count("cargo audit") != 1:
    fail("CI must contain exactly one cargo audit invocation")
audit_line = next(line for line in workflow.splitlines() if "cargo audit" in line)
for required in ('--db "${advisory_db}"', "--no-fetch", "--stale"):
    if required not in audit_line:
        fail(f"cargo audit invocation is missing {required}")
if "--ignore RUSTSEC-2023-0071" not in audit_line:
    fail("cargo audit invocation is missing --ignore RUSTSEC-2023-0071")
if "--ignore RUSTSEC-2026-0381" in audit_line:
    fail("cargo audit must not suppress RUSTSEC-2026-0381 for the unaffected locked package")

print("supply-chain advisory governance passed")
PY
