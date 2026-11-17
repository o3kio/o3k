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
    {
        "id": "RUSTSEC-2026-0459",
        "package": "libsqlite3-sys",
        "affected_version": "0.30.1",
        "owner": "O3K maintainers",
        "rationale": (
            "libsqlite3-sys 0.30.1 (via sqlx-sqlite 0.8.6, bundled feature) vendors a "
            "SQLite affected by a page-cache uninitialized-memory disclosure. The "
            "vector is local: the process must open a crafted database whose sibling "
            "-wal file has a different page size. O3K opens only its own store files "
            "under root-owned, non-group-writable state/journal directories (0700 "
            "where O3K creates them, root:o3k 0750 in the qualified installed "
            "layout); no less-trusted party can write a crafted pair there, and no "
            "O3K feature opens operator-supplied SQLite files. No released SQLx "
            "accepts the fixed libsqlite3-sys >= 0.39 (0.8.6 caps at 0.30.x, 0.9.0 "
            "caps below 0.38), so an upgrade cannot clear the advisory today."
        ),
        "review_trigger": (
            "Remove as soon as SQLx resolves libsqlite3-sys >= 0.39 (bundled SQLite "
            ">= 3.54.0) and the workspace upgrades, or if any code path opens "
            "externally supplied SQLite files."
        ),
    },
    {
        "id": "RUSTSEC-2026-0543",
        "package": "chrono",
        "affected_version": "0.4.45",
        "owner": "O3K maintainers",
        "rationale": (
            "The advisory marks chrono unmaintained; it carries no vulnerability. "
            "The workspace uses chrono only for UTC timestamps, RFC 3339 "
            "formatting/parsing of O3K's own generated documents, and SQLx date/time "
            "mapping (sqlite/postgres); no untrusted input is parsed. No maintained "
            "drop-in replacement covers the sqlx 0.8 chrono feature today, so an "
            "upgrade cannot clear the advisory."
        ),
        "review_trigger": (
            "Remove when the workspace migrates off chrono or sqlx no longer "
            "requires the chrono feature, or if a vulnerability is published for "
            "chrono 0.4.45."
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

# RUSTSEC-2026-0459 is ignored only for the reviewed SQLx SQLite edge. Keep
# the exception precondition tied to the actual lock graph so a dependency
# update cannot silently broaden or strand this waiver.
sqlite_exception = expected_exceptions[2]
sqlite_packages = [
    package
    for package in cargo_lock.get("package", [])
    if package.get("name") == sqlite_exception["package"]
    and package.get("version") == sqlite_exception["affected_version"]
]
if len(sqlite_packages) != 1:
    fail(
        "RUSTSEC-2026-0459 exception requires exactly one locked libsqlite3-sys 0.30.1"
    )
if not any(
    package.get("name") == "sqlx-sqlite"
    and any(
        dependency.split(" ", 1)[0] == "libsqlite3-sys"
        and (
            # An unversioned edge is exact only while a single libsqlite3-sys
            # is locked; with several, the edge must name the waived version.
            (" " not in dependency
             and len(sqlite_packages) == 1)
            or dependency == "libsqlite3-sys 0.30.1"
        )
        for dependency in package.get("dependencies", [])
    )
    for package in cargo_lock.get("package", [])
):
    fail(
        "RUSTSEC-2026-0459 exception requires the locked sqlx-sqlite to resolve "
        "libsqlite3-sys to the waived 0.30.1 package"
    )

# RUSTSEC-2026-0543 is ignored only as an unmaintained notice pinned to the
# locked chrono version; a version change or a duplicate package invalidates
# the waiver.
chrono_exception = expected_exceptions[3]
chrono_packages = [
    package
    for package in cargo_lock.get("package", [])
    if package.get("name") == chrono_exception["package"]
    and package.get("version") == chrono_exception["affected_version"]
]
if len(chrono_packages) != 1:
    fail("RUSTSEC-2026-0543 exception requires exactly one locked chrono 0.4.45")

deny = deny_path.read_text(encoding="utf-8")
deny_ids = re.findall(r'\bid\s*=\s*"(RUSTSEC-[0-9-]+)"', deny)
expected_ids = {"RUSTSEC-2026-0459", "RUSTSEC-2026-0543"}
if set(deny_ids) != expected_ids or len(deny_ids) != len(expected_ids):
    fail(
        "deny.toml must suppress exactly the reviewed RUSTSEC-2026-0459 and "
        "RUSTSEC-2026-0543 exceptions and no other advisory"
    )

workflow = workflow_path.read_text(encoding="utf-8")
if workflow.count(database["commit"]) != 1:
    fail("CI must contain exactly one occurrence of the pinned advisory DB commit")
# Accept both cargo-audit flag spellings (`--ignore ID` and `--ignore=ID`) so
# an equals-form suppression cannot evade the review checks.
def ignore_occurrences(workflow_text, advisory_id):
    return len(re.findall(rf"--ignore[=\s]+{re.escape(advisory_id)}(?![0-9-])", workflow_text))

if ignore_occurrences(workflow, "RUSTSEC-2023-0071") != 1:
    fail("CI must ignore exactly one machine-readable exception for RUSTSEC-2023-0071")
if ignore_occurrences(workflow, "RUSTSEC-2026-0459") != 1:
    fail("CI must ignore exactly one machine-readable exception for RUSTSEC-2026-0459")
if ignore_occurrences(workflow, "RUSTSEC-2026-0543") != 1:
    fail("CI must ignore exactly one machine-readable exception for RUSTSEC-2026-0543")
if ignore_occurrences(workflow, "RUSTSEC-2026-0381"):
    fail("CI must not suppress RUSTSEC-2026-0381 for the unaffected locked package")
if workflow.count("cargo audit") != 1:
    fail("CI must contain exactly one cargo audit invocation")
audit_line = next(line for line in workflow.splitlines() if "cargo audit" in line)
for required in ('--db "${advisory_db}"', "--no-fetch", "--stale"):
    if required not in audit_line:
        fail(f"cargo audit invocation is missing {required}")
# Both legs of the supply-chain gate must suppress exactly the reviewed
# exception set: the cargo-deny leg via deny.toml, the cargo-audit leg via
# --ignore. A pinned advisory-DB bump therefore cannot split the two legs.
expected_audit_ignores = {"RUSTSEC-2023-0071"} | expected_ids
audit_ignores = set(re.findall(r"--ignore[=\s]+(RUSTSEC-[0-9-]+)", audit_line))
if audit_ignores != expected_audit_ignores:
    fail(
        "cargo audit invocation must ignore exactly the reviewed exception set: "
        f"{sorted(expected_audit_ignores)}"
    )

print("supply-chain advisory governance passed")
PY
