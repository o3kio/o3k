#!/usr/bin/env bash
set -Eeuo pipefail

# Fail-closed tests for the PP.5 Small Edge v1 campaign-evidence validator.
# A valid fixture must pass; dropping any required binding, flipping a verdict,
# leaving an owned-resource leak, or binding a broken identity must fail with a
# useful message and a non-zero exit. The fixture is generated here so a large
# committed evidence file is not required.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="${ROOT_DIR}/scripts/validate_pp5_evidence.py"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp5-evidence.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT

FAILED=0

# Generates one fixture per mutation and writes it to "$1" (the output path).
write_fixture() {
    local out="$1" mutation="$2"
    PYTHONPATH="${ROOT_DIR}/scripts" python3 - "${out}" "${mutation}" <<'PY'
import datetime, hashlib, json, pathlib, sys
from test_pp5_scale_soak_contract import (
    base as scale_run_base, host_rows, write_gate_artifacts, write_soak_observations,
)

SHA1 = "0123456789abcdef0123456789abcdef01234567"
SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

def base():
    return {
        "artifact_type": "o3k-pp5-small-edge-campaign-evidence",
        "schema": "o3k.pp5-small-edge.campaign-evidence.v1",
        "schema_version": 1,
        "phase": "PP.5",
        "release": {
            "version": "0.4.0-rc.24",
            "tag": "v0.4.0-rc.24",
            "tag_object": SHA1,
            "source_sha": SHA1,
            "source_tree": SHA1,
            "artifact_url": "https://github.com/o3kio/o3k/releases/tag/v0.4.0-rc.24",
            "archive_sha256": SHA256,
            "manifest_sha256": SHA256,
            "sbom_sha256": SHA256,
            "provenance_sha256": SHA256,
            "signature_bundle_sha256": SHA256,
            "verification_report_sha256": SHA256,
            "install_sha256": SHA256,
            "signature_verified": True,
            "provenance_verified": True,
            "workflow_identity_verified": True,
            "transparency_verified": True,
        },
        "harness": {
            "harness_sha": SHA1,
            "harness_tree": SHA1,
            "campaign_tree_digest": SHA256,
        },
        "hosts": [
            {"name": "edge-h1", "distro": "ubuntu", "distro_version": "24.04",
             "kernel": "6.8.0-139-generic", "architecture": "x86_64", "kvm": True},
        ],
        "database": {"backend": "postgres", "server_version": "16.4",
                     "migrations_applied": 5, "server_identity": "postgres"},
        "campaign": {
            "declared_scale_tier": "S10",
            "declared_soak_tier": "K-min",
            "boundary_smokes": [
                {"name": "S1", "hypervisors": 1, "verdict": "pass"},
                {"name": "S2", "hypervisors": 2, "verdict": "pass"},
            ],
            "foundation_tier": {"name": "S5", "hypervisors": 5, "verdict": "pass"},
            "scale_tiers": [
                {"name": "S3", "hypervisors": 3, "verdict": "pass"},
                {"name": "S10", "hypervisors": 10, "verdict": "pass"},
                {"name": "S20", "hypervisors": 20, "verdict": "pass"},
            ],
            "soak_tiers": [
                {"name": "K-min", "duration": "2h", "scale": "S10", "verdict": "pass"},
                {"name": "K-full", "duration": "12h", "scale": "S20", "verdict": "pass"},
            ],
        },
        "results": [
            {"acceptance_row": row, "verdict": "pass"} for row in "ABCDEFGHIJKLMNOPQRS"
        ],
        "non_claims": [
            "HA", "SLA", "automatic evacuation or live migration",
            "arbitrary datacenter scale", "multi-region", "cells/sharding",
            "blanket OpenStack compatibility", "Araf readiness",
            "GA / PP.7 certification",
        ],
        "leaked_owned_resources": [],
        "server_owned_endpoints_remaining": 0,
    }

def write_artifacts(doc, out):
    root = pathlib.Path(out).parent
    root_run = root
    root.mkdir(parents=True, exist_ok=True)
    release_dir = root / "release"
    release_dir.mkdir(exist_ok=True)
    release_artifacts = {}
    for name, digest_key in (("archive", "archive_sha256"), ("installer", "install_sha256"),
                             ("manifest", "manifest_sha256"), ("sbom", "sbom_sha256"),
                             ("provenance", "provenance_sha256"),
                             ("signature_bundle", "signature_bundle_sha256")):
        content = f"fixture:{name}".encode()
        path = release_dir / f"{name}.bin"
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        doc["release"][digest_key] = digest
        release_artifacts[name] = {"path": str(path.relative_to(root)), "sha256": digest}
    report = {
        "schema": "o3k.release-verification-report.v1", "status": "passed",
        "version": doc["release"]["version"], "tag": doc["release"]["tag"],
        "tag_object": doc["release"]["tag_object"], "source_sha": doc["release"]["source_sha"],
        "source_tree": doc["release"]["source_tree"],
        "archive_sha256": doc["release"]["archive_sha256"],
        "install_sha256": doc["release"]["install_sha256"],
        "manifest_sha256": doc["release"]["manifest_sha256"],
        "sbom_sha256": doc["release"]["sbom_sha256"],
        "provenance_sha256": doc["release"]["provenance_sha256"],
        "signature_bundle_sha256": doc["release"]["signature_bundle_sha256"],
        "checks": {key: "passed" for key in ("archive_round_trip", "signature", "provenance",
                                                "workflow_identity", "transparency")},
        "verifier": {"name": "fixture-verifier", "version": "1.0", "workflow_identity": "fixture"},
    }
    report_path = release_dir / "verification-report.json"
    report_bytes = json.dumps(report, sort_keys=True).encode()
    report_path.write_bytes(report_bytes)
    doc["release"]["verification_report_sha256"] = hashlib.sha256(report_bytes).hexdigest()
    release_artifacts["verification_report"] = {
        "path": str(report_path.relative_to(root)), "sha256": doc["release"]["verification_report_sha256"]}
    doc["release"]["artifacts"] = release_artifacts

    def write_foundation(tier, index, row):
        count = {"S1": 1, "S2": 2, "S5": 5}[tier]
        run_id = f"123-{tier.lower()}-{index}"
        database = f"o3k_pp5_{tier.lower()}_{run_id}"
        hosts = host_rows(count)
        observations = {
            "owned_leaks": 0,
            "foreign_fingerprint_before": "fixture-foreign-state",
            "foreign_fingerprint_after": "fixture-foreign-state",
            "supported_api_teardown": True,
        }
        if tier in ("S1", "S2"):
            observations.update({
                "canonical_eligible_host_count": count,
                "canonical_eligible_host_ids": [host["stable_host_id"] for host in hosts],
                "bootstrap_host_count": 1,
                "child_host_count": count - 1,
                "initial_workload_count": 0,
                "workload_reached_active": True,
                "provider_allocations_before_workload": 0,
            })
        else:
            observations["lifecycle_gates"] = list("ABCDEFGHIJKLMNOPQR")
        payload = {
            "schema": "o3k.pp5-foundation-run.v1",
            "artifact_type": "o3k-pp5-foundation-run",
            "status": "passed",
            "tier": tier,
            "source": {"sha": SHA1, "tree": SHA1},
            "release": {
                "version": doc["release"]["version"], "tag": doc["release"]["tag"],
                "tag_object": doc["release"]["tag_object"], "source_sha": doc["release"]["source_sha"],
                "source_tree": doc["release"]["source_tree"],
                "archive_sha256": doc["release"]["archive_sha256"],
                "install_sha256": doc["release"]["install_sha256"],
                "manifest_sha256": doc["release"]["manifest_sha256"],
                "sbom_sha256": doc["release"]["sbom_sha256"],
                "provenance_sha256": doc["release"]["provenance_sha256"],
                "signature_bundle_sha256": doc["release"]["signature_bundle_sha256"],
                "verification_report_sha256": doc["release"]["verification_report_sha256"],
            },
            "harness": {"sha": SHA1, "tree": SHA1, "workflow_sha": SHA1},
            "run": {"id": run_id, "workflow_run_id": "123",
                    "workflow_ref": "o3kio/o3k/.github/workflows/pp5-foundation.yml@refs/heads/main",
                    "workflow_sha": SHA1, "runner_name": "protected-runner", "evidence_root": "."},
            "database": {"backend": "postgres", "identity": database, "server_version": "16.4",
                         "migrations_applied": 17},
            "observed_eligible_host_count": count,
            "eligible_hosts": hosts,
            "owned_leaks": 0,
            "foreign_mutations": 0,
            "observations": observations,
        }
        raw = json.dumps(payload, sort_keys=True).encode()
        path = root / f"foundation-{tier.lower()}-{index}.json"
        path.write_bytes(raw)
        row.update({"run_id": run_id, "database_identity": database,
                    "run_artifact": {"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()}})

    for index, smoke in enumerate(doc["campaign"]["boundary_smokes"]):
        write_foundation(smoke["name"], index, smoke)
    write_foundation("S5", 0, doc["campaign"]["foundation_tier"])

    def write_run(tier, index):
        import pp5_scale_soak_contract as contract
        run = scale_run_base(tier)
        count = contract.SCALE_HOSTS[tier] if tier in contract.SCALE_HOSTS else contract.SCALE_HOSTS[contract.SOAKS[tier][0]]
        run_id = f"123-{tier.lower().replace('-', '_')}-{index}"
        database = f"o3k_pp5_{tier.lower().replace('-', '_')}_{run_id}"
        run["source"] = {"sha": SHA1, "tree": SHA1}
        run["release"].update({
            "version": doc["release"]["version"], "tag": doc["release"]["tag"],
            "tag_object_sha": doc["release"]["tag_object"], "source_sha": SHA1,
            "source_tree": SHA1, "archive_sha256": doc["release"]["archive_sha256"],
            "install_sha256": doc["release"]["install_sha256"],
            "manifest_sha256": doc["release"]["manifest_sha256"],
            "sbom_sha256": doc["release"]["sbom_sha256"],
            "provenance_sha256": doc["release"]["provenance_sha256"],
            "signature_bundle_sha256": doc["release"]["signature_bundle_sha256"],
            "verification_report_sha256": doc["release"]["verification_report_sha256"],
            "signature_verified": True, "provenance_verified": True,
            "workflow_identity_verified": True, "transparency_verified": True,
        })
        run["harness"] = {"sha": SHA1, "tree": SHA1, "workflow_sha": SHA1}
        run_directory = pathlib.Path("runs") / run_id
        run_root = root_run / run_directory
        run_root.mkdir(parents=True, exist_ok=True)
        run["run"].update({
            "id": run_id, "workflow_run_id": "123",
            "workflow_ref": "o3kio/o3k/.github/workflows/real-host-validation.yml@refs/heads/main",
            "workflow_sha": SHA1, "runner_name": "protected-runner-1",
            "evidence_root": run_directory.as_posix(),
        })
        run["database"].update({"identity": database})
        run["resource_baseline"]["postgres"]["database_identity"] = database
        run["resource_budget"]["management_addresses_reserved"] = count
        if tier in contract.SOAKS:
            for event in run["soak"]["fault_events"]:
                if event.get("kind") == "postgres_process_restart":
                    event["database_identity"] = database
        write_gate_artifacts(run, run_root)
        row = {"name": tier, "verdict": "pass", "run_id": run_id, "database_identity": database}
        if tier in contract.SCALE_HOSTS:
            row["hypervisors"] = count
        else:
            row.update({"duration": "2h" if tier == "K-min" else "12h",
                        "duration_seconds": run["timestamps"]["monotonic_elapsed_seconds"],
                        "scale": contract.SOAKS[tier][0]})
            sample_bytes = run.pop("_samples_bytes")
            sample_name = f"{tier.lower()}-{index}.jsonl"
            (run_root / sample_name).write_bytes(sample_bytes)
            run["soak"]["samples"] = {
                "path": sample_name, "sha256": hashlib.sha256(sample_bytes).hexdigest(),
            }
            scale_name = contract.SOAKS[tier][0]
            scale_row = next(item for item in doc["campaign"]["scale_tiers"]
                             if item["name"] == scale_name)
            scale_path = root_run / scale_row["run_artifact"]["path"]
            scale_run = json.loads(scale_path.read_text())
            scale_snapshot = json.dumps(scale_run["resource_baseline"], sort_keys=True,
                                        separators=(",", ":")).encode()
            run["soak"]["scale_baseline"] = {
                "tier": scale_name,
                "run_id": scale_row["run_id"],
                "database_identity": scale_run["database"]["identity"],
                "evidence": scale_row["run_artifact"],
                "resource_baseline_sha256": hashlib.sha256(scale_snapshot).hexdigest(),
            }
            write_soak_observations(run, run_root)
        run_bytes = json.dumps(run, sort_keys=True).encode()
        run_path = run_root / "run.json"
        run_path.write_bytes(run_bytes)
        row["run_artifact"] = {
            "path": run_path.relative_to(root_run).as_posix(),
            "sha256": hashlib.sha256(run_bytes).hexdigest(),
        }
        return row

    for key in ("scale_tiers", "soak_tiers"):
        rows = doc["campaign"][key]
        for index, row in enumerate(rows):
            generated = write_run(row["name"], index)
            if isinstance(row, dict):
                row.update(generated)

def mutate_foundation(doc, out, tier, index, path, value):
    row = (doc["campaign"]["boundary_smokes"][index] if tier in ("S1", "S2")
           else doc["campaign"]["foundation_tier"])
    artifact_path = pathlib.Path(out).parent / row["run_artifact"]["path"]
    payload = json.loads(artifact_path.read_text())
    current = payload
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value
    raw = json.dumps(payload, sort_keys=True).encode()
    artifact_path.write_bytes(raw)
    row["run_artifact"]["sha256"] = hashlib.sha256(raw).hexdigest()

def mutate_soak_artifact(doc, out, tier, mutate):
    row = next(item for item in doc["campaign"]["soak_tiers"] if item["name"] == tier)
    path = pathlib.Path(out).parent / row["run_artifact"]["path"]
    payload = json.loads(path.read_text())
    mutate(payload)
    raw = json.dumps(payload, sort_keys=True).encode()
    path.write_bytes(raw)
    row["run_artifact"]["sha256"] = hashlib.sha256(raw).hexdigest()


def drop(doc, dotted):
    parts = dotted.split(".")
    cur = doc
    for part in parts[:-1]:
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    cur.pop(parts[-1], None)
    return doc

mutation = sys.argv[2]
doc = base()
write_artifacts(doc, sys.argv[1])
if mutation == "valid":
    pass
elif mutation == "drop_release_version":
    drop(doc, "release.version")
elif mutation == "drop_source_sha":
    drop(doc, "release.source_sha")
elif mutation == "drop_harness_sha":
    drop(doc, "harness.harness_sha")
elif mutation == "empty_hosts":
    doc["hosts"] = []
elif mutation == "drop_migrations":
    drop(doc, "database.migrations_applied")
elif mutation == "drop_declared_soak":
    drop(doc, "campaign.declared_soak_tier")
elif mutation == "drop_results":
    doc["results"] = []
elif mutation == "missing_acceptance_row":
    doc["results"] = [r for r in doc["results"] if r["acceptance_row"] != "M"]
elif mutation == "drop_non_claims":
    doc["non_claims"] = []
elif mutation == "drop_required_non_claim":
    doc["non_claims"] = [c for c in doc["non_claims"] if "Araf" not in c]
elif mutation == "flip_result":
    doc["results"][0]["verdict"] = "fail"
elif mutation == "own_leak":
    doc["leaked_owned_resources"] = ["o3k-server:deleted-but-not-released"]
elif mutation == "remaining_endpoints":
    doc["server_owned_endpoints_remaining"] = 1
elif mutation == "non_hex_sha":
    doc["release"]["source_sha"] = "zz" + SHA1[2:]
elif mutation == "missing_duration":
    drop(doc, "campaign.soak_tiers.0.duration")
elif mutation == "mismatched_schema":
    doc["schema"] = "o3k.pp5-small-edge.campaign-evidence.v0-bogus"
elif mutation == "absent_schema":
    drop(doc, "schema")
elif mutation == "drop_sbom_sha256":
    drop(doc, "release.sbom_sha256")
elif mutation == "drop_provenance_sha256":
    drop(doc, "release.provenance_sha256")
elif mutation == "drop_archive_sha256":
    drop(doc, "release.archive_sha256")
elif mutation == "drop_signature_verified":
    drop(doc, "release.signature_verified")
elif mutation == "false_signature_verified":
    doc["release"]["signature_verified"] = False
elif mutation == "drop_server_version":
    drop(doc, "database.server_version")
elif mutation == "missing_scale_tier":
    doc["campaign"]["scale_tiers"] = [
        t for t in doc["campaign"]["scale_tiers"] if t["name"] != "S3"
    ]
elif mutation == "wrong_scale_cardinality":
    doc["campaign"]["scale_tiers"][2]["hypervisors"] = 4
elif mutation == "missing_boundary_smoke":
    doc["campaign"]["boundary_smokes"] = [
        smoke for smoke in doc["campaign"]["boundary_smokes"] if smoke["name"] != "S2"
    ]
elif mutation == "wrong_boundary_cardinality":
    doc["campaign"]["boundary_smokes"][1]["hypervisors"] = 1
elif mutation == "missing_foundation_tier":
    drop(doc, "campaign.foundation_tier")
elif mutation == "boolean_s1_host_count":
    mutate_foundation(doc, sys.argv[1], "S1", 0, "observed_eligible_host_count", True)
elif mutation == "boolean_s1_bootstrap_count":
    mutate_foundation(doc, sys.argv[1], "S1", 0, "observations.bootstrap_host_count", True)
elif mutation == "boolean_s1_leak_count":
    mutate_foundation(doc, sys.argv[1], "S1", 0, "owned_leaks", False)
elif mutation == "missing_s5_matrix_gate":
    mutate_foundation(doc, sys.argv[1], "S5", 0, "observations.lifecycle_gates", list("ABCDEFGHIJKLMNOPQ"))
elif mutation == "duplicate_foundation_run_id":
    s1 = doc["campaign"]["boundary_smokes"][0]
    s2 = doc["campaign"]["boundary_smokes"][1]
    path = pathlib.Path(sys.argv[1]).parent / s2["run_artifact"]["path"]
    payload = json.loads(path.read_text())
    payload["run"]["id"] = s1["run_id"]
    payload["database"]["identity"] = f"o3k_pp5_s2_{s1['run_id']}"
    raw = json.dumps(payload, sort_keys=True).encode()
    path.write_bytes(raw)
    s2["run_id"] = s1["run_id"]
    s2["database_identity"] = payload["database"]["identity"]
    s2["run_artifact"]["sha256"] = hashlib.sha256(raw).hexdigest()
elif mutation == "wrong_soak_baseline_binding":
    scale = next(item for item in doc["campaign"]["scale_tiers"] if item["name"] == "S3")
    def wrong_baseline(payload):
        payload["soak"]["scale_baseline"].update({
            "evidence": scale["run_artifact"],
            "run_id": scale["run_id"],
        })
    mutate_soak_artifact(doc, sys.argv[1], "K-min", wrong_baseline)
elif mutation == "wrong_soak_baseline_digest":
    def wrong_digest(payload):
        payload["soak"]["scale_baseline"]["resource_baseline_sha256"] = "f" * 64
    mutate_soak_artifact(doc, sys.argv[1], "K-min", wrong_digest)
elif mutation == "missing_soak_tier":
    doc["campaign"]["soak_tiers"] = [
        t for t in doc["campaign"]["soak_tiers"] if t["name"] != "K-full"
    ]
elif mutation == "short_soak":
    doc["campaign"]["soak_tiers"][0]["duration"] = "1s"
elif mutation == "wrong_soak_scale":
    doc["campaign"]["soak_tiers"][1]["scale"] = "S10"
elif mutation == "db_url_with_password":
    doc["database"]["url"] = "postgres://o3k:password@127.0.0.1:5432/o3k_test"
else:
    raise SystemExit(f"unknown mutation: {mutation}")
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
}

# (mutation, expected non-zero, expected stderr substring)
cases=(
    "valid|0|"
    "drop_release_version|1|release.version must be a non-empty string"
    "drop_source_sha|1|release.source_sha must be a lowercase 40-character hex digest"
    "drop_harness_sha|1|harness.harness_sha must be a lowercase 40-character hex digest"
    "empty_hosts|1|hosts must be a non-empty list"
    "drop_migrations|1|database.migrations_applied must be an integer"
    "drop_declared_soak|1|campaign.declared_soak_tier must be a non-empty string"
    "drop_results|1|results must be a non-empty list"
    "missing_acceptance_row|1|missing acceptance row(s): M"
    "drop_non_claims|1|non_claims must be a non-empty explicit list"
    "drop_required_non_claim|1|non_claims missing required disclaimer"
    "flip_result|1|must be 'pass'"
    "own_leak|1|leaked_owned_resources must be empty"
    "remaining_endpoints|1|server_owned_endpoints_remaining must be 0"
    "non_hex_sha|1|release.source_sha must be a lowercase 40-character hex digest"
    "missing_duration|1|campaign.soak_tiers[0].duration must be a non-empty string"
    "mismatched_schema|1|schema must be 'o3k.pp5-small-edge.campaign-evidence.v1'"
    "absent_schema|1|schema must be 'o3k.pp5-small-edge.campaign-evidence.v1'"
    "drop_sbom_sha256|1|release.sbom_sha256 must be a lowercase 64-character hex digest"
    "drop_provenance_sha256|1|release.provenance_sha256 must be a lowercase 64-character hex digest"
    "drop_archive_sha256|1|release.archive_sha256 must be a lowercase 64-character hex digest"
    "drop_signature_verified|1|release.signature_verified must be true"
    "false_signature_verified|1|release.signature_verified must be true"
    "drop_server_version|1|database.server_version must be a non-empty string"
    "missing_scale_tier|1|missing required tier(s): S3"
    "wrong_scale_cardinality|1|campaign.scale_tiers[2] S20 must declare 20 hypervisors"
    "missing_boundary_smoke|1|campaign.boundary_smokes missing required smoke(s): S2"
    "wrong_boundary_cardinality|1|campaign.boundary_smokes[1] S2 must declare 2 hypervisors"
    "missing_foundation_tier|1|campaign.foundation_tier must be an object"
    "boolean_s1_host_count|1|observed eligible host count must be 1"
    "boolean_s1_bootstrap_count|1|exactly one bootstrap host"
    "boolean_s1_leak_count|1|owned resource leak count must be zero"
    "missing_s5_matrix_gate|1|every lifecycle gate A through R exactly once"
    "duplicate_foundation_run_id|1|run IDs must be unique across all foundation"
    "wrong_soak_baseline_binding|1|must reference the exact campaign S10 run artifact"
    "wrong_soak_baseline_digest|1|resource baseline digest differs from the campaign scale run"
    "missing_soak_tier|1|missing required tier(s): K-full"
    "short_soak|1|K-min must declare duration 2h"
    "wrong_soak_scale|1|K-full must declare scale S20"
    "db_url_with_password|1|secret-bearing field(s) present"
)

for entry in "${cases[@]}"; do
    IFS='|' read -r mutation expected_code expected_message <<<"${entry}"
    fixture="${WORK_DIR}/${mutation}.json"
    write_fixture "${fixture}" "${mutation}"
    if python3 "${VALIDATOR}" "${fixture}" >"${WORK_DIR}/${mutation}.out" 2>"${WORK_DIR}/${mutation}.err"; then
        actual_code=0
    else
        actual_code=$?
    fi
    if [[ "${actual_code}" -ne "${expected_code}" ]]; then
        echo "FAIL: ${mutation}: expected exit ${expected_code}, got ${actual_code}" >&2
        if [[ "${mutation}" == "valid" ]]; then
            cat "${WORK_DIR}/${mutation}.err" >&2
        fi
        FAILED=1
        continue
    fi
    if [[ -n "${expected_message}" ]] && ! grep -Fq "${expected_message}" "${WORK_DIR}/${mutation}.err"; then
        echo "FAIL: ${mutation}: stderr missing expected message: ${expected_message}" >&2
        FAILED=1
        continue
    fi
    echo "PASS: ${mutation}"
done

# Standalone fail-closed cases that do not go through write_fixture: a missing /
# unreadable artifact and malformed (non-JSON) input must fail before any
# contract checks run.
missing="${WORK_DIR}/does-not-exist.json"
if python3 "${VALIDATOR}" "${missing}" >"${WORK_DIR}/missing_file.out" 2>"${WORK_DIR}/missing_file.err"; then
    echo "FAIL: missing_file: expected non-zero exit" >&2
    FAILED=1
else
    if ! grep -Fq "PP.5 evidence validation FAILED" "${WORK_DIR}/missing_file.err"; then
        echo "FAIL: missing_file: stderr missing FAILED marker" >&2
        FAILED=1
    else
        echo "PASS: missing_file"
    fi
fi

printf 'this is { not [ valid json\n' >"${WORK_DIR}/malformed.json"
if python3 "${VALIDATOR}" "${WORK_DIR}/malformed.json" >"${WORK_DIR}/malformed_json.out" 2>"${WORK_DIR}/malformed_json.err"; then
    echo "FAIL: malformed_json: expected non-zero exit" >&2
    FAILED=1
else
    if ! grep -Fq "PP.5 evidence validation FAILED" "${WORK_DIR}/malformed_json.err"; then
        echo "FAIL: malformed_json: stderr missing FAILED marker" >&2
        FAILED=1
    else
        echo "PASS: malformed_json"
    fi
fi

if [[ "${FAILED}" -ne 0 ]]; then
    echo "PP.5 evidence validation guard failed" >&2
    exit 1
fi
echo "All PP.5 campaign-evidence validation guards passed"
