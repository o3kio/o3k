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
    python3 - "${out}" "${mutation}" <<'PY'
import json, pathlib, sys

SHA1 = "0123456789abcdef0123456789abcdef01234567"
SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

def base():
    return {
        "artifact_type": "o3k-pp5-small-edge-campaign-evidence",
        "schema": "o3k.pp5-small-edge.campaign-evidence.v1",
        "schema_version": 1,
        "phase": "PP.5",
        "release": {
            "version": "v0.4.0-rc.24",
            "tag_object": SHA1,
            "source_sha": SHA1,
            "artifact_url": "https://github.com/o3kio/o3k/releases/tag/v0.4.0-rc.24",
            "archive_sha256": SHA256,
            "manifest_sha256": SHA256,
            "sbom_sha256": SHA256,
            "provenance_sha256": SHA256,
            "signature_verified": True,
        },
        "harness": {
            "harness_sha": SHA1,
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
            "scale_tiers": [
                {"name": "S1", "hypervisors": 1, "verdict": "pass"},
                {"name": "S2", "hypervisors": 2, "verdict": "pass"},
                {"name": "S5", "hypervisors": 5, "verdict": "pass"},
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
        t for t in doc["campaign"]["scale_tiers"] if t["name"] != "S5"
    ]
elif mutation == "wrong_scale_cardinality":
    doc["campaign"]["scale_tiers"][2]["hypervisors"] = 4
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
    "missing_scale_tier|1|missing required tier(s): S5"
    "wrong_scale_cardinality|1|campaign.scale_tiers[2] S5 must declare 5 hypervisors"
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
