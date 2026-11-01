#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-release-gate.XXXXXX")"
MALFORMED_ROOT="${ARTIFACT_DIR}/malformed-workspace"
cleanup() {
  if [[ -d "${MALFORMED_ROOT}" ]]; then
    git -C "${ROOT_DIR}" worktree remove --force "${MALFORMED_ROOT}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${ARTIFACT_DIR}"
}
trap cleanup EXIT
SOURCE_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
export SOURCE_COMMIT

python3 - "${ARTIFACT_DIR}" <<'PY'
import hashlib, json, os, pathlib, sys, time

root = pathlib.Path(sys.argv[1])
finished_at = int(time.time())
common = {
    "profile": "libvirt",
    "redacted": True,
    "cleanup": {"status": "passed"},
    "finished_at": finished_at,
}
artifacts = {
    "ubuntu.json": {**common, "artifact_type": "clean-install", "status": "passed", "distro": "ubuntu", "install": {"status": "passed"}},
    "debian.json": {**common, "artifact_type": "clean-install", "status": "passed", "distro": "debian", "install": {"status": "passed"}},
    "recovery.json": {
        **common,
        "artifact_type": "failure-recovery",
        "status": "passed",
        "scenarios": {
            scenario: {
                "status": "passed",
                "evidence": {
                    "artifact": f"failure-recovery/{scenario}.json",
                    "checks": ["observed transition", "verified cleanup"],
                },
            }
            for scenario in (
                "control-plane-crash-before-dispatch",
                "control-plane-crash-after-dispatch",
                "compute-agent-crash-before-mutation",
                "compute-agent-crash-after-domain-definition-or-start",
                "libvirt-daemon-restart",
                "agent-control-plane-network-interruption",
                "timeout-after-accepted-mutation",
                "duplicate-create-delivery",
                "duplicate-action-delivery",
                "duplicate-delete-delivery",
                "corrupted-truncated-image",
                "image-checksum-mismatch",
                "qemu-img-failure",
                "config-drive-failure",
                "tap-failure",
                "dnsmasq-failure",
                "disk-full",
                "repeated-delete",
                "partial-cleanup",
            )
        },
    },
    "benchmark-raw.json": {**common, "artifact_type": "benchmark", "status": "measured", "environment": {"uname": "Linux test-host 6.1", "rustc": "rustc 1.97.1"}, "samples": 5, "control_plane": {"startup_readiness_ms": 100, "token_p95_seconds": 0.01, "idle_rss_kib": 1024}, "guest_and_libvirt": {"status": "measured"}, "targets": {"startup_readiness_ms": 2000, "idle_rss_mib": 150, "token_p95_ms": 100}, "release_eligible": True},
    "human-review.json": {
        "artifact_type": "human-architecture-security-review",
        "schema_version": 1,
        "status": "approved",
        "reviewer": {"name": "Example Reviewer", "organization": "Example Security", "role": "Independent reviewer", "is_implementing_agent": False},
        "reviewed_commit": os.environ["SOURCE_COMMIT"],
        "review_record_url": "https://example.invalid/review/93",
        "scope": [
            "Keystone and project isolation", "Compute-agent mTLS",
            "Journal and reconciliation", "Placement and scheduler",
            "Images and paths", "Config-drive", "Libvirt and ownership",
            "Bridge/TAP/DHCP", "Console and logs",
            "Installer/reset/uninstall/runner",
        ],
        "findings": [{"id": "SEC-001", "severity": "low", "disposition": "fixed"}],
        "approvals": {"release_blocking_findings": True, "destructive_cleanup": True, "foreign_state_safeguards": True},
        "unresolved_risks": ["Real-host evidence is still required."],
    },
}
raw = artifacts["benchmark-raw.json"]
(root / "benchmark-raw.json").write_text(json.dumps(raw), encoding="utf-8")
raw_sha256 = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
artifacts["benchmark.json"] = {**common, "artifact_type": "benchmark", "status": "measured", "samples": raw["samples"], "control_plane": raw["control_plane"], "guest_and_libvirt": raw["guest_and_libvirt"], "targets_evaluated": {"startup": True, "rss": True, "token_p95": True}, "release_eligible": raw["release_eligible"], "raw_sha256": raw_sha256}
for name, value in artifacts.items():
    (root / name).write_text(json.dumps(value), encoding="utf-8")
PY

# The e2e fixture comes from the shared contract generator so the gate test
# never hand-duplicates the resource key sets; a pristine copy is kept for the
# contract-negative cases below.
python3 "${ROOT_DIR}/scripts/validate-release-e2e-evidence.py" --example \
    >"${ARTIFACT_DIR}/e2e.json"
cp "${ARTIFACT_DIR}/e2e.json" "${ARTIFACT_DIR}/e2e.pristine.json"

python3 - "${ARTIFACT_DIR}" <<'PY'
import hashlib, json, pathlib, sys, os
root = pathlib.Path(sys.argv[1])
source = os.environ["SOURCE_COMMIT"]
hashes = {"o3kd_sha256": "a" * 64, "o3k_compute_sha256": "b" * 64, "bundle_tree_sha256": "c" * 64}
names = {"real_libvirt_e2e":"e2e.json", "clean_ubuntu_install":"ubuntu.json", "clean_debian_install":"debian.json", "failure_recovery":"recovery.json", "benchmark":"benchmark.json", "benchmark_raw":"benchmark-raw.json"}
manifest = {"artifact_type":"candidate-evidence-manifest", "candidate_sha":source, **hashes, "artifacts":{}}
for logical, filename in names.items():
    path = root / filename
    value = json.loads(path.read_text(encoding="utf-8"))
    value.update({"source_commit":source, "candidate_sha":source, **hashes})
    path.write_text(json.dumps(value), encoding="utf-8")
    manifest["artifacts"][logical] = {"artifact":filename, "artifact_sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
raw = json.loads((root / "benchmark-raw.json").read_text(encoding="utf-8"))
summary_path = root / "benchmark.json"
summary = json.loads(summary_path.read_text(encoding="utf-8"))
summary["raw_sha256"] = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
summary_path.write_text(json.dumps(summary), encoding="utf-8")
manifest["artifacts"]["benchmark"]["artifact_sha256"] = hashlib.sha256(summary_path.read_bytes()).hexdigest()
(root / "candidate-evidence-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
PY

HUMAN_REVIEW="${ARTIFACT_DIR}/human-review.json"
OUTPUT="${ARTIFACT_DIR}/valid-release.json"

# The remediation work starts from the permanently rejected historical
# checkout. Until these changes are committed at a new SHA, the release gate
# must reject this test's otherwise-valid fixture before any ready-path
# assertions can run. Once HEAD moves, the complete ready-path suite below is
# exercised normally.
if [[ "${SOURCE_COMMIT}" == "952dcf9c4a1ae958996e4ae9444763e5524eddc5" ]]; then
    if bash "${ROOT_DIR}/packaging/release-gate.sh" \
        --e2e "${ARTIFACT_DIR}/e2e.json" \
        --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json" \
        --install-debian "${ARTIFACT_DIR}/debian.json" \
        --recovery "${ARTIFACT_DIR}/recovery.json" \
        --benchmark "${ARTIFACT_DIR}/benchmark.json" \
        --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json" \
        --human-review "${HUMAN_REVIEW}" \
        --source-commit "${SOURCE_COMMIT}" \
        --candidate-evidence-manifest "${ARTIFACT_DIR}/candidate-evidence-manifest.json" \
        --output "${OUTPUT}"; then
        echo "release gate accepted the permanently rejected historical candidate" >&2
        exit 1
    fi
    grep -q 'historical candidate 952dcf9c4a1ae958996e4ae9444763e5524eddc5 is rejected and ineligible' "${OUTPUT}"
    echo "release gate historical-candidate rejection test passed"
    exit 0
fi

bash "${ROOT_DIR}/packaging/release-gate.sh" \
    --e2e "${ARTIFACT_DIR}/e2e.json" \
    --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json" \
    --install-debian "${ARTIFACT_DIR}/debian.json" \
    --recovery "${ARTIFACT_DIR}/recovery.json" \
    --benchmark "${ARTIFACT_DIR}/benchmark.json" \
    --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json" \
    --human-review "${HUMAN_REVIEW}" \
    --source-commit "${SOURCE_COMMIT}" \
    --candidate-evidence-manifest "${ARTIFACT_DIR}/candidate-evidence-manifest.json" \
    --output "${OUTPUT}"
grep -q '"status": "ready"' "${OUTPUT}"
EXPECTED_RELEASE="v$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "${ROOT_DIR}/Cargo.toml" | head -1)"
EXPECTED_INSTALLER_PIN="$(sed -n 's/^O3K_INSTALLER_VERSION="\([^"]*\)"$/\1/p' "${ROOT_DIR}/packaging/get-o3k.sh")"
[[ "${EXPECTED_INSTALLER_PIN}" == "${EXPECTED_RELEASE}" ]]
grep -Fq '"release": "'"${EXPECTED_RELEASE}"'"' "${OUTPUT}"

# A later package stanza must never supply a missing workspace package version.
git -C "${ROOT_DIR}" worktree add --detach "${MALFORMED_ROOT}" "${SOURCE_COMMIT}" >/dev/null
cp "${ROOT_DIR}/packaging/release-gate.sh" "${MALFORMED_ROOT}/packaging/release-gate.sh"
cat >"${MALFORMED_ROOT}/Cargo.toml" <<'EOF'
[workspace.package]
edition = "2024"

[package]
version = "9.9.9"
EOF
if bash "${MALFORMED_ROOT}/packaging/release-gate.sh" \
    --e2e "${ARTIFACT_DIR}/e2e.json" \
    --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json" \
    --install-debian "${ARTIFACT_DIR}/debian.json" \
    --recovery "${ARTIFACT_DIR}/recovery.json" \
    --benchmark "${ARTIFACT_DIR}/benchmark.json" \
    --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json" \
    --human-review "${HUMAN_REVIEW}" \
    --source-commit "${SOURCE_COMMIT}" \
    --candidate-evidence-manifest "${ARTIFACT_DIR}/candidate-evidence-manifest.json" \
    --output "${ARTIFACT_DIR}/malformed-workspace-release.json"; then
    echo "release gate accepted a later package version as the workspace version" >&2
    exit 1
fi
grep -q 'release_version: workspace package version is missing' \
    "${ARTIFACT_DIR}/malformed-workspace-release.json"
python3 - "${ARTIFACT_DIR}/malformed-workspace-release.json" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
assert result["status"] == "blocked"
assert result["release"] is None
PY
git -C "${ROOT_DIR}" worktree remove --force "${MALFORMED_ROOT}" >/dev/null

if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    --e2e "${ARTIFACT_DIR}/e2e.json" \
    --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json" \
    --install-debian "${ARTIFACT_DIR}/debian.json" \
    --recovery "${ARTIFACT_DIR}/recovery.json" \
    --benchmark "${ARTIFACT_DIR}/benchmark.json" \
    --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json" \
    --source-commit "${SOURCE_COMMIT}" \
    --candidate-evidence-manifest "${ARTIFACT_DIR}/candidate-evidence-manifest.json" \
    --output "${ARTIFACT_DIR}/missing-human-review.json"; then
    echo "release gate accepted missing human review evidence" >&2
    exit 1
fi
grep -q 'human_review: artifact path was not supplied' "${ARTIFACT_DIR}/missing-human-review.json"

if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    --e2e "${ARTIFACT_DIR}/e2e.json" \
    --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json" \
    --install-debian "${ARTIFACT_DIR}/debian.json" \
    --recovery "${ARTIFACT_DIR}/recovery.json" \
    --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json" \
    --human-review "${HUMAN_REVIEW}" \
    --source-commit "${SOURCE_COMMIT}" \
    --candidate-evidence-manifest "${ARTIFACT_DIR}/candidate-evidence-manifest.json" \
    --output "${ARTIFACT_DIR}/missing-benchmark.json"; then
    echo "release gate accepted missing benchmark evidence" >&2
    exit 1
fi
grep -q 'benchmark: artifact path was not supplied' "${ARTIFACT_DIR}/missing-benchmark.json"

GATE_ARGS=(
    --e2e "${ARTIFACT_DIR}/e2e.json"
    --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json"
    --install-debian "${ARTIFACT_DIR}/debian.json"
    --recovery "${ARTIFACT_DIR}/recovery.json"
    --benchmark "${ARTIFACT_DIR}/benchmark.json"
    --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json"
    --human-review "${HUMAN_REVIEW}"
    --source-commit "${SOURCE_COMMIT}"
    --candidate-evidence-manifest "${ARTIFACT_DIR}/candidate-evidence-manifest.json"
)

# Provenance regressions: a structurally valid artifact with missing or stale
# binding must never become ready merely because human review is present.
cp "${ARTIFACT_DIR}/e2e.json" "${ARTIFACT_DIR}/e2e-unbound.json"
python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["source_commit"] = None
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" "${GATE_ARGS[@]}" \
    --output "${ARTIFACT_DIR}/missing-source-binding.json"; then
    echo "release gate accepted evidence without source binding" >&2
    exit 1
fi
grep -q 'real_libvirt_e2e: source_commit must match candidate evidence manifest' \
    "${ARTIFACT_DIR}/missing-source-binding.json"
cp "${ARTIFACT_DIR}/e2e-unbound.json" "${ARTIFACT_DIR}/e2e.json"

python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["o3kd_sha256"] = "0" * 64
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" "${GATE_ARGS[@]}" \
    --output "${ARTIFACT_DIR}/mismatched-binary-binding.json"; then
    echo "release gate accepted evidence for a different binary" >&2
    exit 1
fi
grep -q 'real_libvirt_e2e: o3kd_sha256 must match candidate evidence manifest' \
    "${ARTIFACT_DIR}/mismatched-binary-binding.json"
cp "${ARTIFACT_DIR}/e2e-unbound.json" "${ARTIFACT_DIR}/e2e.json"

# Contract negatives for the e2e artifact. Each mutation must block the gate;
# membership/vocabulary errors come from the shared validator, and the
# passed => all-verified_absent policy stays a gate check.
run_e2e_gate_expect_failure() {
    local output="$1" expected_error="$2"
    if bash "${ROOT_DIR}/packaging/release-gate.sh" \
        "${GATE_ARGS[@]}" --output "${output}"; then
        echo "release gate accepted a contract-violating e2e artifact" >&2
        exit 1
    fi
    grep -q "${expected_error}" "${output}"
    cp "${ARTIFACT_DIR}/e2e.pristine.json" "${ARTIFACT_DIR}/e2e.json"
}

python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
del value["resources"]["port_id"]
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
run_e2e_gate_expect_failure "${ARTIFACT_DIR}/missing-port-id.json" \
    'resources: missing required keys: port_id'

python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
del value["cleanup"]["resources"]["port"]
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
run_e2e_gate_expect_failure "${ARTIFACT_DIR}/missing-port-cleanup.json" \
    'cleanup.resources: missing required keys: port'

python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["cleanup"]["resources"]["port"] = "not_verified"
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
run_e2e_gate_expect_failure "${ARTIFACT_DIR}/unverified-port.json" \
    'cleanup.resources must prove every resource absent'

python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
del value["cleanup"]["resources"]["server"]
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
run_e2e_gate_expect_failure "${ARTIFACT_DIR}/missing-server-cleanup.json" \
    'cleanup.resources: missing required keys: server'

python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["resources"]["volume_id"] = "00000000-0000-0000-0000-0000000000ff"
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
run_e2e_gate_expect_failure "${ARTIFACT_DIR}/extra-resource-key.json" \
    'resources: unexpected keys: volume_id'

if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --source-commit "fedcba9876543210fedcba9876543210fedcba98" \
    --output "${ARTIFACT_DIR}/wrong-source-commit.json"; then
    echo "release gate accepted a valid but unrelated source commit" >&2
    exit 1
fi
grep -q 'source_commit: must match the repository checkout HEAD' \
    "${ARTIFACT_DIR}/wrong-source-commit.json"

if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --source-commit "952dcf9c4a1ae958996e4ae9444763e5524eddc5" \
    --output "${ARTIFACT_DIR}/rejected-historical-candidate.json"; then
    echo "release gate accepted the permanently rejected historical candidate" >&2
    exit 1
fi
grep -q 'historical candidate 952dcf9c4a1ae958996e4ae9444763e5524eddc5 is rejected and ineligible' \
    "${ARTIFACT_DIR}/rejected-historical-candidate.json"

cp "${ARTIFACT_DIR}/recovery.json" "${ARTIFACT_DIR}/recovery-missing-evidence.json"
python3 - "${ARTIFACT_DIR}/recovery-missing-evidence.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
del value["scenarios"]["partial-cleanup"]["evidence"]
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    --e2e "${ARTIFACT_DIR}/e2e.json" \
    --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json" \
    --install-debian "${ARTIFACT_DIR}/debian.json" \
    --recovery "${ARTIFACT_DIR}/recovery-missing-evidence.json" \
    --benchmark "${ARTIFACT_DIR}/benchmark.json" \
    --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json" \
    --human-review "${HUMAN_REVIEW}" \
    --source-commit "${SOURCE_COMMIT}" \
    --candidate-evidence-manifest "${ARTIFACT_DIR}/candidate-evidence-manifest.json" \
    --output "${ARTIFACT_DIR}/missing-recovery-evidence.json"; then
    echo "release gate accepted a scenario without evidence" >&2
    exit 1
fi
grep -q 'failure_recovery: scenarios.partial-cleanup.evidence must identify an artifact and checks' \
    "${ARTIFACT_DIR}/missing-recovery-evidence.json"

python3 - "${HUMAN_REVIEW}" <<'PY'
import json, os, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["reviewed_commit"] = "fedcba9876543210fedcba9876543210fedcba98"
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/mismatched-review.json"; then
    echo "release gate accepted human review for a different commit" >&2
    exit 1
fi
grep -q 'human_review: reviewed_commit must match source_commit' "${ARTIFACT_DIR}/mismatched-review.json"
python3 - "${HUMAN_REVIEW}" <<'PY'
import json, os, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["reviewed_commit"] = os.environ["SOURCE_COMMIT"]
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY

set_e2e_finished_at() {
    python3 - "${ARTIFACT_DIR}/e2e.json" "$1" <<'PY'
import json, pathlib, sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["finished_at"] = int(sys.argv[2])
path.write_text(json.dumps(value), encoding="utf-8")
PY
}

set_benchmark_raw_finished_at() {
    python3 - "${ARTIFACT_DIR}/benchmark-raw.json" "${ARTIFACT_DIR}/benchmark.json" "$1" <<'PY'
import hashlib, json, pathlib, sys

raw_path = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
raw = json.loads(raw_path.read_text(encoding="utf-8"))
raw["finished_at"] = int(sys.argv[3])
raw_path.write_text(json.dumps(raw), encoding="utf-8")
canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
summary = json.loads(summary_path.read_text(encoding="utf-8"))
summary["finished_at"] = int(sys.argv[3])
summary["raw_sha256"] = hashlib.sha256(canonical).hexdigest()
summary_path.write_text(json.dumps(summary), encoding="utf-8")
PY
}

set_benchmark_raw_timestamp_only() {
    python3 - "${ARTIFACT_DIR}/benchmark-raw.json" "${ARTIFACT_DIR}/benchmark.json" "$1" <<'PY'
import hashlib, json, pathlib, sys

raw_path = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
raw = json.loads(raw_path.read_text(encoding="utf-8"))
raw["finished_at"] = int(sys.argv[3])
raw_path.write_text(json.dumps(raw), encoding="utf-8")
canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
summary = json.loads(summary_path.read_text(encoding="utf-8"))
summary["raw_sha256"] = hashlib.sha256(canonical).hexdigest()
summary_path.write_text(json.dumps(summary), encoding="utf-8")
PY
}

set_e2e_finished_at "$(python3 - <<'PY'
import time
print(int(time.time()) - 3_601)
PY
)"
if O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS=3600 bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/stale-release.json"; then
    echo "release gate accepted stale evidence" >&2
    exit 1
fi
grep -q 'older than the configured maximum age' "${ARTIFACT_DIR}/stale-release.json"

set_e2e_finished_at "$(python3 - <<'PY'
import time
print(int(time.time()))
PY
)"

set_benchmark_raw_timestamp_only "$(python3 - <<'PY'
import time
print(int(time.time()) - 3_601)
PY
)"
if O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS=3600 bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/stale-raw-release.json"; then
    echo "release gate accepted stale raw benchmark evidence" >&2
    exit 1
fi
grep -q 'benchmark_raw: finished_at is older than the configured maximum age' "${ARTIFACT_DIR}/stale-raw-release.json"
set_benchmark_raw_finished_at "$(python3 - <<'PY'
import time
print(int(time.time()))
PY
)"
set_benchmark_raw_timestamp_only "$(python3 - "${ARTIFACT_DIR}/benchmark.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(summary["finished_at"] + 1)
PY
)"
if O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS=3600 bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/mismatched-benchmark-timestamps.json"; then
    echo "release gate accepted mismatched benchmark timestamps" >&2
    exit 1
fi
grep -q 'benchmark: finished_at must match benchmark_raw.finished_at' "${ARTIFACT_DIR}/mismatched-benchmark-timestamps.json"
set_benchmark_raw_finished_at "$(python3 - <<'PY'
import time
print(int(time.time()))
PY
)"

python3 - "${ARTIFACT_DIR}/benchmark-raw.json" "${ARTIFACT_DIR}/benchmark.json" <<'PY'
import hashlib, json, pathlib, sys

raw_path, summary_path = map(pathlib.Path, sys.argv[1:])
raw = json.loads(raw_path.read_text(encoding="utf-8"))
summary = json.loads(summary_path.read_text(encoding="utf-8"))
raw["release_eligible"] = False
summary["release_eligible"] = False
raw_path.write_text(json.dumps(raw), encoding="utf-8")
summary["raw_sha256"] = hashlib.sha256(
    json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
).hexdigest()
summary_path.write_text(json.dumps(summary), encoding="utf-8")
PY
if O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS=3600 bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/ineligible-benchmark.json"; then
    echo "release gate accepted an ineligible benchmark" >&2
    exit 1
fi
grep -q 'benchmark: release_eligible must be true' "${ARTIFACT_DIR}/ineligible-benchmark.json"
grep -q 'benchmark_raw: release_eligible must be true' "${ARTIFACT_DIR}/ineligible-benchmark.json"
python3 - "${ARTIFACT_DIR}/benchmark-raw.json" "${ARTIFACT_DIR}/benchmark.json" <<'PY'
import hashlib, json, pathlib, sys

raw_path, summary_path = map(pathlib.Path, sys.argv[1:])
raw = json.loads(raw_path.read_text(encoding="utf-8"))
summary = json.loads(summary_path.read_text(encoding="utf-8"))
raw["release_eligible"] = True
summary["release_eligible"] = True
raw_path.write_text(json.dumps(raw), encoding="utf-8")
summary["raw_sha256"] = hashlib.sha256(
    json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
).hexdigest()
summary_path.write_text(json.dumps(summary), encoding="utf-8")
PY

set_e2e_finished_at -1
if O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS=3600 bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/negative-release.json"; then
    echo "release gate accepted a negative evidence timestamp" >&2
    exit 1
fi
grep -q 'finished_at must be positive' "${ARTIFACT_DIR}/negative-release.json"

set_e2e_finished_at 0
if O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS=3600 bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/zero-release.json"; then
    echo "release gate accepted a zero evidence timestamp" >&2
    exit 1
fi
grep -q 'finished_at must be positive' "${ARTIFACT_DIR}/zero-release.json"

set_e2e_finished_at "$(python3 - <<'PY'
import time
# Keep the future timestamp comfortably beyond the gate's validation boundary.
print(int(time.time()) + 3600)
PY
)"
if O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS=3600 bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/future-release.json"; then
    echo "release gate accepted future-dated evidence" >&2
    exit 1
fi
grep -q 'finished_at cannot be in the future' "${ARTIFACT_DIR}/future-release.json"

python3 - "${ARTIFACT_DIR}/e2e.json" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump({"status": "passed"}, output)
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    --e2e "${ARTIFACT_DIR}/e2e.json" \
    --install-ubuntu "${ARTIFACT_DIR}/ubuntu.json" \
    --install-debian "${ARTIFACT_DIR}/debian.json" \
    --recovery "${ARTIFACT_DIR}/recovery.json" \
    --benchmark "${ARTIFACT_DIR}/benchmark.json" \
    --benchmark-raw "${ARTIFACT_DIR}/benchmark-raw.json" \
    --output "${ARTIFACT_DIR}/invalid-release.json"; then
    echo "release gate accepted an underspecified artifact" >&2
    exit 1
fi

python3 - "${ARTIFACT_DIR}/benchmark-raw.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
del value["environment"]["rustc"]
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/missing-environment.json"; then
    echo "release gate accepted raw benchmark without required environment metadata" >&2
    exit 1
fi
grep -q 'benchmark_raw: environment.rustc must be a non-empty string' "${ARTIFACT_DIR}/missing-environment.json"

python3 - "${ARTIFACT_DIR}/benchmark-raw.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["environment"]["rustc"] = "rustc 1.97.1"
value["samples"] = 6
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/inconsistent-release.json"; then
    echo "release gate accepted inconsistent benchmark summary/raw" >&2
    exit 1
fi
grep -q 'benchmark: samples must match benchmark_raw.samples' "${ARTIFACT_DIR}/inconsistent-release.json"

python3 - "${ARTIFACT_DIR}/benchmark-raw.json" "${ARTIFACT_DIR}/benchmark.json" <<'PY'
import hashlib, json, sys
raw_path, summary_path = sys.argv[1:]
raw = json.loads(open(raw_path, encoding="utf-8").read())
summary = json.loads(open(summary_path, encoding="utf-8").read())
raw["control_plane"]["startup_readiness_ms"] = 3000
summary["control_plane"] = raw["control_plane"]
summary["raw_sha256"] = hashlib.sha256(
    json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
).hexdigest()
open(raw_path, "w", encoding="utf-8").write(json.dumps(raw))
open(summary_path, "w", encoding="utf-8").write(json.dumps(summary))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/forged-target-evaluation.json"; then
    echo "release gate accepted forged benchmark target evaluation" >&2
    exit 1
fi
grep -q 'benchmark: targets_evaluated does not match raw measurements' "${ARTIFACT_DIR}/forged-target-evaluation.json"

python3 - "${ARTIFACT_DIR}/benchmark-raw.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["samples"] = 5
value["control_plane"]["startup_readiness_ms"] = 101
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/tampered-release.json"; then
    echo "release gate accepted cryptographically unbound raw benchmark" >&2
    exit 1
fi
grep -q 'benchmark: raw_sha256 does not match benchmark_raw' "${ARTIFACT_DIR}/tampered-release.json"

python3 - "${ARTIFACT_DIR}/recovery.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
del value["scenarios"]["partial-cleanup"]
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/missing-recovery-scenario.json"; then
    echo "release gate accepted an incomplete failure-recovery artifact" >&2
    exit 1
fi
grep -q 'failure_recovery: scenarios missing required keys: partial-cleanup' "${ARTIFACT_DIR}/missing-recovery-scenario.json"

python3 - "${ARTIFACT_DIR}/recovery.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["scenarios"]["partial-cleanup"] = {"status": "failed"}
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
if bash "${ROOT_DIR}/packaging/release-gate.sh" \
    "${GATE_ARGS[@]}" --output "${ARTIFACT_DIR}/failed-recovery-scenario.json"; then
    echo "release gate accepted a failed failure-recovery scenario" >&2
    exit 1
fi
grep -q "failure_recovery: scenarios.partial-cleanup.status must be 'passed'" "${ARTIFACT_DIR}/failed-recovery-scenario.json"

PREFLIGHT_ARTIFACT_DIR="${ARTIFACT_DIR}/preflight"
O3K_TESTLAB_ARTIFACT_DIR="${PREFLIGHT_ARTIFACT_DIR}" bash "${ROOT_DIR}/tests/testlab-libvirt.sh"
grep -q '"status": "skipped"' "${PREFLIGHT_ARTIFACT_DIR}/libvirt-result.json"

echo "release gate schema tests passed"
