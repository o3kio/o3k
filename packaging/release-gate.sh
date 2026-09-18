#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT=release-evidence.json
E2E=
INSTALL_UBUNTU=
INSTALL_DEBIAN=
RECOVERY=
BENCHMARK=
BENCHMARK_RAW=
HUMAN_REVIEW=
SOURCE_COMMIT=
CANDIDATE_EVIDENCE_MANIFEST=
while (($#)); do
  case "$1" in
    --e2e) E2E="${2:?missing E2E artifact}"; shift 2;;
    --install-ubuntu) INSTALL_UBUNTU="${2:?missing Ubuntu artifact}"; shift 2;;
    --install-debian) INSTALL_DEBIAN="${2:?missing Debian artifact}"; shift 2;;
    --recovery) RECOVERY="${2:?missing recovery artifact}"; shift 2;;
    --benchmark) BENCHMARK="${2:?missing benchmark artifact}"; shift 2;;
    --benchmark-raw) BENCHMARK_RAW="${2:?missing raw benchmark artifact}"; shift 2;;
    --human-review) HUMAN_REVIEW="${2:?missing human-review artifact}"; shift 2;;
    --source-commit) SOURCE_COMMIT="${2:?missing source commit}"; shift 2;;
    --candidate-evidence-manifest) CANDIDATE_EVIDENCE_MANIFEST="${2:?missing candidate evidence manifest}"; shift 2;;
    --output) OUTPUT="${2:?missing output path}"; shift 2;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
HUMAN_REVIEW_VALIDATION_ERROR=
if [[ -z "$HUMAN_REVIEW" ]]; then
  HUMAN_REVIEW_VALIDATION_ERROR="human_review: artifact path was not supplied"
else
  set +e
  HUMAN_REVIEW_VALIDATION_OUTPUT="$(bash "$SCRIPT_DIR/validate-human-review.sh" --input "$HUMAN_REVIEW" --require-approved 2>&1)"
  HUMAN_REVIEW_VALIDATION_STATUS=$?
  set -e
  if (( HUMAN_REVIEW_VALIDATION_STATUS != 0 )); then
    HUMAN_REVIEW_VALIDATION_ERROR="human_review: validator rejected artifact: ${HUMAN_REVIEW_VALIDATION_OUTPUT//$'\n'/; }"
  fi
fi
export E2E INSTALL_UBUNTU INSTALL_DEBIAN RECOVERY BENCHMARK BENCHMARK_RAW HUMAN_REVIEW OUTPUT SOURCE_COMMIT CANDIDATE_EVIDENCE_MANIFEST HUMAN_REVIEW_VALIDATION_ERROR REPOSITORY_ROOT
python3 <<'PY'
import hashlib
import json
import os
import re
import subprocess
import sys
import time

DEFAULT_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
# Historical candidate 952dcf9c4a1ae958996e4ae9444763e5524eddc5 was
# independently rejected by issue #92.  It must remain ineligible even if a
# caller supplies matching historical evidence from a checkout at that SHA.
REJECTED_SOURCE_COMMITS = {
    "952dcf9c4a1ae958996e4ae9444763e5524eddc5",
}
max_age_text = os.environ.get(
    "O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS",
    str(DEFAULT_MAX_AGE_SECONDS),
)
try:
    max_age_seconds = int(max_age_text)
except ValueError:
    max_age_seconds = DEFAULT_MAX_AGE_SECONDS
    max_age_error = (
        "O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS must be a positive integer"
    )
else:
    max_age_error = None
    if max_age_seconds <= 0:
        max_age_error = (
            "O3K_RELEASE_EVIDENCE_MAX_AGE_SECONDS must be a positive integer"
        )
required = {
    "real_libvirt_e2e": (os.environ["E2E"], "openstack-cli-e2e"),
    "clean_ubuntu_install": (os.environ["INSTALL_UBUNTU"], "clean-install"),
    "clean_debian_install": (os.environ["INSTALL_DEBIAN"], "clean-install"),
    "failure_recovery": (os.environ["RECOVERY"], "failure-recovery"),
}
required["benchmark"] = (os.environ["BENCHMARK"], "benchmark")
errors = []
if max_age_error:
    errors.append(max_age_error)
evidence = {}
paths = {}
source_commit = os.environ["SOURCE_COMMIT"]
manifest = None
manifest_path = os.environ.get("CANDIDATE_EVIDENCE_MANIFEST", "")
if not manifest_path:
    errors.append("candidate_evidence_manifest: artifact path was not supplied")
else:
    try:
        with open(manifest_path, encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"candidate_evidence_manifest: cannot read JSON artifact ({error})")
    if not isinstance(manifest, dict):
        errors.append("candidate_evidence_manifest: artifact root must be an object")
        manifest = None
if isinstance(manifest, dict):
    if manifest.get("artifact_type") != "candidate-evidence-manifest":
        errors.append("candidate_evidence_manifest: artifact_type must be 'candidate-evidence-manifest'")
    if manifest.get("candidate_sha") != source_commit:
        errors.append("candidate_evidence_manifest: candidate_sha must match source_commit")
    for field in ("o3kd_sha256", "o3k_compute_sha256", "bundle_tree_sha256"):
        if not isinstance(manifest.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", manifest[field]):
            errors.append(f"candidate_evidence_manifest: {field} must be a lowercase SHA-256 hex digest")
    if not isinstance(manifest.get("artifacts"), dict):
        errors.append("candidate_evidence_manifest: artifacts must be an object")
    else:
        manifest_real_path = os.path.realpath(manifest_path)
        if manifest_real_path in paths:
            errors.append("candidate_evidence_manifest: artifact reuses another gate input")
        else:
            paths[manifest_real_path] = "candidate_evidence_manifest"
human_review_path = os.environ["HUMAN_REVIEW"]
human_review_validation_error = os.environ["HUMAN_REVIEW_VALIDATION_ERROR"]
if human_review_validation_error:
    errors.append(human_review_validation_error)
if not source_commit:
    errors.append("source_commit: value was not supplied")
elif not re.fullmatch(r"[0-9a-f]{40}", source_commit):
    errors.append("source_commit: must be a 40-character lowercase commit SHA")
elif source_commit in REJECTED_SOURCE_COMMITS:
    errors.append(
        "source_commit: historical candidate 952dcf9c4a1ae958996e4ae9444763e5524eddc5 is rejected and ineligible"
    )
else:
    try:
        checkout_commit = subprocess.run(
            ["git", "-C", os.environ["REPOSITORY_ROOT"], "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        checkout_commit = ""
    if not re.fullmatch(r"[0-9a-f]{40}", checkout_commit):
        errors.append("source_commit: could not verify the repository checkout HEAD")
    elif source_commit != checkout_commit:
        errors.append("source_commit: must match the repository checkout HEAD")
human_review = None
if human_review_path:
    human_review_real_path = os.path.realpath(human_review_path)
    if human_review_real_path in paths:
        errors.append(
            "human_review: artifact reuses "
            f"{paths[human_review_real_path]}; each gate input must be distinct"
        )
    else:
        paths[human_review_real_path] = "human_review"
    try:
        with open(human_review_path, encoding="utf-8") as stream:
            human_review = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"human_review: cannot read JSON artifact ({error})")
    if isinstance(human_review, dict):
        if source_commit and human_review.get("reviewed_commit") != source_commit:
            errors.append("human_review: reviewed_commit must match source_commit")
        evidence["human_review"] = {
            "path": human_review_path,
            "artifact_type": human_review.get("artifact_type"),
            "status": human_review.get("status"),
            "reviewed_commit": human_review.get("reviewed_commit"),
        }
    else:
        evidence["human_review"] = {"path": human_review_path}
else:
    evidence["human_review"] = {}
benchmark_summary = None
now = int(time.time())
for name, (path, artifact_type) in required.items():
    if not path:
        errors.append(f"{name}: artifact path was not supplied")
        continue
    real_path = os.path.realpath(path)
    if real_path in paths:
        errors.append(f"{name}: artifact reuses {paths[real_path]}; each gate input must be distinct")
        continue
    paths[real_path] = name
    try:
        with open(path, encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{name}: cannot read JSON artifact ({error})")
        continue
    if not isinstance(value, dict):
        errors.append(f"{name}: artifact root must be an object")
        continue
    if name == "benchmark":
        benchmark_summary = value
    status = value.get("status")
    evidence[name] = {
        "path": path,
        "artifact_type": value.get("artifact_type"),
        "profile": value.get("profile"),
        "status": status,
    }
    binding = manifest.get("artifacts", {}).get(name) if isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), dict) else None
    if not isinstance(binding, dict):
        errors.append(f"{name}: candidate evidence manifest entry is required")
    else:
        if not isinstance(binding.get("artifact"), str) or not binding["artifact"].strip():
            errors.append(f"{name}: manifest artifact path is required")
        elif os.path.realpath(os.path.join(os.path.dirname(manifest_path), binding["artifact"])) != os.path.realpath(path):
            errors.append(f"{name}: artifact path does not match candidate evidence manifest")
        actual_sha256 = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if binding.get("artifact_sha256") != actual_sha256:
            errors.append(f"{name}: artifact_sha256 does not match candidate evidence manifest")
        for field in ("source_commit", "o3kd_sha256", "o3k_compute_sha256", "bundle_tree_sha256"):
            expected = manifest.get("candidate_sha") if field == "source_commit" else manifest.get(field)
            if not isinstance(value.get(field), str) or value.get(field) != expected:
                errors.append(f"{name}: {field} must match candidate evidence manifest")
    if value.get("artifact_type") != artifact_type:
        errors.append(f"{name}: artifact_type must be {artifact_type!r}")
    if value.get("profile") != "libvirt":
        errors.append(f"{name}: profile must be 'libvirt'")
    if value.get("redacted") is not True:
        errors.append(f"{name}: redacted must be true")
    finished_at = value.get("finished_at")
    if isinstance(finished_at, bool) or not isinstance(finished_at, int):
        errors.append(f"{name}: finished_at must be an integer epoch timestamp")
    elif finished_at <= 0:
        errors.append(f"{name}: finished_at must be positive")
    elif finished_at > now:
        errors.append(f"{name}: finished_at cannot be in the future")
    elif now - finished_at > max_age_seconds:
        errors.append(
            f"{name}: finished_at is older than the configured maximum age "
            f"({max_age_seconds} seconds)"
        )
    cleanup = value.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("status") != "passed":
        errors.append(f"{name}: cleanup.status must be 'passed'")
    if name == "benchmark":
        if status != "measured":
            errors.append(f"{name}: status must be measured, got {status!r}")
        if value.get("release_eligible") is not True:
            errors.append(f"{name}: release_eligible must be true")
        guest = value.get("guest_and_libvirt")
        if not isinstance(guest, dict) or guest.get("status") != "measured":
            errors.append(f"{name}: guest_and_libvirt.status must be measured")
        targets = value.get("targets_evaluated")
        if not isinstance(targets, dict) or not targets or not all(targets.values()):
            errors.append(f"{name}: all benchmark targets must evaluate true")
    elif status != "passed":
        errors.append(f"{name}: status must be passed, got {status!r}")
    if name == "real_libvirt_e2e":
        # Resource membership is governed by the normative machine-readable
        # contract, validated by the shared validator; the gate consumes the
        # same validator as the producer and fails closed if it is missing.
        validator_path = os.path.join(
            os.environ["REPOSITORY_ROOT"],
            "scripts",
            "validate-release-e2e-evidence.py",
        )
        if not os.path.isfile(validator_path):
            errors.append(
                f"{name}: contract validator is missing: {validator_path}"
            )
        else:
            try:
                validation = subprocess.run(
                    [sys.executable or "python3", validator_path, path],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except (OSError, subprocess.SubprocessError) as error:
                errors.append(
                    f"{name}: contract validator could not run ({error})"
                )
            else:
                if validation.returncode != 0:
                    errors.append(
                        f"{name}: resources/cleanup.resources must satisfy "
                        "contracts/release-e2e-evidence.schema.json"
                    )
                    for line in validation.stderr.strip().splitlines():
                        if line:
                            errors.append(f"{name}: {line}")
        cleanup_resources = cleanup.get("resources") if isinstance(cleanup, dict) else None
        if status == "passed" and (
            not isinstance(cleanup_resources, dict) or not cleanup_resources
        ):
            errors.append(
                f"{name}: cleanup.resources must identify every created "
                "resource when status is passed"
            )
        elif status == "passed" and any(
            cleanup_resources[resource] != "verified_absent"
            for resource in cleanup_resources
        ):
            errors.append(
                f"{name}: cleanup.resources must prove every resource absent "
                "when status is passed"
            )
        lifecycle = value.get("lifecycle")
        expected = {"create", "show", "list", "stop", "start", "reboot", "console", "delete"}
        if not isinstance(lifecycle, dict) or set(lifecycle) != expected or not all(lifecycle.values()):
            errors.append(f"{name}: lifecycle must prove create/show/list/stop/start/reboot/console/delete")
        acceptance = value.get("acceptance")
        if not isinstance(acceptance, dict):
            errors.append(f"{name}: acceptance evidence is required")
        else:
            if acceptance.get("status") != "ACTIVE":
                errors.append(f"{name}: acceptance.status must be 'ACTIVE'")
            if not isinstance(acceptance.get("fixed_ip"), str) or not acceptance["fixed_ip"].strip():
                errors.append(f"{name}: acceptance.fixed_ip must be a non-empty string")
            if acceptance.get("config_drive") is not True:
                errors.append(f"{name}: acceptance.config_drive must be true")
            if acceptance.get("console_boot_marker") is not True:
                errors.append(f"{name}: acceptance.console_boot_marker must be true")
            restart = acceptance.get("restart")
            if not isinstance(restart, dict):
                errors.append(f"{name}: acceptance.restart evidence is required")
            else:
                if restart.get("status") != "ACTIVE":
                    errors.append(f"{name}: acceptance.restart.status must be 'ACTIVE'")
                if not isinstance(restart.get("fixed_ip"), str) or not restart["fixed_ip"].strip():
                    errors.append(f"{name}: acceptance.restart.fixed_ip must be a non-empty string")
                if restart.get("config_drive") is not True:
                    errors.append(f"{name}: acceptance.restart.config_drive must be true")
        if value.get("public_api_only") is not True:
            errors.append(f"{name}: public_api_only must be true")
    if name == "failure_recovery":
        required_scenarios = {
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
        }
        scenarios = value.get("scenarios")
        if not isinstance(scenarios, dict):
            errors.append(f"{name}: scenarios must be an object keyed by required scenario")
        else:
            missing = required_scenarios - scenarios.keys()
            unexpected = scenarios.keys() - required_scenarios
            if missing:
                errors.append(
                    f"{name}: scenarios missing required keys: {', '.join(sorted(missing))}"
                )
            if unexpected:
                errors.append(
                    f"{name}: scenarios contain unknown keys: {', '.join(sorted(unexpected))}"
                )
            for scenario in sorted(required_scenarios & scenarios.keys()):
                result = scenarios[scenario]
                if not isinstance(result, dict) or result.get("status") != "passed":
                    errors.append(
                        f"{name}: scenarios.{scenario}.status must be 'passed'"
                    )
                elif (
                    not isinstance(result.get("evidence"), dict)
                    or not isinstance(result["evidence"].get("artifact"), str)
                    or not result["evidence"]["artifact"].strip()
                    or not isinstance(result["evidence"].get("checks"), list)
                    or not result["evidence"]["checks"]
                    or not all(
                        isinstance(check, str) and check.strip()
                        for check in result["evidence"]["checks"]
                    )
                ):
                    errors.append(
                        f"{name}: scenarios.{scenario}.evidence must identify an artifact and checks"
                    )
    if name in {"clean_ubuntu_install", "clean_debian_install"}:
        expected_distro = "ubuntu" if name.endswith("ubuntu_install") else "debian"
        if value.get("distro") != expected_distro:
            errors.append(f"{name}: distro must be {expected_distro!r}")
        install = value.get("install")
        if not isinstance(install, dict) or install.get("status") != "passed":
            errors.append(f"{name}: install.status must be 'passed'")

benchmark_raw = None
benchmark_raw_path = os.environ["BENCHMARK_RAW"]
if not benchmark_raw_path:
    errors.append("benchmark_raw: artifact path was not supplied")
else:
    real_path = os.path.realpath(benchmark_raw_path)
    if real_path in paths:
        errors.append(
            "benchmark_raw: artifact reuses "
            f"{paths[real_path]}; each gate input must be distinct"
        )
    else:
        paths[real_path] = "benchmark_raw"
        try:
            with open(benchmark_raw_path, encoding="utf-8") as stream:
                benchmark_raw = json.load(stream)
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"benchmark_raw: cannot read JSON artifact ({error})")
        if benchmark_raw is not None and not isinstance(benchmark_raw, dict):
            errors.append("benchmark_raw: artifact root must be an object")
            benchmark_raw = None

if isinstance(benchmark_raw, dict):
    if benchmark_raw.get("artifact_type") != "benchmark":
        errors.append("benchmark_raw: artifact_type must be 'benchmark'")
    if benchmark_raw.get("status") != "measured":
        errors.append(
            f"benchmark_raw: status must be measured, got {benchmark_raw.get('status')!r}"
        )
    if benchmark_raw.get("profile") != "libvirt":
        errors.append("benchmark_raw: profile must be 'libvirt'")
    if benchmark_raw.get("redacted") is not True:
        errors.append("benchmark_raw: redacted must be true")
    if benchmark_raw.get("release_eligible") is not True:
        errors.append("benchmark_raw: release_eligible must be true")
    raw_finished_at = benchmark_raw.get("finished_at")
    if isinstance(raw_finished_at, bool) or not isinstance(raw_finished_at, int):
        errors.append("benchmark_raw: finished_at must be an integer epoch timestamp")
    elif raw_finished_at <= 0:
        errors.append("benchmark_raw: finished_at must be positive")
    elif raw_finished_at > now:
        errors.append("benchmark_raw: finished_at cannot be in the future")
    elif now - raw_finished_at > max_age_seconds:
        errors.append(
            "benchmark_raw: finished_at is older than the configured maximum age "
            f"({max_age_seconds} seconds)"
        )
    environment = benchmark_raw.get("environment")
    if not isinstance(environment, dict):
        errors.append("benchmark_raw: environment must be an object")
    else:
        for field in ("uname", "rustc"):
            if not isinstance(environment.get(field), str) or not environment[field].strip():
                errors.append(
                    f"benchmark_raw: environment.{field} must be a non-empty string"
                )
    samples = benchmark_raw.get("samples")
    if isinstance(samples, bool) or not isinstance(samples, int) or samples <= 0:
        errors.append("benchmark_raw: samples must be a positive integer")
    for field in ("control_plane", "guest_and_libvirt", "targets"):
        if not isinstance(benchmark_raw.get(field), dict):
            errors.append(f"benchmark_raw: {field} must be an object")
    guest = benchmark_raw.get("guest_and_libvirt")
    if isinstance(guest, dict) and guest.get("status") != "measured":
        errors.append("benchmark_raw: guest_and_libvirt.status must be measured")
    targets = benchmark_raw.get("targets")
    if isinstance(targets, dict):
        for field in ("startup_readiness_ms", "idle_rss_mib", "token_p95_ms"):
            if field not in targets:
                errors.append(f"benchmark_raw: targets.{field} is required")

if isinstance(benchmark_summary, dict) and isinstance(benchmark_raw, dict):
    raw_sha256 = benchmark_summary.get("raw_sha256")
    if not isinstance(raw_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", raw_sha256):
        errors.append("benchmark: raw_sha256 must be a lowercase SHA-256 hex digest")
    else:
        canonical_raw = json.dumps(
            benchmark_raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        expected_sha256 = hashlib.sha256(canonical_raw).hexdigest()
        if raw_sha256 != expected_sha256:
            errors.append("benchmark: raw_sha256 does not match benchmark_raw")
    for field in (
        "samples",
        "finished_at",
        "control_plane",
        "guest_and_libvirt",
        "release_eligible",
    ):
        if benchmark_summary.get(field) != benchmark_raw.get(field):
            errors.append(f"benchmark: {field} must match benchmark_raw.{field}")
    control_plane = benchmark_raw.get("control_plane")
    targets = benchmark_raw.get("targets")
    evaluated = benchmark_summary.get("targets_evaluated")
    if isinstance(control_plane, dict) and isinstance(targets, dict) and isinstance(evaluated, dict):
        measurements = {
            "startup": (control_plane.get("startup_readiness_ms"), targets.get("startup_readiness_ms")),
            "rss": (control_plane.get("idle_rss_kib"), targets.get("idle_rss_mib")),
            "token_p95": (control_plane.get("token_p95_seconds"), targets.get("token_p95_ms")),
        }
        expected = {}
        valid = True
        for name, (measurement, target) in measurements.items():
            if isinstance(measurement, bool) or not isinstance(measurement, (int, float)):
                valid = False
                continue
            if isinstance(target, bool) or not isinstance(target, (int, float)):
                valid = False
                continue
            if name == "rss":
                expected[name] = measurement <= target * 1024
            elif name == "token_p95":
                expected[name] = measurement * 1000 <= target
            else:
                expected[name] = measurement <= target
        if not valid:
            errors.append("benchmark_raw: control_plane measurements and targets must be numeric")
        elif evaluated != expected or not all(expected.values()):
            errors.append("benchmark: targets_evaluated does not match raw measurements")

report = {"release": "v0.4.0-rc.2", "profile": "libvirt", "source_commit": source_commit, "status": "ready" if not errors else "blocked", "evidence": evidence, "errors": errors, "tag_created": False}
with open(os.environ["OUTPUT"], "w", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2, sort_keys=True); stream.write("\n")
if errors:
    print("release gate blocked; see " + os.environ["OUTPUT"], file=sys.stderr)
    for error in errors: print("- " + error, file=sys.stderr)
    sys.exit(1)
print("release gate passed; tag creation remains an explicit operator action")
PY
