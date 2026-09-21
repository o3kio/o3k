#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORKFLOW="${ROOT_DIR}/.github/workflows/ci.yml"

python3 - "${WORKFLOW}" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert "git fetch origin main:refs/remotes/origin/main" in text
assert "buf breaking --against '.git#branch=origin/main,subdir=proto'" in text
assert "packaging/*.sh tests/*.sh scripts/*.sh scripts/ci/*.sh" in text
assert "python3 -m compileall -q scripts" in text
assert "actionlint_1.7.7_linux_amd64.tar.gz" in text
assert "023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757" in text
assert "sha256sum --check --status" in text
assert "run: bash scripts/validate-workflows.sh actionlint" in text
assert "run: bash tests/workflow-validation.sh actionlint" in text
assert "run: bash tests/real-libvirt-harness.sh" in text
assert "run: bash tests/p13_1_provider_harness.sh" in text
assert "run: bash tests/openapi-governance.sh" in text
assert "run: bash tests/toolchain-evidence.sh" in text
assert "run: cargo test --workspace --all-features" in text
assert "run: bash tests/packaging-safety.sh" in text
assert "run: bash tests/packaging-bundle.sh" in text
assert "run: bash tests/doctor-process.sh" in text
assert "run: bash tests/upgrade-process.sh" in text
assert "run: bash tests/helm-lint-and-template.sh" in text
assert "run: bash tests/kubernetes-version-consistency.sh" in text
assert "run: sudo bash tests/installer-negative.sh" in text
assert "run: bash tests/pp4-core-installer-contract.sh" in text
assert "run: bash tests/release-consumer-trust.sh" in text
# The installer-negative matrix skip is vacuous on any non-24.04 runner:
# the dedicated job must stay pinned to ubuntu-24.04.
assert re.search(r"^  installer-negative:\s*\n\s+runs-on: ubuntu-24\.04", text, re.MULTILINE) is not None
assert "run: node --test packaging/get-o3k-worker/test.mjs" in text
assert "run: bash packaging/get-o3k-worker/sync.sh --check" in text
assert "run: cargo test --workspace\n" not in text
assert "protobuf-compiler libvirt-dev pkg-config" in text
assert "cargo clean -p virt-sys" in text
assert "scripts/ci/apt-provision.sh install" in text
assert "apt-get update" not in text
for workflow in pathlib.Path(sys.argv[1]).parent.glob("*.y*ml"):
    workflow_text = workflow.read_text(encoding="utf-8")
    assert "apt-get update" not in workflow_text, workflow
    assert "apt-get install" not in workflow_text, workflow
assert "git fetch origin main:refs/heads/main" not in text
assert "buf breaking --against '.git#branch=main,subdir=proto'" not in text
assert "sha256sum result.json sbom.spdx.json > SHA256SUMS" in text
assert "path: target/testlab-artifacts/" not in text
artifact_paths = re.findall(r"^\s+target/testlab-artifacts/[^\s]+$", text, re.MULTILINE)
assert artifact_paths == [
    "            target/testlab-artifacts/result.json",
    "            target/testlab-artifacts/sbom.spdx.json",
    "            target/testlab-artifacts/SHA256SUMS",
], artifact_paths
for forbidden in (
    "target/testlab-artifacts/o3kd.log",
    "target/testlab-artifacts/openstack-cli-error.log",
    "target/testlab-artifacts/server-show.json",
    "target/testlab-artifacts/server-list.json",
    "target/testlab-artifacts/server-show-after-reboot.json",
    "target/testlab-artifacts/console.log",
    "target/testlab-artifacts/console-error.log",
    "target/testlab-artifacts/credentials",
    "target/testlab-artifacts/secrets",
):
    assert forbidden not in text, forbidden

for workflow in pathlib.Path(sys.argv[1]).parent.glob("*.y*ml"):
    for line in workflow.read_text(encoding="utf-8").splitlines():
        if "uses:" in line:
            assert re.search(r"uses:\s+[^\s]+@[0-9a-f]{40}(?:\s+#.*)?$", line), line
real_host = pathlib.Path(sys.argv[1]).parent / "real-host-validation.yml"
real_host_text = real_host.read_text(encoding="utf-8")
assert "github.repository == 'o3kio/o3k'" in real_host_text
assert "github.event_name == 'workflow_dispatch'" in real_host_text
assert "github.ref == 'refs/heads/main' || inputs.target_sha != ''" in real_host_text
assert "target_sha:" in real_host_text
assert "ref: ${{ inputs.target_sha || github.sha }}" in real_host_text
assert "target/real-host-workflow-artifacts/console.log" not in real_host_text
assert "target/real-host-workflow-artifacts/server-show.json" not in real_host_text
assert "target/real-host-workflow-artifacts/openstack-cli-result.json" in real_host_text
assert "target/real-host-workflow-artifacts/console-result.json" in real_host_text
assert "Download and verify CirrOS image" in real_host_text
assert "id: image" in real_host_text
assert "steps.bootstrap.outcome == 'success' && steps.image.outcome == 'success'" in real_host_text
assert "CIRROS_IMAGE_URL: https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img" in real_host_text
assert "CIRROS_IMAGE_SHA256: 7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b" in real_host_text
assert "printf 'O3K_TESTLAB_IMAGE_PATH=%s\\n'" in real_host_text
assert "--connect-timeout 15 --max-time 300" in real_host_text
assert "O3K_TESTLAB_CONSOLE_REQUEST_TIMEOUT_SECONDS: 25" in real_host_text
assert "timeout-minutes: 120" in real_host_text
assert "Bootstrap disposable TestLab" in real_host_text
assert "scripts/bootstrap-disposable-testlab.sh" in real_host_text
assert "scripts/cleanup-disposable-testlab.sh" in real_host_text
assert "disposable-testlab-bootstrap.json" in real_host_text
real_cinder = pathlib.Path(sys.argv[1]).parent / "real-cinder-testbed.yml"
real_cinder_text = real_cinder.read_text(encoding="utf-8")
assert "if: github.repository == 'o3kio/o3k' && github.ref == 'refs/heads/main'" in real_cinder_text
assert "scripts/real-cinder-testbed-runner.sh --keep" in real_cinder_text
assert "scripts/real-cinder-pre-run-guard.sh" in real_cinder_text
assert "scripts/real-cinder-post-run-guard.sh" in real_cinder_text
assert "Remove run-owned state root" in real_cinder_text
assert "real-cinder-environment.json" in real_cinder_text
assert "tempest-cinder-summary.json" in real_cinder_text
assert "real-cinder-runner-result.json" in real_cinder_text
PY

echo "CI workflow contract tests passed"
