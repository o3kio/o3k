#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="${ROOT_DIR}/.github/workflows/real-lvm-provider.yml"
PROFILE="${ROOT_DIR}/scripts/lvm-testlab-profile.sh"

test -f "${WORKFLOW}"
test -f "${PROFILE}"
bash -n "${PROFILE}"

python3 - "${WORKFLOW}" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
required = (
    "workflow_dispatch:",
    "runs-on: [self-hosted, linux, x64, kvm, libvirt, o3k-testlab]",
    'test "${GITHUB_REPOSITORY}" = "o3kio/o3k"',
    'test "${GITHUB_REF}" = "refs/heads/main"',
    "sudo -n true",
    "run_slug=",
    "O3K_LVM_VG_NAME: o3k-lvm-${{ steps.runner.outputs.run_slug }}",
    "O3K_LVM_THIN_POOL: o3k-thin-${{ steps.runner.outputs.run_slug }}",
    "scripts/lvm-testlab-profile.sh provision",
    "scripts/lvm-testlab-profile.sh cleanup",
    "if: always()",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
)
for needle in required:
    assert needle in text, needle
assert "rm -rf" not in text
assert "o3k-storage start" not in text
assert "O3K_LVM_THIN_POOL_NAME" not in text
PY

echo "LVM provider workflow guard tests passed"
