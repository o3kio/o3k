#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTIONLINT="${1:-actionlint}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-workflow-validation.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT

bash "${ROOT_DIR}/scripts/validate-workflows.sh" "${ACTIONLINT}"

closure_guard="${ROOT_DIR}/.github/workflows/pp6-epic-closure-guard.yml"
grep -Fq 'types: [closed]' "${closure_guard}"
grep -Fq 'github.event.issue.number == 975' "${closure_guard}"
grep -Fq "!contains(github.event.issue.labels.*.name, 'pp6-final-go')" "${closure_guard}"
grep -Fq 'gh api --method PATCH "$issue_api" --field state=open' "${closure_guard}"

duplicate_workflow="${WORK_DIR}/duplicate.yml"
cat >"${duplicate_workflow}" <<'YAML'
name: duplicate-key-regression
on:
  workflow_dispatch:
jobs:
  duplicate:
    runs-on: ubuntu-latest
    steps:
      - name: Duplicate environment key
        run: true
        env:
          DUPLICATE: first
          DUPLICATE: second
YAML

if "${ACTIONLINT}" "${duplicate_workflow}" >/dev/null 2>&1; then
    echo "workflow validator accepted duplicate mapping keys" >&2
    exit 1
fi

echo "workflow validation and duplicate-key regression tests passed"
