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

ea_closure_guard="${ROOT_DIR}/.github/workflows/ea-epic-closure-guard.yml"
grep -Fq 'github.event.issue.number == 1241' "${ea_closure_guard}"
grep -Fq 'ea-final-go' "${ea_closure_guard}"
grep -Fq 'EA-OWNER-GO' "${ea_closure_guard}"
grep -Fq 'SPEC-0052 acceptance evidence:' "${ea_closure_guard}"
grep -Fq 'EA_OWNER_LOGIN: senolcolak' "${ea_closure_guard}"
grep -Fq 'gh api --method PATCH "$issue_api" --field state=open' "${ea_closure_guard}"

# Fail-safe and legitimate-closure fixture checks mirror the guard's jq
# predicates without contacting GitHub: label-only and owner-marker-only
# inputs fail, while the complete label + owner evidence pair passes.
fixture="${WORK_DIR}/ea-closure-fixtures.json"
cat >"${fixture}" <<'JSON'
[
  {"name":"label-only","labels":["ea-final-go"],"owner_go":false,"expected":false},
  {"name":"owner-marker-only","labels":[],"owner_go":true,"expected":false},
  {"name":"complete","labels":["ea-final-go"],"owner_go":true,"expected":true}
]
JSON
if ! python3 - "${fixture}" <<'PY'
import json
import sys

for row in json.load(open(sys.argv[1], encoding="utf-8")):
    accepted = "ea-final-go" in row["labels"] and row["owner_go"] is True
    assert accepted is row["expected"], row
PY
then
    echo "EA closure guard fixture checks failed" >&2
    exit 1
fi

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
