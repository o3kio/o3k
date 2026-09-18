#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Running product-profile status governance validator..."
python3 "${repo_root}/scripts/validate-profile-state.py" --root "${repo_root}"
bash "${repo_root}/tests/p15_7_scale_composition_guards.sh"

echo "Running PP.0 frozen profile and release/installer contract validation..."
bash "${repo_root}/tests/pp0-contracts.sh"

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/o3k-profile-state.XXXXXX")"
trap 'rm -rf "${temp_dir}"' EXIT

# Mutate a copy of the real status file; every mutation must be rejected.
mutate() {
  local target="$1"
  shift
  local mutation_name="$1"
  python3 - "${repo_root}/docs/status/current-state.yaml" "${target}" "${mutation_name}" <<'PY'
import sys
import yaml

source, target, mutation_name = sys.argv[1], sys.argv[2], sys.argv[3]
with open(source, encoding="utf-8") as handle:
    doc = yaml.safe_load(handle)
mutations = {
    "rename-profile": lambda d: d["profiles"].__setitem__(
        "native-rust-testlab-x", d["profiles"].pop("native-rust-testlab")
    ),
    "missing-field": lambda d: d["profiles"]["native-rust-testlab"].pop(
        "explicitly_unproven_claims"
    ),
    "cinder-evidence-in-native": lambda d: d["profiles"]["native-rust-testlab"][
        "portable_evidence"
    ].append({"name": "real-cinder-lifecycle", "state": "passed"}),
    "native-full-profile-passed": lambda d: d["profiles"]["native-rust-testlab"][
        "full_profile_evidence"
    ][0].__setitem__("state", "passed"),
    "bad-evidence-state": lambda d: d["profiles"]["native-rust-testlab"][
        "portable_evidence"
    ][0].__setitem__("state", "banana"),
    "bad-source-commit": lambda d: d["profiles"]["native-rust-testlab"].__setitem__(
        "source_commit", "0" * 40
    ),
    "claim-e2d-drift": lambda d: d["claim_reconciliation"]["e2d_status"].__setitem__(
        "E2D-18", "OPEN"
    ),
    "claim-source-drift": lambda d: d["claim_reconciliation"]["sources"].remove(
        "docs/ROADMAP.md"
    ),
    "cross-profile-evidence-without-shared-run": lambda d: d["profiles"][
        "small-edge-cloud"
    ]["portable_evidence"].append(
        {"name": "p15-7-scale-composition-real-host-gate", "state": "passed"}
    ),
    "inherited-evidence-without-source": lambda d: d["profiles"]["o3k-demo-v1"][
        "protected_component_evidence"
    ][0].pop("inherited_from"),
}
mutations[mutation_name](doc)
with open(target, "w", encoding="utf-8") as handle:
    yaml.safe_dump(doc, handle, sort_keys=False)
PY
}

for mutation in rename-profile missing-field cinder-evidence-in-native \
    native-full-profile-passed bad-evidence-state bad-source-commit \
    claim-e2d-drift claim-source-drift cross-profile-evidence-without-shared-run \
    inherited-evidence-without-source; do
  mutated="${temp_dir}/status-${mutation}.yaml"
  mutate "${mutated}" "${mutation}"
  if python3 "${repo_root}/scripts/validate-profile-state.py" \
      --root "${repo_root}" --status-file "${mutated}" >/dev/null 2>&1; then
    echo "ERROR: validator accepted mutated status (${mutation})" >&2
    exit 1
  fi
  echo "mutation rejected: ${mutation}"
done

duplicate_profiles="${temp_dir}/product-profiles-duplicate.yaml"
cp "${repo_root}/compatibility/product-profiles.yaml" "${duplicate_profiles}"
printf '\nprofiles: []\n' >>"${duplicate_profiles}"
if python3 "${repo_root}/scripts/validate-profile-state.py" \
    --root "${repo_root}" --profiles-file "${duplicate_profiles}" >/dev/null 2>&1; then
  echo "ERROR: validator accepted duplicate YAML mapping keys" >&2
  exit 1
fi
echo "mutation rejected: duplicate-yaml-key"

echo "Product-profile status governance tests passed"
