#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Running core architecture boundary ratchet..."
bash "${repo_root}/tests/architecture-boundaries.sh"

echo "Running primary ADR governance and normative drift validator..."
python3 "${repo_root}/scripts/validate-adr-index.py" --root "${repo_root}"

echo "Testing negative scenarios for ADR governance validator..."

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/o3k-adr-test.XXXXXX")"
trap 'rm -rf "${temp_dir}"' EXIT

# Create minimal valid repo mock
mkdir -p "${temp_dir}/docs/adr" "${temp_dir}/docs/specs"
cat <<'EOF' > "${temp_dir}/docs/adr/ADR-0001-test-one.md"
# ADR-0001 — Test One

Status: Accepted
Date: 2026-08-01
Supersedes: none
Superseded-by: none
Affected-services: compute
EOF

cat <<'EOF' > "${temp_dir}/docs/adr/ADR-0002-test-two.md"
# ADR-0002 — Test Two

Status: Accepted
Date: 2026-08-01
Supersedes: none
Superseded-by: none
Affected-services: network
EOF

cat <<'EOF' > "${temp_dir}/docs/adr/README.md"
# ADR Index

## ADR index

| ADR | Subject | Status | Affected Services |
| --- | --- | --- | --- |
| [ADR-0001](ADR-0001-test-one.md) | Test One | Accepted | compute |
| [ADR-0002](ADR-0002-test-two.md) | Test Two | Accepted | network |
EOF

cat <<'EOF' > "${temp_dir}/docs/NORMATIVE_SOURCES.md"
# Normative source ownership

## Authority map

| Subject | Normative source | Summary-only documents |
|---|---|---|
| Test subject | `docs/adr/ADR-0001-test-one.md` | `README.md` |
EOF

cat <<'EOF' > "${temp_dir}/README.md"
# Summary doc
EOF

# 1. Verify valid mock passes
python3 "${repo_root}/scripts/validate-adr-index.py" --root "${temp_dir}" >/dev/null

# 1b. Reciprocal supersession metadata is valid and must not be reported as a
# cycle: the forward edge is recorded by the successor and the reverse edge
# by the predecessor.
sed -i 's/Supersedes: none/Supersedes: ADR-0001/' "${temp_dir}/docs/adr/ADR-0002-test-two.md"
sed -i 's/Superseded-by: none/Superseded-by: ADR-0002/' "${temp_dir}/docs/adr/ADR-0001-test-one.md"
python3 "${repo_root}/scripts/validate-adr-index.py" --root "${temp_dir}" >/dev/null
sed -i 's/Supersedes: ADR-0001/Supersedes: none/' "${temp_dir}/docs/adr/ADR-0002-test-two.md"
sed -i 's/Superseded-by: ADR-0002/Superseded-by: none/' "${temp_dir}/docs/adr/ADR-0001-test-one.md"

# 2. Test invalid status fails
sed -i 's/Status: Accepted/Status: InvalidStatus/' "${temp_dir}/docs/adr/ADR-0001-test-one.md"
if python3 "${repo_root}/scripts/validate-adr-index.py" --root "${temp_dir}" >/dev/null 2>&1; then
    echo "ERROR: Validator accepted invalid status" >&2
    exit 1
fi
sed -i 's/Status: InvalidStatus/Status: Accepted/' "${temp_dir}/docs/adr/ADR-0001-test-one.md"

# 3. Test dangling supersession link fails
sed -i 's/Supersedes: none/Supersedes: ADR-9999/' "${temp_dir}/docs/adr/ADR-0001-test-one.md"
if python3 "${repo_root}/scripts/validate-adr-index.py" --root "${temp_dir}" >/dev/null 2>&1; then
    echo "ERROR: Validator accepted dangling supersession link" >&2
    exit 1
fi
sed -i 's/Supersedes: ADR-9999/Supersedes: none/' "${temp_dir}/docs/adr/ADR-0001-test-one.md"

# 4. Test missing affected-services fails
sed -i 's/Affected-services: compute//' "${temp_dir}/docs/adr/ADR-0001-test-one.md"
if python3 "${repo_root}/scripts/validate-adr-index.py" --root "${temp_dir}" >/dev/null 2>&1; then
    echo "ERROR: Validator accepted missing affected-services metadata" >&2
    exit 1
fi
sed -i 's/Superseded-by: none/Superseded-by: none\nAffected-services: compute/' "${temp_dir}/docs/adr/ADR-0001-test-one.md"

# 5. Test duplicate ADR number fails
cp "${temp_dir}/docs/adr/ADR-0001-test-one.md" "${temp_dir}/docs/adr/ADR-0001-dup.md"
if python3 "${repo_root}/scripts/validate-adr-index.py" --root "${temp_dir}" >/dev/null 2>&1; then
    echo "ERROR: Validator accepted duplicate ADR number" >&2
    exit 1
fi
rm "${temp_dir}/docs/adr/ADR-0001-dup.md"

# 6. Test broken link fails
cat <<'EOF' >> "${temp_dir}/docs/adr/ADR-0001-test-one.md"
[Broken Link](non-existent-file.md)
EOF
if python3 "${repo_root}/scripts/validate-adr-index.py" --root "${temp_dir}" >/dev/null 2>&1; then
    echo "ERROR: Validator accepted broken markdown link" >&2
    exit 1
fi

echo "All ADR governance, architecture-boundary, and negative validation checks passed successfully!"
