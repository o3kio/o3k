#!/usr/bin/env bash
set -euo pipefail

# ISSUE #907 — Integrated production-profile northbound convergence gate.
#
# Runs the Araf P2 convergence evidence in ONE real environment:
#   * a disposable PostgreSQL 16.4 (primary production profile) and a SQLite
#     parity pass;
#   * a pinned disposable Keycloak 25.0.6 as the real RS256 OIDC provider;
#   * the real `o3kd` binary (bins/o3kd/tests/araf_p2_convergence.rs) driving
#     all 16 northbound evidence items over real HTTP.
#
# Keycloak provisioning is REUSED from tests/p12-iam-7-real-idp.sh via its
# O3K_P12_7_AFTER_HOOK composition point rather than duplicated here, so the
# gate and the P12-IAM.7 suite share one identical IdP fixture and env surface
# (tokens, subjects, discovery URL, bootstrap secret), and Keycloak cleanup is
# owned by that script. This script owns the disposable PostgreSQL lifecycle.

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

run_id="o3k-araf-p2-${RANDOM}-${RANDOM}"
workdir="$(mktemp -d)"
pg_container="${run_id}-postgres"

cleanup() {
  docker rm -f "${pg_container}" >/dev/null 2>&1 || true
  rm -rf "${workdir}"
}
trap cleanup EXIT

# ── Disposable PostgreSQL (dispatcher pattern from test-postgres-audit.sh) ──
pg_password="o3k-araf-disposable"
start_postgres() {
  docker run --rm -d --name "${pg_container}" \
    -e POSTGRES_USER=o3k -e POSTGRES_PASSWORD="${pg_password}" -e POSTGRES_DB=o3k_test \
    -p 127.0.0.1::5432 postgres:16.4 >/dev/null
  local port="" ready=""
  for _ in $(seq 1 60); do
    port="$(docker port "${pg_container}" 5432/tcp 2>/dev/null | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -1)"
    if [[ -n "${port}" ]] && \
      docker exec "${pg_container}" pg_isready -h 127.0.0.1 -p 5432 -U o3k -d o3k_test >/dev/null 2>&1; then
      ready="1"
      break
    fi
    sleep 1
  done
  if [[ -z "${ready}" ]]; then
    echo "PostgreSQL readiness timeout (container=${pg_container})" >&2
    docker logs "${pg_container}" >&2 || true
    return 1
  fi
  echo "postgres://o3k:${pg_password}@127.0.0.1:${port}/o3k_test"
}

# Each AFTER_HOOK runs the Rust gate with the env the p12-iam-7 script has
# already exported (tokens, subjects, issuer, discovery URL, bootstrap secret).
# The hook asserts the gate actually ran: cargo exits 0 with "0 passed" when
# the test is renamed or loses #[ignore], which would otherwise print PASS with
# no evidence.
cat >"${workdir}/run-gate.sh" <<HOOK
#!/usr/bin/env bash
set -euo pipefail
cd '${repo_root}'
set +e
gate_output="\$(cargo test --locked -p o3kd --test araf_p2_convergence --all-features -- \
  araf_p2_northbound_convergence --ignored --nocapture 2>&1)"
gate_status=\$?
set -e
if (( gate_status != 0 )) || ! grep -q "test result: ok. 1 passed" <<<"\${gate_output}"; then
  echo "Araf P2 gate did not report exactly one passed test:" >&2
  echo "\${gate_output}" >&2
  exit 1
fi
HOOK
chmod +x "${workdir}/run-gate.sh"

echo "────────────────────────────────────────────────────────────────"
echo "ISSUE #907 Araf P2 convergence — PostgreSQL production profile"
echo "────────────────────────────────────────────────────────────────"
pg_url="$(start_postgres)"
export O3K_DATABASE_URL="${pg_url}"
export O3K_P12_7_AFTER_HOOK="${workdir}/run-gate.sh"
bash "${repo_root}/tests/p12-iam-7-real-idp.sh"
echo "PASS: Araf P2 convergence (PostgreSQL)"

echo
echo "────────────────────────────────────────────────────────────────"
echo "ISSUE #907 Araf P2 convergence — SQLite parity pass"
echo "────────────────────────────────────────────────────────────────"
unset O3K_DATABASE_URL
bash "${repo_root}/tests/p12-iam-7-real-idp.sh"
echo "PASS: Araf P2 convergence (SQLite)"

echo
echo "ISSUE #907 Araf P2 northbound convergence: PASS (PostgreSQL + SQLite)"
