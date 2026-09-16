#!/usr/bin/env bash
set -Eeuo pipefail

# Contract/regression guards for the self-contained P15.7 authority.  The
# real Keycloak signature/JWKS and durable exchange evidence remains owned by
# the accepted P12-IAM.7 real-provider test; this guard exercises the runner
# boundary without requiring Docker in every developer checkout.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTHORITY="$ROOT_DIR/scripts/p15-7-keycloak-authority.sh"
PREFLIGHT="$ROOT_DIR/scripts/p15-7-protected-preflight.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-keycloak-guards.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

test -x "$AUTHORITY"
grep -Fq 'quay.io/keycloak/keycloak:25.0.6@sha256:' "$AUTHORITY"
grep -Fq 'testlab-keycloak' "$AUTHORITY"
grep -Fq 'external-oidc' "$AUTHORITY"
grep -Fq 'O3K_TESTLAB_FEDERATED_BINDING_ID' "$AUTHORITY"
grep -Fq 'O3K_TESTLAB_OPERATOR_ASSIGNMENT_ID' "$AUTHORITY"
grep -Fq 'operator-console' "$ROOT_DIR/bins/o3kd/src/composition/mod.rs"
grep -Fq 'acquire_operator_token' "$AUTHORITY"
grep -Fq 'refresh_operator_authority' "$ROOT_DIR/scripts/p15-7-real-host-journey.sh"
grep -Fq 'signature' "$ROOT_DIR/bins/o3kd/tests/p12_iam_7_real_oidc.rs"
for workflow in \
  "$ROOT_DIR/.github/workflows/p15-7-protected-preflight.yml" \
  "$ROOT_DIR/.github/workflows/real-host-validation.yml"; do
  grep -Fq 'shred --remove --zero --force -- "${token_file}"' "$workflow"
done
for variable in O3K_OIDC_TRUST_ID O3K_OIDC_ISSUER O3K_OIDC_AUDIENCE \
  O3K_OIDC_DISCOVERY_URL O3K_TESTLAB_FEDERATED_SUBJECT \
  O3K_TESTLAB_FEDERATED_BINDING_ID O3K_TESTLAB_OPERATOR_ASSIGNMENT_ID; do
  grep -Fq "$variable" "$ROOT_DIR/scripts/bootstrap-disposable-testlab.sh"
done
! grep -Eiq 'mint.*operator|fabricat(e|ing).*AuthContext' "$AUTHORITY"
! grep -Fq 'python3 - "$reset_body" "$operator_password"' "$AUTHORITY"
grep -Fq 'OPERATOR_PASSWORD_FILE' "$AUTHORITY"

# Default preflight: a provider launcher is sufficient; no GitHub OIDC
# issuer/audience/exchange variables are supplied.
FAKE_BIN="$WORK/bin"
mkdir -p "$FAKE_BIN" "$WORK/images"
cat >"$FAKE_BIN/virsh" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == "-c qemu:///system uri" ]]; then echo qemu:///system; fi
SH
cat >"$FAKE_BIN/docker" <<'SH'
#!/usr/bin/env bash
if [[ "$1" == info ]]; then exit 0; fi
exit 0
SH
cat >"$FAKE_BIN/curl" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$FAKE_BIN/virsh" "$FAKE_BIN/docker" "$FAKE_BIN/curl"
FAKE_AUTHORITY="$WORK/fake-authority.sh"
cat >"$FAKE_AUTHORITY" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
state="${O3K_P15_7_KEYCLOAK_STATE_ROOT:?}"
mkdir -p "$state"
case "${1:-}" in
  start)
    printf 'O3K_P15_7_AUTHORITY_MODE=testlab-keycloak\nO3K_P15_7_KEYCLOAK_STATE_ROOT=%s\nO3K_OIDC_TRUST_ID=p15-7-keycloak\nO3K_OIDC_ISSUER=http://127.0.0.1:1234/realms/o3k-p15-7\nO3K_OIDC_AUDIENCE=o3k\nO3K_OIDC_DISCOVERY_URL=http://127.0.0.1:1234/realms/o3k-p15-7/.well-known/openid-configuration\nO3K_OIDC_ALLOW_INSECURE_LOCAL=true\nO3K_TESTLAB_FEDERATED_SUBJECT=subject\n' "$state" >"$state/provider.env"
    printf 'header.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjEyMzQvcmVhbG1zL28zay1wMTUtNyIsInN1YiI6InN1YmplY3QiLCJleHAiOjQwMDAwMDAwMDB9.signature\n' >"$state/oidc-operator.token"
    chmod 0600 "$state/provider.env" "$state/oidc-operator.token"
    ;;
  cleanup) rm -rf -- "$state" ;;
esac
SH
chmod +x "$FAKE_AUTHORITY"
sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"
run_root="$WORK/run"
mkdir -p "$run_root/images"
touch "$WORK/images/kvm"
PATH="$FAKE_BIN:$PATH" \
  RUNNER_TEMP="$run_root" \
  O3K_REAL_HOST_KVM_PATH="$WORK/images/kvm" \
  O3K_P15_7_LIBVIRT_IMAGE_ROOT="$WORK/images" \
  O3K_REAL_HOST_ARTIFACT_DIR="$WORK/artifacts" \
  O3K_P15_7_SOURCE_SHA="$sha" \
  GITHUB_RUN_ID=authority-default \
  GITHUB_ENV="$WORK/github-env" \
  O3K_P15_7_KEYCLOAK_AUTHORITY_SCRIPT="$FAKE_AUTHORITY" \
  bash "$PREFLIGHT" >/dev/null
test -s "$WORK/artifacts/p15-7-protected-preflight.json"
grep -Fq '"status": "passed"' "$WORK/artifacts/p15-7-protected-preflight.json"

# Cleanup must remove only a container with the complete O3K ownership ledger.
STATE="$WORK/o3k-p15-7-keycloak-owned"
mkdir -p "$STATE"
printf 'o3k-p15-7-keycloak-owned-v1\nrun=owned\nsource_sha=%s\n' "$sha" >"$STATE/.o3k-owned"
printf 'o3k-p15-7-keycloak-container-v1\nrun=owned\nsource_sha=%s\n' "$sha" >"$STATE/.o3k-keycloak-owned"
cat >"$FAKE_BIN/docker" <<SH
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "\$1" == inspect ]]; then
  case "\$3" in
    *owner* ) echo "\${FAKE_OWNER:-o3k}" ;;
    *component* ) echo "p15-7-keycloak" ;;
    *phase* ) echo "p15-7" ;;
    *run_id* ) echo "\${FAKE_RUN:-owned}" ;;
    *source_sha* ) echo "\${FAKE_SOURCE:-$sha}" ;;
  esac
elif [[ "\$1" == rm ]]; then
  printf 'removed\n' >"$WORK/removed"
fi
SH
chmod +x "$FAKE_BIN/docker"

# Startup must not adopt, chmod, or later clean a pre-existing run-path
# directory that lacks the O3K ownership ledger.
STATE="$WORK/o3k-p15-7-keycloak-existing"
mkdir -m 0755 "$STATE"
printf 'foreign-runner-data\n' >"$STATE/keep.me"
if PATH="$FAKE_BIN:$PATH" RUNNER_TEMP="$WORK" GITHUB_RUN_ID=existing \
  O3K_P15_7_SOURCE_SHA="$sha" O3K_P15_7_KEYCLOAK_STATE_ROOT="$STATE" \
  bash "$AUTHORITY" start; then
  echo "pre-existing Keycloak state directory was adopted" >&2
  exit 1
fi
test -f "$STATE/keep.me"
test "$(stat -c '%a' "$STATE")" = 755

STATE="$WORK/o3k-p15-7-keycloak-owned"
PATH="$FAKE_BIN:$PATH" RUNNER_TEMP="$WORK" GITHUB_RUN_ID=owned \
  O3K_P15_7_SOURCE_SHA="$sha" O3K_P15_7_KEYCLOAK_STATE_ROOT="$STATE" \
  bash "$AUTHORITY" cleanup
test -f "$WORK/removed"

# A crafted ownership ledger must not authorize recursive cleanup of the
# shared runner temp directory or another path outside this run's child.
mkdir -p "$STATE"
printf 'o3k-p15-7-keycloak-owned-v1\nrun=owned\nsource_sha=%s\n' "$sha" >"$STATE/.o3k-owned"
printf 'o3k-p15-7-keycloak-container-v1\nrun=owned\nsource_sha=%s\n' "$sha" >"$STATE/.o3k-keycloak-owned"
rm -f "$WORK/removed"
if PATH="$FAKE_BIN:$PATH" RUNNER_TEMP="$WORK" GITHUB_RUN_ID=owned \
  O3K_P15_7_SOURCE_SHA="$sha" O3K_P15_7_KEYCLOAK_STATE_ROOT="$WORK" \
  bash "$AUTHORITY" cleanup; then
  echo "broad Keycloak state root was accepted" >&2
  exit 1
fi
test ! -e "$WORK/removed"
test -f "$STATE/.o3k-owned"

STATE="$WORK/o3k-p15-7-keycloak-foreign"
mkdir -p "$STATE"
printf 'o3k-p15-7-keycloak-owned-v1\nrun=foreign\nsource_sha=%s\n' "$sha" >"$STATE/.o3k-owned"
printf 'o3k-p15-7-keycloak-container-v1\nrun=foreign\nsource_sha=%s\n' "$sha" >"$STATE/.o3k-keycloak-owned"
printf 'run-scoped-oauth-token\n' >"$STATE/oidc-operator.token"
printf 'run-scoped-operator-password\n' >"$STATE/operator-password"
rm -f "$WORK/removed"
if PATH="$FAKE_BIN:$PATH" RUNNER_TEMP="$WORK" GITHUB_RUN_ID=foreign \
  O3K_P15_7_SOURCE_SHA="$sha" O3K_P15_7_KEYCLOAK_STATE_ROOT="$STATE" \
  FAKE_OWNER=foreign bash "$AUTHORITY" cleanup; then
  echo "foreign Keycloak container was removed" >&2
  exit 1
fi
test ! -e "$WORK/removed"
test ! -e "$STATE/oidc-operator.token"
test ! -e "$STATE/operator-password"
test -f "$STATE/.o3k-owned"

echo "P15.7 Keycloak authority guards passed"
