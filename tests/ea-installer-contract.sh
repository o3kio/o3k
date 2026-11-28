#!/usr/bin/env bash
# Static installer contract for the bounded v0.4.1 Early Access path.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT/packaging/get-o3k.sh"
INSTALLER="$ROOT/packaging/install.sh"
PREFLIGHT="$ROOT/packaging/ea-preflight.sh"
RELEASE="$ROOT/packaging/make-release.sh"
WORKFLOW="$ROOT/.github/workflows/release.yml"
PROMOTE_WORKFLOW="$ROOT/.github/workflows/promote-ea-release.yml"
PROMOTE_SCRIPT="$ROOT/packaging/promote-ea-release.sh"

bash -n "$WRAPPER" "$INSTALLER" "$PREFLIGHT" "$RELEASE"
bash -n "$ROOT/packaging/config-env.sh" "$ROOT/tests/config-env.sh"
bash "$ROOT/tests/config-env.sh"
grep -Fq 'postgresql-16' "$WRAPPER"
grep -Fq 'installation-security-profile early-access-v1' "$WRAPPER"
grep -Fq 'installation-local-provision --data-root' "$INSTALLER"
grep -Fq 'CREATE ROLE o3k LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION' "$INSTALLER"
grep -Fq 'CREATE DATABASE o3k OWNER o3k' "$INSTALLER"
grep -Fq 'pg_isready' "$INSTALLER"
grep -Fq 'installation-local-verify' "$INSTALLER"
grep -Fq 'existing O3K configuration or TLS state blocks a fresh install' "$PREFLIGHT"
grep -Fq 'existing O3K release files block a fresh install' "$PREFLIGHT"
grep -Fq 'for identity in o3k o3k-compute o3k-network' "$PREFLIGHT"
grep -Fq 'o3k-compute.service' "$PREFLIGHT" "$INSTALLER"
grep -Fq 'o3k-network.service' "$PREFLIGHT" "$INSTALLER"
grep -Fq 'release_artifact_sha256' "$PREFLIGHT" "$WRAPPER"
grep -Fq 'installation_security_profile":"early-access-v1' "$RELEASE"
grep -Fq 'O3K_INSTALLATION_SECURITY_PROFILE=early-access-v1' "$RELEASE"
grep -Fq '0\.4\.1-rc\.' "$RELEASE"
grep -Fq 'EA_INSTALL" = 1' "$WRAPPER"
grep -Fq 'EA_INSTALL" = 0' "$WRAPPER"
grep -Fq 'installation_authority":"installation-local' "$RELEASE"
grep -Fq 'early-access-v1' "$WORKFLOW"
grep -Fq "'0' || '1'" "$WORKFLOW"
python3 - "$WRAPPER" <<'PY'
from pathlib import Path
import sys

wrapper = Path(sys.argv[1]).read_text()
integrity = wrapper.index('verify-release-bundle.sh" "$BUNDLE_DIR" --integrity-only')
ea_preflight = wrapper.index('ea-preflight.sh')
install_tools = wrapper.index('apt-get install -y $APT_PACKAGES')
executable_check = wrapper.index('release bundle executable verification failed')
service_start = wrapper.index('systemctl enable --now libvirtd')
assert integrity < ea_preflight < install_tools < executable_check < service_start
PY
grep -Fq 'qualification candidate' "$ROOT/docs/releases/v0.4.1-rc.1.md"
grep -Fq -- '--draft --title "O3K v0.4.1' "$WORKFLOW"
grep -Fq 'workflow_dispatch:' "$PROMOTE_WORKFLOW"
grep -Fq 'packaging/promote-ea-release.sh "$TAG"' "$PROMOTE_WORKFLOW"
grep -Fq 'gh release download "$TAG" --dir "$DIST_DIR"' "$PROMOTE_SCRIPT"
grep -Fq 'verify-release-sigstore.sh' "$PROMOTE_SCRIPT"
grep -Fq 'sha256:$digest' "$PROMOTE_SCRIPT"
grep -Fq 'asset_snapshot' "$PROMOTE_SCRIPT"
grep -Fq 'PATCH "repos/o3kio/o3k/releases/$release_id"' "$PROMOTE_SCRIPT"
if grep -Eq 'make-release\.sh|make-release-archive\.sh|cargo build' "$PROMOTE_SCRIPT" "$PROMOTE_WORKFLOW"; then
  echo 'EA promotion must not rebuild qualified artifacts' >&2
  exit 1
fi

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
version = re.search(r'^version = "([^"]+)"$', (root / "Cargo.toml").read_text(), re.M).group(1)
pin = re.search(r'^O3K_INSTALLER_VERSION="v([^"]+)"$', (root / "packaging/get-o3k.sh").read_text(), re.M).group(1)
chart = (root / "deployments/helm/o3k/Chart.yaml").read_text()
app_version = re.search(r'^appVersion: "([^"]+)"$', chart, re.M).group(1)
chart_version = re.search(r'^version: ([^\n]+)$', chart, re.M).group(1)
docker = (root / "deployments/docker/Dockerfile.o3kd").read_text()
docker_version = re.search(r'^ARG VERSION="([^"]+)"$', docker, re.M).group(1)
docker_local = (root / "deployments/docker/Dockerfile.o3kd-local").read_text()
docker_local_version = re.search(r'^ARG VERSION="([^"]+)"$', docker_local, re.M).group(1)
wrapper = (root / "packaging/get-o3k.sh").read_text()
assert version == "0.4.1-rc.1", version
assert pin == version, pin
assert app_version == version, app_version
assert chart_version == version, chart_version
assert docker_version == version, docker_version
assert docker_local_version == version, docker_local_version
integrity = wrapper.index('verify-release-bundle.sh" "$BUNDLE_DIR" --integrity-only')
ea_preflight = wrapper.index('ea-preflight.sh')
install_tools = wrapper.index('apt-get install -y $APT_PACKAGES')
executable_check = wrapper.index('release bundle executable verification failed')
service_start = wrapper.index('systemctl enable --now libvirtd')
assert integrity < ea_preflight < install_tools < executable_check < service_start
assert 'openssh-client binutils libvirt-daemon-system' in wrapper
release_builder = (root / "packaging/make-release.sh").read_text()
binary_builder = (root / "scripts/build-release-binaries-debian12.sh").read_text()
assert 'baseline binary is missing: $BINARIES_DIR/o3k-enrollment-issuer' in release_builder
assert 'install -m 0755 "$BINARIES_DIR/o3k-enrollment-issuer" "$OUT_DIR/bin/o3k-enrollment-issuer"' in release_builder
assert 'cargo build --release --locked --bin o3k-enrollment-issuer' in binary_builder
assert 'o3k-enrollment-issuer > SHA256SUMS' in binary_builder
qualification = (root / "tests/ea-qualification/ea-testlab.sh").read_text()
assert '"ubuntu@$ip" "$@"' in qualification
assert '- name: ubuntu' in qualification
assert '- name: o3k\n' not in qualification
PY
bash "$ROOT/packaging/get-o3k-worker/sync.sh" --check

grep -Fq 'O3K_ENROLLMENT_LISTEN_ADDR=127.0.0.1:19443' "$ROOT/packaging/install.sh"
grep -Fq 'O3K_ENROLLMENT_SIGNER' "$ROOT/packaging/install.sh"
grep -Fq 'O3K_STORAGE_CONTROLLER_IDENTITY=' "$ROOT/packaging/install.sh"
grep -Fq 'o3k-storage.service' "$ROOT/packaging/install.sh" "$ROOT/packaging/uninstall.sh" "$ROOT/packaging/make-release.sh"
grep -Fq 'DevicePolicy=closed' "$ROOT/packaging/o3k-storage.service"
grep -Fq 'DeviceAllow=/dev/mapper/control rw' "$ROOT/packaging/o3k-storage.service"
grep -Fq 'o3k-enrollment-issuer" --export-ca' "$ROOT/packaging/install.sh"
grep -Fq 'O3K_COMPUTE_CLIENT_CA=$COMPUTE_CLIENT_CA' "$ROOT/packaging/install.sh"
grep -Fq 'compute-client-ca.pem' "$ROOT/packaging/install.sh"
grep -Fq 'install -d -m 0750 -o root -g o3k "$CONFIG_DIR/ea"' "$ROOT/packaging/install.sh"
grep -Fq 'Some("--export-ca")' "$ROOT/bins/o3k-enrollment-issuer/src/main.rs"
grep -Fq 'o3k_upsert_env_setting' "$ROOT/packaging/install.sh"
grep -Fq '"$ROOT_DIR/packaging/config-env.sh"' "$ROOT/packaging/make-release.sh"
python3 - "$ROOT/packaging/install.sh" <<'PY'
from pathlib import Path
import sys
installer = Path(sys.argv[1]).read_text()
assert installer.index('o3k_verify_config_ledger "$CONFIG_DIR"') < installer.index('bash "$ROOT_DIR/scripts/generate-passwords.sh"')
PY
grep -Fq 'share/o3k/o3k-enrollment-issuer@.service' "$ROOT/packaging/install.sh" "$ROOT/packaging/uninstall.sh"
grep -Fq 'systemctl disable --now o3k-enrollment-issuer.socket' "$ROOT/packaging/uninstall.sh"
grep -Fq 'if [[ "$EA_INSTALL" == 1 ]]; then' "$ROOT/packaging/install.sh"
! grep -Fq 'O3K_ENROLLMENT_SIGNER=/run/o3k/enrollment-issuer.sock' "$ROOT/packaging/install.sh"
grep -Fq '/run/o3k/enrollment-issuer.sock' "$ROOT/packaging/install.sh"
grep -Fq 'EA_INSTALL' "$ROOT/packaging/install.sh"
if grep -Fq 'O3K_ENROLLMENT_SIGNER=' "$ROOT/packaging/install.sh" && \
  ! grep -Fq 'if [[ "$EA_INSTALL" == 1' "$ROOT/packaging/install.sh"; then
  echo "EA enrollment settings are not gated by the authenticated EA installer" >&2
  exit 1
fi

echo 'Early Access installer contract: PASS'
