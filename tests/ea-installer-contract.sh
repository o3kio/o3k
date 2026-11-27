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

bash -n "$WRAPPER" "$INSTALLER" "$PREFLIGHT" "$RELEASE"
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
grep -Fq 'qualification candidate' "$ROOT/docs/releases/v0.4.1-rc.1.md"
grep -Fq -- '--draft --title "O3K v0.4.1' "$WORKFLOW"
grep -Fq 'workflow_dispatch:' "$PROMOTE_WORKFLOW"
grep -Fq 'gh release download "$TAG" --dir dist' "$PROMOTE_WORKFLOW"
grep -Fq 'packaging/verify-release-sigstore.sh "$TAG" dist' "$PROMOTE_WORKFLOW"
grep -Fq 'sha256:$digest' "$PROMOTE_WORKFLOW"
grep -Fq 'PATCH "repos/o3kio/o3k/releases/$release_id"' "$PROMOTE_WORKFLOW"
if grep -Eq 'make-release\.sh|make-release-archive\.sh|cargo build' "$PROMOTE_WORKFLOW"; then
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
assert version == "0.4.1-rc.1", version
assert pin == version, pin
assert app_version == version, app_version
assert chart_version == version, chart_version
assert docker_version == version, docker_version
assert docker_local_version == version, docker_local_version
PY
bash "$ROOT/packaging/get-o3k-worker/sync.sh" --check

echo 'Early Access installer contract: PASS'
