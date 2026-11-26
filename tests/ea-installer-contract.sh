#!/usr/bin/env bash
# Static installer contract for the bounded v0.4.1 Early Access path.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT/packaging/get-o3k.sh"
INSTALLER="$ROOT/packaging/install.sh"
PREFLIGHT="$ROOT/packaging/ea-preflight.sh"
RELEASE="$ROOT/packaging/make-release.sh"

bash -n "$WRAPPER" "$INSTALLER" "$PREFLIGHT" "$RELEASE"
grep -Fq 'postgresql-16' "$WRAPPER"
grep -Fq 'installation-security-profile early-access-v1' "$WRAPPER"
grep -Fq 'installation-local-provision --data-root' "$INSTALLER"
grep -Fq 'CREATE ROLE o3k LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION' "$INSTALLER"
grep -Fq 'CREATE DATABASE o3k OWNER o3k' "$INSTALLER"
grep -Fq 'pg_isready' "$INSTALLER"
grep -Fq 'installation-local-verify' "$INSTALLER"
grep -Fq 'release_artifact_sha256' "$PREFLIGHT" "$WRAPPER"
grep -Fq 'installation_security_profile":"early-access-v1' "$RELEASE"
grep -Fq 'O3K_INSTALLATION_SECURITY_PROFILE=early-access-v1' "$RELEASE"
grep -Fq 'EA_INSTALL" = 1' "$WRAPPER"
grep -Fq 'EA_INSTALL" = 0' "$WRAPPER"

echo 'Early Access installer contract: PASS'
