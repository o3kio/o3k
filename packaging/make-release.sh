#!/usr/bin/env bash
# make-release.sh — build the verified release bundle (dist/o3k-<version>/) and
# export the one-line installer as the dist/install.sh GitHub Release asset.
#
# Usage: packaging/make-release.sh [VERSION] [PROFILE=fake]
#
# Release asset contract for the GitHub Release (see docs/RELEASE.md):
#   dist/install.sh                            byte-identical export of
#                                              packaging/get-o3k.sh (0755,
#                                              drift-gated by cmp, SHA-256
#                                              recorded in the bundle
#                                              manifest.json installer_sha256)
#   dist/o3k-<version>-linux-x86_64.tar.gz     produced by
#   dist/o3k-<version>-linux-x86_64.tar.gz.sha256
#                                              packaging/make-release-archive.sh
#   plus o3kd, o3k-compute, SHA256SUMS, sbom.spdx.json, and manifest.json
#   from the bundle and the baseline build. The manifest declares
#   schema_version (max migration prefix from crates/o3k-store/migrations/)
#   and upgrade_from.min_version (from O3K_UPGRADE_FROM_MIN_VERSION; the
#   release operator must name the previous published release explicitly).
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -1)}"
PROFILE="${2:-fake}"
VERSION_RE='^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'
if [[ ! "$VERSION" =~ $VERSION_RE ]]; then
  echo "version must be a numeric release version with an optional prerelease suffix" >&2
  exit 2
fi
[[ "$PROFILE" == fake || "$PROFILE" == libvirt ]] || { echo "profile must be fake or libvirt" >&2; exit 2; }
if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=all)" ]]; then
  echo "release source tree must be clean before packaging" >&2
  exit 2
fi
# schema_version: the maximum numeric migration prefix under
# crates/o3k-store/migrations/ at build time (e.g. 0017_placement.sql -> 17).
# This is the single migration authority: the release declares the schema
# version its embedded migrator converges to, so the upgrade engine can verify
# a post-start migration without embedding any migration SQL. Fail the build
# when the directory is empty or any file name lacks a numeric prefix.
MIGRATIONS_DIR="$ROOT_DIR/crates/o3k-store/migrations"
SCHEMA_VERSION=""
MIGRATION_COUNT=0
for migration in "$MIGRATIONS_DIR"/*.sql; do
  [[ -f "$migration" ]] || continue
  MIGRATION_COUNT=$((MIGRATION_COUNT + 1))
  base="${migration##*/}"
  case "$base" in
    [0-9]*_*.sql) prefix="${base%%_*}" ;;
    *) echo "release migration file name has no numeric prefix: $base" >&2; exit 1 ;;
  esac
  case "$prefix" in
    ''|*[!0-9]*) echo "release migration prefix is not numeric: $base" >&2; exit 1 ;;
  esac
  if [[ -z "$SCHEMA_VERSION" || "$((10#$prefix))" -gt "$SCHEMA_VERSION" ]]; then
    SCHEMA_VERSION="$((10#$prefix))"
  fi
done
[[ "$MIGRATION_COUNT" -gt 0 ]] || { echo "release migration directory is empty: $MIGRATIONS_DIR" >&2; exit 1; }
# upgrade_from.min_version: the oldest installed release this build supports
# upgrading from. It is deliberately NOT hardcoded — the release operator must
# name the previous published release explicitly (see docs/RELEASE.md).
UPGRADE_FROM_MIN_VERSION="${O3K_UPGRADE_FROM_MIN_VERSION:-}"
if [[ -z "$UPGRADE_FROM_MIN_VERSION" ]]; then
  echo "O3K_UPGRADE_FROM_MIN_VERSION is unset: set it to the previous published release version" >&2
  echo "  e.g. O3K_UPGRADE_FROM_MIN_VERSION=v0.3.0-alpha.1 packaging/make-release.sh 0.4.0-rc.3 libvirt" >&2
  exit 1
fi
UPGRADE_FROM_VERSION_NO_V="${UPGRADE_FROM_MIN_VERSION#v}"
[[ "$UPGRADE_FROM_VERSION_NO_V" =~ $VERSION_RE ]] \
  || { echo "upgrade_from.min_version must be a published release version: $UPGRADE_FROM_MIN_VERSION" >&2; exit 2; }
DIST_ROOT="${O3K_RELEASE_DIST_DIR:-$ROOT_DIR/dist}"
if [[ -L "$DIST_ROOT" || ( -e "$DIST_ROOT" && ! -d "$DIST_ROOT" ) ]]; then
  echo "release dist root must be a real directory, not a symlink or special file" >&2
  exit 2
fi
mkdir -p -- "$DIST_ROOT"
OUT_DIR="$DIST_ROOT/o3k-$VERSION"

# Release binaries must execute on every advertised target (Ubuntu 24.04 and
# Debian 12). They are built on the Debian 12 (bookworm, glibc 2.36) baseline
# with scripts/build-release-binaries-debian12.sh and handed in through
# O3K_RELEASE_BINARIES_DIR; building on a newer baseline (e.g. Ubuntu 24.04)
# produces binaries that fail at exec on Debian 12 and is rejected here by the
# glibc floor check.
BINARIES_DIR="${O3K_RELEASE_BINARIES_DIR:-}"
if [[ -n "$BINARIES_DIR" ]]; then
  [[ -f "$BINARIES_DIR/o3kd" ]] || { echo "baseline binary is missing: $BINARIES_DIR/o3kd" >&2; exit 2; }
  bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$BINARIES_DIR/o3kd"
  [[ -f "$BINARIES_DIR/o3k" ]] || { echo "baseline binary is missing: $BINARIES_DIR/o3k" >&2; exit 2; }
  bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$BINARIES_DIR/o3k"
  if [[ "$PROFILE" == libvirt ]]; then
    [[ -f "$BINARIES_DIR/o3k-compute" ]] || { echo "baseline binary is missing: $BINARIES_DIR/o3k-compute" >&2; exit 2; }
    bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$BINARIES_DIR/o3k-compute"
    # The network execution agent ships in every libvirt-profile bundle for
    # the o3k-small-edge-v1 boundary (PP.1 resolution of the PP.0 gap).
    [[ -f "$BINARIES_DIR/o3k-network" ]] || { echo "baseline binary is missing: $BINARIES_DIR/o3k-network" >&2; exit 2; }
    bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$BINARIES_DIR/o3k-network"
  fi
else
  cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --bin o3kd
  bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$ROOT_DIR/target/release/o3kd"
  cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --bin o3k
  bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$ROOT_DIR/target/release/o3k"
  if [[ "$PROFILE" == libvirt ]]; then
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --features libvirt --bin o3k-compute-bin
    bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$ROOT_DIR/target/release/o3k-compute-bin"
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --bin o3k-network-bin
    bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$ROOT_DIR/target/release/o3k-network-bin"
  fi
fi
rm -rf -- "$OUT_DIR"
mkdir -p "$OUT_DIR/bin" "$OUT_DIR/packaging" "$OUT_DIR/scripts" "$OUT_DIR/contracts" "$OUT_DIR/docs" "$OUT_DIR/examples"
if [[ -n "$BINARIES_DIR" ]]; then
  install -m 0755 "$BINARIES_DIR/o3kd" "$OUT_DIR/bin/o3kd"
  install -m 0755 "$BINARIES_DIR/o3k" "$OUT_DIR/bin/o3k"
  if [[ "$PROFILE" == libvirt ]]; then
    install -m 0755 "$BINARIES_DIR/o3k-compute" "$OUT_DIR/bin/o3k-compute"
    install -m 0755 "$BINARIES_DIR/o3k-network" "$OUT_DIR/bin/o3k-network"
  fi
else
  install -m 0755 "$ROOT_DIR/target/release/o3kd" "$OUT_DIR/bin/o3kd"
  install -m 0755 "$ROOT_DIR/target/release/o3k" "$OUT_DIR/bin/o3k"
  if [[ "$PROFILE" == libvirt ]]; then
    install -m 0755 "$ROOT_DIR/target/release/o3k-compute-bin" "$OUT_DIR/bin/o3k-compute"
    install -m 0755 "$ROOT_DIR/target/release/o3k-network-bin" "$OUT_DIR/bin/o3k-network"
  fi
fi
# get-o3k.sh and channels.yaml ship in the bundle so a pinned/self-hosted
# release is self-describing (the wrapper and its advisory channel table
# travel with the artifacts they download; the wrapper itself never consults
# the channel table).
cp "$ROOT_DIR/packaging/o3kd.service" "$ROOT_DIR/packaging/install.sh" "$ROOT_DIR/packaging/reset.sh" "$ROOT_DIR/packaging/uninstall.sh" "$ROOT_DIR/packaging/diagnose.sh" "$ROOT_DIR/packaging/preflight.sh" "$ROOT_DIR/packaging/bootstrap-certs.sh" "$ROOT_DIR/packaging/bootstrap-testlab.sh" "$ROOT_DIR/packaging/get-o3k.sh" "$ROOT_DIR/packaging/channels.yaml" "$ROOT_DIR/packaging/release-gate.sh" "$ROOT_DIR/packaging/validate-human-review.sh" "$ROOT_DIR/packaging/scan-release-evidence.sh" "$ROOT_DIR/packaging/generate-candidate-evidence-manifest.py" "$ROOT_DIR/packaging/verify-release-bundle.sh" "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$ROOT_DIR/packaging/o3k-compute.service" "$ROOT_DIR/packaging/o3k-network.service" "$ROOT_DIR/packaging/50-o3k-libvirt.rules" "$OUT_DIR/packaging/"
cp "$ROOT_DIR/scripts/generate-passwords.sh" "$OUT_DIR/scripts/"
cp "$ROOT_DIR/scripts/validate-release-e2e-evidence.py" "$OUT_DIR/scripts/"
cp "$ROOT_DIR/contracts/release-e2e-evidence.schema.json" "$OUT_DIR/contracts/"
cp "$ROOT_DIR/docs/compatibility.md" "$ROOT_DIR/docs/cirros-walkthrough.md" "$ROOT_DIR/docs/release-evidence-schema.md" "$ROOT_DIR/docs/human-review-schema.md" "$ROOT_DIR/docs/security-review-checklist.md" "$ROOT_DIR/docs/releases/v0.4.0-rc.4.md" "$OUT_DIR/docs/"
cp "$ROOT_DIR/examples/clouds.yaml" "$ROOT_DIR/examples/o3kd.env.example" "$OUT_DIR/examples/"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" show -s --format=%ct HEAD)}" \
  "$ROOT_DIR/packaging/make-sbom.sh" "$OUT_DIR/sbom.spdx.json"
# install.sh release asset: export the single installer source byte-for-byte
# NEXT TO the bundle dir (it is a release asset, not a bundle file, so it is
# deliberately absent from the bundle SHA256SUMS). The cmp gate makes drift
# between the published asset and the reviewed source impossible to miss.
INSTALL_SH="$DIST_ROOT/install.sh"
cp "$ROOT_DIR/packaging/get-o3k.sh" "$INSTALL_SH"
chmod 0755 "$INSTALL_SH"
cmp -- "$ROOT_DIR/packaging/get-o3k.sh" "$INSTALL_SH" \
  || { echo "install.sh release asset drifted from packaging/get-o3k.sh after copy" >&2; exit 1; }
INSTALLER_SHA256="$(sha256sum "$INSTALL_SH" | awk '{print $1}')"
COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
WORKFLOW="${GITHUB_WORKFLOW:-local}"
# The manifest is written BEFORE SHA256SUMS so the final bundle verification
# covers the installer record too. schema_version is the max migration prefix
# computed above; upgrade_from.min_version is the operator-declared fence.
printf '{"version":"%s","profile":"%s","source_commit":"%s","workflow":"%s","installer_sha256":"%s","installer_asset":"install.sh","schema_version":"%s","upgrade_from":{"min_version":"%s"}}\n' \
  "$VERSION" "$PROFILE" "$COMMIT" "$WORKFLOW" "$INSTALLER_SHA256" \
  "$SCHEMA_VERSION" "$UPGRADE_FROM_MIN_VERSION" >"$OUT_DIR/manifest.json"
(cd "$OUT_DIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
bash "$ROOT_DIR/packaging/verify-release-bundle.sh" "$OUT_DIR"
echo "release prepared at $OUT_DIR"
echo "install.sh release asset: $INSTALL_SH (sha256 $INSTALLER_SHA256)"
