#!/usr/bin/env bash
# scripts/build-release-binaries-debian12.sh — build the release binaries on
# the Debian 12 (bookworm) glibc 2.36 baseline
#
# The release binaries (o3kd, o3k, o3k-compute-bin --features libvirt) must
# execute
# on every advertised target: Ubuntu 24.04 and Debian 12. Debian 12 ships
# glibc 2.36, so a binary built on a newer baseline (Ubuntu 24.04's glibc
# 2.39, for example) fails at exec on bookworm with `version 'GLIBC_2.38' not
# found` (see target/real-host-workflow-artifacts/clean-debian/
# defect-5-glibc-abi.md). This script builds the binaries inside a disposable
# Debian 12 rootfs so they link against glibc 2.36, then copies them out with
# sha256 and a glibc-floor proof recorded.
#
# The build is deterministic: the toolchain channel and components come from
# rust-toolchain.toml and are installed with rustup; the workspace is built
# from the committed Cargo.lock with `cargo build --release --locked` inside
# the bookworm rootfs; the Debian suite and mirror are fixed (bookworm,
# http://deb.debian.org/debian by default).
#
# Requirements: root (debootstrap + chroot), network access to deb.debian.org,
# static.rust-lang.org, and crates.io; debootstrap, curl, tar, and readelf
# (binutils) on the host. The rootfs is disposable and removed on exit.
#
# Usage: bash scripts/build-release-binaries-debian12.sh [OUTPUT_DIR]
#   OUTPUT_DIR defaults to $ROOT_DIR/target/release-debian12 and receives
#   o3kd, o3k, o3k-compute, SHA256SUMS, glibc-floor.txt, and build-info.txt.
#   Then assemble the release bundle from the baseline binaries:
#     O3K_RELEASE_BINARIES_DIR="$OUTPUT_DIR" \
#       packaging/make-release.sh VERSION libvirt
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/target/release-debian12}"
MIRROR="${O3K_DEBOOTSTRAP_MIRROR:-http://deb.debian.org/debian}"
SUITE=bookworm
ARCH="${O3K_BUILD_ARCH:-amd64}"

(( EUID == 0 )) || { echo "must run as root (debootstrap + chroot)" >&2; exit 2; }
for tool in debootstrap curl tar readelf; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool is missing: $tool" >&2; exit 2; }
done

TOOLCHAIN_FILE="$ROOT_DIR/rust-toolchain.toml"
CHANNEL="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "$TOOLCHAIN_FILE" | head -1)"
[[ -n "$CHANNEL" ]] || { echo "cannot read the toolchain channel from $TOOLCHAIN_FILE" >&2; exit 2; }
COMPONENT_ARGS=()
while IFS= read -r component; do
  [[ -n "$component" ]] && COMPONENT_ARGS+=(--component "$component")
done < <(sed -n 's/^components = \[\(.*\)\]/\1/p' "$TOOLCHAIN_FILE" | tr -d '"' | tr ',' '\n')

ROOTFS="$(mktemp -d "${TMPDIR:-/tmp}/o3k-debian12-rootfs.XXXXXX")"
cleanup() {
  umount "$ROOTFS/dev" 2>/dev/null || true
  umount "$ROOTFS/sys" 2>/dev/null || true
  umount "$ROOTFS/proc" 2>/dev/null || true
  rm -rf -- "$ROOTFS"
}
trap cleanup EXIT

echo "==> debootstrap $SUITE ($ARCH) into $ROOTFS"
debootstrap --variant=minbase --arch="$ARCH" "$SUITE" "$ROOTFS" "$MIRROR"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sysfs "$ROOTFS/sys"
mount --bind /dev "$ROOTFS/dev"
[[ -f "$ROOTFS/etc/resolv.conf" ]] || cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"

echo "==> installing build dependencies inside the rootfs"
chroot "$ROOTFS" /bin/bash -c '
  set -Eeuo pipefail
  export DEBIAN_FRONTEND=noninteractive LC_ALL=C
  apt-get update -qq
  apt-get install -y -qq build-essential cmake pkg-config libvirt-dev \
    libsqlite3-dev protobuf-compiler curl ca-certificates perl
'

echo "==> installing rust toolchain $CHANNEL (rust-toolchain.toml) via rustup"
chroot "$ROOTFS" /bin/bash -c '
  set -Eeuo pipefail
  export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo HOME=/root
  curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain none
'
chroot "$ROOTFS" /bin/bash -c '
  set -Eeuo pipefail
  export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo PATH="/root/.cargo/bin:$PATH" HOME=/root
  rustup toolchain install "'"$CHANNEL"'" --profile minimal '"${COMPONENT_ARGS[*]}"'
  rustup default "'"$CHANNEL"'"
'

echo "==> copying the workspace sources into the rootfs"
mkdir -p "$ROOTFS/build"
(cd "$ROOT_DIR" && tar -cf - Cargo.toml Cargo.lock rust-toolchain.toml bins crates proto) \
  | tar -xf - -C "$ROOTFS/build"

echo "==> cargo build --release (o3kd, o3k, o3k-compute-bin --features libvirt, o3k-network)"
chroot "$ROOTFS" /bin/bash -c '
  set -Eeuo pipefail
  cd /build
  export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo PATH="/root/.cargo/bin:$PATH" HOME=/root
  cargo build --release --locked --bin o3kd --bin o3k
  cargo build --release --locked --features libvirt --bin o3k-compute-bin
  cargo build --release --locked --bin o3k-network
  rustc --version > rustc-version.txt
'

mkdir -p "$OUTPUT_DIR"
install -m 0755 "$ROOTFS/build/target/release/o3kd" "$OUTPUT_DIR/o3kd"
install -m 0755 "$ROOTFS/build/target/release/o3k" "$OUTPUT_DIR/o3k"
install -m 0755 "$ROOTFS/build/target/release/o3k-compute-bin" "$OUTPUT_DIR/o3k-compute"
install -m 0755 "$ROOTFS/build/target/release/o3k-network" "$OUTPUT_DIR/o3k-network"
(cd "$OUTPUT_DIR" && sha256sum o3kd o3k o3k-compute o3k-network > SHA256SUMS)

echo "==> recording the glibc floor proof (checked with the host readelf)"
{
  echo "release build baseline: Debian $SUITE (bookworm), glibc 2.36"
  echo "rootfs Debian version: $(cat "$ROOTFS/etc/debian_version")"
  echo "rust toolchain: $(cat "$ROOTFS/build/rustc-version.txt") (rust-toolchain.toml channel $CHANNEL)"
  echo "source commit: $(git -C "$ROOT_DIR" rev-parse HEAD)"
  bash "$ROOT_DIR/packaging/check-glibc-baseline.sh" "$OUTPUT_DIR/o3kd" "$OUTPUT_DIR/o3k" "$OUTPUT_DIR/o3k-compute"
} | tee "$OUTPUT_DIR/glibc-floor.txt"
{
  echo "rootfs: Debian $SUITE (bookworm)"
  echo "arch: $ARCH"
  echo "mirror: $MIRROR"
  echo "toolchain: $(cat "$ROOTFS/build/rustc-version.txt")"
  echo "source_commit: $(git -C "$ROOT_DIR" rev-parse HEAD)"
} > "$OUTPUT_DIR/build-info.txt"

echo "release binaries built on the Debian 12 baseline: $OUTPUT_DIR"
echo "next: O3K_RELEASE_BINARIES_DIR=$OUTPUT_DIR packaging/make-release.sh VERSION libvirt"
