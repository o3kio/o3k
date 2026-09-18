#!/usr/bin/env bash
# get-o3k.sh — thin one-line installer wrapper (issue #613, PP.2 #971).
#
# Published as the GitHub Release asset install.sh of every O3K release: the
# release generator exports this file byte-for-byte as dist/install.sh
# (packaging/make-release.sh, 0755, drift-gated by cmp), so the canonical
# alpha invocation is
#   curl -sfL https://github.com/o3kio/o3k/releases/download/v0.4.0-rc.2/install.sh | sudo sh -
# get.o3k.io is only a convenience 302 redirect to that exact asset:
#   curl -sfL https://get.o3k.io | sudo sh -
#
# Canonical bootstrap (PP.2, contracts/installer-v1.yaml): this script is
# orchestration only. After the verified prebuilt runtime is installed it
# invokes the canonical `o3k init` and authenticated `o3k join` (one local
# BuildingBlock, real Placement/topology state), waits for canonical runtime
# readiness (o3kd /readyz, o3k-compute /readyz, `o3k doctor`), and only then
# creates the bounded o3k-demo-v1 workload through the supported public CLI.
# It never fabricates topology, providers, BuildingBlocks, CloudProfile state,
# agent identity, or readiness, and it never compiles on the target host.
#
# This file is POSIX-sh compatible on purpose: on Ubuntu 24.04 and Debian 12
# `sudo sh -` is dash, so the piped invocation must not depend on bashisms.
# Fail-fast is `set -eu` plus pipefail where the shell supports it — Ubuntu
# 24.04's dash (0.5.12-6ubuntu5) rejects `set -o pipefail`, so it is enabled
# conditionally (empirically verified on a clean noble VM).
#
# SECURITY CONTRACT — no curl|sh of unverified content:
#   The version to install is BAKED into this file (O3K_INSTALLER_VERSION);
#   the installer never consults a channel service or any other network
#   endpoint to decide which version to install. Every file that is executed
#   (packaging/*.sh, bin/o3kd, bin/o3k-compute, bin/o3k-network) comes from the release
#   tarball AFTER its published SHA-256 is verified; the tarball is never
#   extracted before that verification, and extraction rejects any entry that
#   is absolute, contains a ".." component, does not start with "./", or is
#   not a regular file (symlink, hardlink, device, fifo, socket entries are
#   refused from the `tar -tvzf` listing before anything is written). Any
#   download or verification failure aborts.
#
# An optional endpoint may serve this same file with an added FIRST line
#   O3K_PINNED_VERSION="v0.3.0-alpha.1"
# which is a plain shell assignment when the stream is piped to sh. It is
# kept for optional future /v<version> endpoint paths (packaging/get-o3k-worker)
# and handled by the resolution order below; its absence is not an error.
# There is no fallback to main/latest: resolution failure aborts.
#
# Version resolution precedence:
#   1. O3K_VERSION environment variable (explicit dev/test override);
#   2. O3K_PINNED_VERSION (the endpoint-injected first line, if present);
#   3. the baked O3K_INSTALLER_VERSION release pin (this file's own release).
# The installer NEVER consults a channel service.
#
# Upgrade fence (issue #626, docs/plan/o3k-upgrade.md §12): when an O3K
# release is already installed (parsed from
# /usr/local/share/o3k/release-manifest.json), the resolved TARGET version is
# compared against it BEFORE any mutation:
#   - fresh host (no manifest): the normal install flow, unchanged;
#   - installed == target: the existing idempotent convergence flow;
#   - installed > target: refuse the implicit downgrade (exit 1, no mutation);
#   - installed < target: download + verify the new release bundle (tarball +
#     published .sha256 + install.sh) into /var/lib/o3k/upgrade-download/
#     (mode 0700; the only override knob is O3K_UPGRADE_DOWNLOAD_DIR for
#     test/campaign sandboxes), print the exact next command
#     `sudo /var/lib/o3k/upgrade-download/o3k-<target>/bin/o3k upgrade`, and
#     exit 0. Nothing is extracted or executed here — extraction is the o3k
#     upgrade engine's job — so a noninteractive curl|sh NEVER auto-upgrades
#     an existing installation (safety over convenience).
#
# Supported platforms (strict): Linux x86_64, Ubuntu 24.04 (noble) or
# Debian 12 (bookworm). Anything else fails with a clear message. Root is
# required.
#
# Overrides for testing/campaigns (the only knobs):
#   O3K_RELEASE_BASE  release asset base (default
#                     https://github.com/o3kio/o3k/releases/download)
# Local campaigns serve the release assets from one http server:
# /releases/v<version>/<assets>; HTTP is permitted only for this explicit
# override, production URLs are pinned to HTTPS.
#
# Release asset naming contract (packaging/make-release-archive.sh):
#   o3k-<version>-linux-x86_64.tar.gz + o3k-<version>-linux-x86_64.tar.gz.sha256
#   at <release-base>/v<version>/.
#
# The dependency package list mirrors the exact host set proven by the clean
# Ubuntu 24.04 and Debian 12 VM campaigns
# (target/real-host-workflow-artifacts/asr-021-cd15263/vm-run.sh cloud-init
# package list plus openssl/openssh-client for the bundled bootstrap scripts
# and binutils for readelf in the bundled verify-release-bundle.sh glibc floor
# check).
# This is the ONE place the outer installer may apt-install. It does NOT touch
# netplan, systemd-networkd, sysctl forwarding, or host-wide NAT (goal §11).
set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

# Baked release pin — updated in EVERY release's version-bump commit; the
# published install.sh GitHub Release asset is byte-identical to this file,
# so an installer downloaded from .../releases/download/v<version>/install.sh
# installs exactly <version> by default.
O3K_INSTALLER_VERSION="v0.4.0-rc.2"
O3K_RELEASE_BASE="${O3K_RELEASE_BASE:-https://github.com/o3kio/o3k/releases/download}"
INSTALL_MANIFEST=/usr/local/share/o3k/.o3k-installed

die() { printf 'O3K installer: %s\n' "$1" >&2; exit 1; }
step() { printf '✓ %s\n' "$1"; }

# Platform guard — self-contained so the test matrix can exercise it with
# faked inputs in a subshell.
check_platform() {
  local kernel="$1" machine="$2" distro_id="$3" codename="$4"
  [ "$kernel" = Linux ] || {
    printf 'unsupported kernel: %s — only Linux x86_64 is supported\n' "$kernel" >&2
    exit 1
  }
  [ "$machine" = x86_64 ] || {
    printf 'unsupported architecture: %s — only x86_64 is supported\n' "$machine" >&2
    exit 1
  }
  case "$distro_id:$codename" in
    ubuntu:noble|debian:bookworm) ;;
    *)
      printf 'unsupported distribution: %s %s — only Ubuntu 24.04 (noble) and Debian 12 (bookworm) are supported\n' \
        "${distro_id:-unknown}" "${codename:-unknown}" >&2
      exit 1
      ;;
  esac
}

# Version fence — the ADR-0130 release-version format
# (docs/adr/ADR-0130-release-version-path-fence.md): numeric release version
# with one or two dots and an optional dot-separated alphanumeric prerelease
# suffix, nothing else; an optional leading "v" is accepted and stripped.
# Self-contained so the test matrix can exercise it with faked inputs.
check_version_format() {
  local version="${1#v}"
  printf '%s\n' "$version" \
    | grep -Eq '^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$' \
    || {
      printf 'unsupported version: %s — expected a published release version like v0.3.0-alpha.1; refusing to fall back to main/latest\n' "$1" >&2
      exit 1
    }
}

trim() { # dash-safe: dash does not implement [:space:] in expansion patterns
  printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

fetch() { # fetch URL DESTINATION — fail closed, no silent retry exhaustion
  local url="$1" destination="$2" proto='=https'
  case "$url" in
    http://*) proto='=http,https' ;; # only for the documented local overrides
  esac
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 15 \
    --max-time 600 --proto "$proto" --output "$destination" "$url" \
    || die "download failed: $url"
}

safe_extract() { # safe_extract TARBALL DESTINATION ENTRIES_FILE
  local tarball="$1" destination="$2" entries="$3" entry
  if ! tar -tzf "$tarball" >"$entries" 2>/dev/null; then
    die "release archive is not a readable gzip tarball: $tarball"
  fi
  while IFS= read -r entry; do
    [ -n "$entry" ] || die "release archive contains an empty entry"
    case "$entry" in
      ./*) ;;
      *) die "unsafe release archive entry (must start with ./): $entry" ;;
    esac
    case "$entry" in
      *'/../'*|*'/..'|'..') die "unsafe release archive entry (.. component): $entry" ;;
    esac
  done <"$entries"
  # Second pass over the verbose listing: refuse any non-regular entry type
  # (symlink, device, fifo, socket) before extraction so an archive cannot
  # plant a link or special file in the extraction tree. The leading listing
  # character is the entry type; ` -> ` is the GNU tar symlink target marker.
  # Checking both is deliberate: a tar implementation that renders a link
  # differently is still caught by the type character.
  if ! tar -tvzf "$tarball" >"$entries.types" 2>/dev/null; then
    die "release archive is not a readable gzip tarball: $tarball"
  fi
  while IFS= read -r entry; do
    case "$entry" in
      *' -> '*) die "unsafe release archive entry (symlink): $entry" ;;
    esac
    case "$(printf '%s' "$entry" | cut -c1)" in
      l|b|c|p|s) die "unsafe release archive entry (device, fifo, or link): $entry" ;;
    esac
  done <"$entries.types"
  tar -xzf "$tarball" -C "$destination" \
    || die "release archive extraction failed: $tarball"
}

wait_http_ok() { # wait_http_ok URL ATTEMPTS
  local url="$1" attempts="$2" attempt=1
  while [ "$attempt" -le "$attempts" ]; do
    if curl --fail --silent --output /dev/null --max-time 5 "$url"; then
      return 0
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
  return 1
}

# Idempotency notice — self-contained so the test matrix can exercise it with
# a faked manifest path in a subshell.
print_installed_notice() {
  if [ -f "$INSTALL_MANIFEST" ] && [ ! -L "$INSTALL_MANIFEST" ]; then
    printf 'O3K v%s already installed\n' "${VERSION_NO_V:-}"
  fi
}

# ---- upgrade fence helpers (issue #626) ---------------------------------------
# compare_versions LEFT RIGHT — embedded python3 semver-with-prerelease
# comparison (the ADR-0130 release-version format: one or two numeric dots
# plus an optional dot-separated alphanumeric prerelease; a leading "v" is
# accepted and stripped). Exit codes: 0 = LEFT is older, 1 = equal,
# 2 = LEFT is newer, 3 = unparseable input (caller must fail closed).
# Deterministic and unit-tested by tests/installer-negative.sh (extracted via
# sed and driven with faked inputs, same mechanism as check_platform).
compare_versions() {
python3 - "$1" "$2" <<'PY'
import re
import sys


def parse(text):
    text = text.strip()
    if text.startswith("v"):
        text = text[1:]
    match = re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){1,2}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?", text
    )
    if match is None:
        return None
    body, _, prerelease = text.partition("-")
    numeric = [int(part) for part in body.split(".")]
    while len(numeric) < 3:
        numeric.append(0)
    identifiers = tuple(prerelease.split(".")) if prerelease else ()
    return numeric, identifiers


def identifier_key(identifier):
    return (0, int(identifier)) if identifier.isdigit() else (1, identifier)


def precedence(parsed):
    numeric, identifiers = parsed
    return tuple(numeric) + (0 if identifiers else 1,), tuple(
        identifier_key(item) for item in identifiers
    )


left = parse(sys.argv[1])
right = parse(sys.argv[2])
if left is None or right is None:
    sys.exit(3)
if precedence(left) < precedence(right):
    sys.exit(0)
if precedence(left) == precedence(right):
    sys.exit(1)
sys.exit(2)
PY
}

# read_installed_version MANIFEST — prints the installed release version, or
# nothing when the manifest is absent (fresh host). Unreadable/malformed
# manifests fail closed (exit 3). Self-contained for the test matrix.
read_installed_version() {
  local manifest="$1"
  [ -f "$manifest" ] || return 0
  [ ! -L "$manifest" ] || die "installed release manifest must not be a symlink: $manifest"
python3 - "$manifest" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        document = json.load(stream)
except (OSError, ValueError):
    print("O3K installer: installed release manifest is unreadable: %s" % sys.argv[1], file=sys.stderr)
    sys.exit(3)
version = document.get("version") if isinstance(document, dict) else None
if not isinstance(version, str) or not version.strip():
    print("O3K installer: installed release manifest declares no version: %s" % sys.argv[1], file=sys.stderr)
    sys.exit(3)
print(version.strip())
PY
}

# verify_delegation_sha256 DIR ASSET — the same strict published-digest gate
# the install path uses: exactly one `<64-hex>  <asset>` line naming the
# expected asset, then sha256sum --check --strict in DIR.
verify_delegation_sha256() {
  local dir="$1" asset="$2" lines fields digest name
  lines="$(awk 'END{print NR}' "$dir/$asset.sha256")"
  fields="$(awk 'NR==1{print NF}' "$dir/$asset.sha256")"
  digest="$(awk 'NR==1{print $1}' "$dir/$asset.sha256")"
  name="$(awk 'NR==1{print $2}' "$dir/$asset.sha256")"
  [ "$lines" = 1 ] && [ "$fields" = 2 ] \
    || die "published SHA-256 file is malformed: $asset.sha256"
  printf '%s' "$digest" | grep -Eq '^[0-9a-f]{64}$' \
    || die "published SHA-256 file is malformed: $asset.sha256"
  [ "$name" = "$asset" ] \
    || die "published SHA-256 file names an unexpected asset: $name"
  (cd "$dir" && sha256sum -c --strict -- "$asset.sha256") \
    || die "published SHA-256 verification failed for $asset — refusing to extract or execute anything from the bundle"
}

# delegate_upgrade_download — verified delegation download for the
# installed < target case. Downloads tarball + published .sha256 + install.sh
# into O3K_UPGRADE_DOWNLOAD_DIR (0700), extracts the VERIFIED tarball next to
# them (so the printed `o3k upgrade` entry point exists), and prints the
# exact next command. Extracting a verified archive is not executing a
# downloaded script: the o3k upgrade engine re-downloads and re-verifies
# every asset itself before any mutation, so this copy is only an operator
# entry point, never trusted directly.
# Interrupted-delegation reuse: when the directory already holds the tarball
# and its .sha256, they are re-verified against the published digest and
# reused; a failed re-verification fails closed (remove the directory
# deliberately to force a fresh download).
delegate_upgrade_download() {
  local asset base dest reused=0 bundle_dir
  asset="o3k-${VERSION_NO_V}-linux-x86_64.tar.gz"
  base="$O3K_RELEASE_BASE/v$VERSION_NO_V"
  dest="$O3K_UPGRADE_DOWNLOAD_DIR"
  mkdir -p "$dest"
  chmod 700 "$dest"
  if [ -s "$dest/$asset" ] && [ -s "$dest/$asset.sha256" ]; then
    reused=1
    verify_delegation_sha256 "$dest" "$asset"
  else
    fetch "$base/$asset" "$dest/$asset"
    fetch "$base/$asset.sha256" "$dest/$asset.sha256"
    verify_delegation_sha256 "$dest" "$asset"
  fi
  # install.sh asset copy: a fresh atomic fetch every time (byte-identical to
  # the published GitHub Release asset; never executed by this installer).
  fetch "$base/install.sh" "$dest/install.sh.tmp"
  mv -- "$dest/install.sh.tmp" "$dest/install.sh"
  # Extract the verified tarball so `.../o3k-<target>/bin/o3k upgrade` exists
  # (entry point only; the engine re-verifies everything before mutating).
  # The tarball root is already `o3k-<version>/`, so extraction targets the
  # download directory itself (same convention as the install flow's
  # `safe_extract "$TMP_DIR/$ASSET" "$TMP_DIR" ...`).
  bundle_dir="$dest/o3k-${VERSION_NO_V}"
  if [ ! -x "$bundle_dir/bin/o3k" ]; then
    rm -rf -- "$bundle_dir"
    safe_extract "$dest/$asset" "$dest" "$dest/delegation-entries.txt"
  fi
  chmod 0600 "$dest/$asset" "$dest/$asset.sha256" "$dest/install.sh"
  if [ "$reused" -eq 1 ]; then
    step "upgrade download for O3K v$VERSION_NO_V re-verified ($dest)"
  else
    step "upgrade download for O3K v$VERSION_NO_V verified ($dest)"
  fi
  printf 'O3K v%s is installed; the installer never upgrades an existing installation automatically.\n' "${INSTALLED_VERSION#v}"
  printf 'Run: sudo %s/o3k-%s/bin/o3k upgrade\n' "$dest" "$VERSION_NO_V"
}

# check_upgrade_fence — compares the resolved TARGET version against the
# installed release (parsed from /usr/local/share/o3k/release-manifest.json;
# absent = fresh host). Runs after the platform guard and BEFORE any mutation.
check_upgrade_fence() {
  INSTALLED_VERSION="$(read_installed_version "$INSTALLED_MANIFEST")" \
    || die "installed release manifest is unreadable or declares no version: $INSTALLED_MANIFEST"
  [ -n "$INSTALLED_VERSION" ] || return 0 # fresh host: normal install flow
  set +e
  compare_versions "$INSTALLED_VERSION" "$VERSION"
  fence_status=$?
  set -e
  case "$fence_status" in
    0) # installed < target: verified delegation, then explicit operator action
       delegate_upgrade_download
       exit 0
       ;;
    1) # same version: the existing idempotent convergence flow below
       ;;
    2)
       die "installed v${INSTALLED_VERSION#v} is newer than requested v${VERSION#v}; refusing implicit downgrade"
       ;;
    *)
       die "cannot compare installed v${INSTALLED_VERSION#v} against requested v${VERSION#v}"
       ;;
  esac
}

# ---- platform and privilege guards -------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  printf 'O3K installer: root is required; run: curl -sfL https://get.o3k.io | sudo sh -\n' >&2
  exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
check_platform "$(uname -s)" "$(uname -m)" "${ID:-}" "${VERSION_CODENAME:-}"

printf 'O3K Cloud OS — TestLab\n'
printf '✓ %s %s\n' "${PRETTY_NAME:-${ID:-unknown} ${VERSION_ID:-unknown}}" "$(uname -m)"

# ---- version resolution -------------------------------------------------------
# The version is baked into this file; the installer never consults a channel
# service. Explicit dev/test overrides take precedence.
VERSION="${O3K_VERSION:-${O3K_PINNED_VERSION:-$O3K_INSTALLER_VERSION}}"
VERSION="$(trim "$VERSION")"
[ -n "$VERSION" ] || die "no installer version resolved"
check_version_format "$VERSION"
VERSION_NO_V="${VERSION#v}"

# ---- upgrade fence (issue #626) — before ANY mutation -------------------------
# Fresh host -> normal install; same version -> idempotent convergence;
# newer installed version -> refuse implicit downgrade (exit 1); older
# installed version -> verified delegation download + printed
# `sudo .../bin/o3k upgrade` command, exit 0. curl|sh never auto-upgrades an
# existing install.
INSTALLED_MANIFEST=/usr/local/share/o3k/release-manifest.json
O3K_UPGRADE_DOWNLOAD_DIR="${O3K_UPGRADE_DOWNLOAD_DIR:-/var/lib/o3k/upgrade-download}"
check_upgrade_fence
print_installed_notice

# ---- private temp dir + cleanup ----------------------------------------------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-installer.XXXXXX")"
chmod 700 "$TMP_DIR"
trap 'rm -rf -- "$TMP_DIR"' EXIT
trap 'rm -rf -- "$TMP_DIR"; exit 130' INT
trap 'rm -rf -- "$TMP_DIR"; exit 143' TERM HUP

# ---- host dependencies (the one place apt is allowed) -------------------------
# Mirror the proven clean-VM set (asr-021-cd15263/vm-run.sh cloud-init):
# ca-certificates curl libvirt-daemon-system libvirt-clients qemu-utils
# iproute2 dnsmasq-base polkitd genisoimage python3 python3-openstackclient,
# with the distro-specific QEMU package (Ubuntu 24.04: qemu-kvm; Debian 12:
# qemu-system-x86), plus openssl (bootstrap-certs.sh) and openssh-client
# (ssh-keygen in bootstrap-testlab.sh), plus binutils (readelf for the bundled
# verify-release-bundle.sh glibc floor check). libvirtd is enabled/started
# exactly like the proven VM setup did. No netplan/NAT/sysctl/host-network
# writes.
printf 'installing host dependencies (apt)\n'
APT_PACKAGES="ca-certificates curl openssl openssh-client binutils libvirt-daemon-system libvirt-clients qemu-utils iproute2 dnsmasq-base polkitd genisoimage python3 python3-openstackclient"
case "$ID:$VERSION_CODENAME" in
  ubuntu:noble) APT_PACKAGES="$APT_PACKAGES qemu-kvm" ;;
  debian:bookworm) APT_PACKAGES="$APT_PACKAGES qemu-system-x86" ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
# shellcheck disable=SC2086
apt-get install -y $APT_PACKAGES
systemctl enable --now libvirtd
step 'dependencies ready'

# ---- download the certified release bundle ------------------------------------
ASSET="o3k-${VERSION_NO_V}-linux-x86_64.tar.gz"
ASSET_URL="$O3K_RELEASE_BASE/v$VERSION_NO_V/$ASSET"
printf 'downloading %s\n' "$ASSET"
fetch "$ASSET_URL" "$TMP_DIR/$ASSET"
fetch "$ASSET_URL.sha256" "$TMP_DIR/$ASSET.sha256"

# ---- published SHA-256 verification BEFORE extraction -------------------------
SHA_LINES="$(awk 'END{print NR}' "$TMP_DIR/$ASSET.sha256")"
SHA_FIELDS="$(awk 'NR==1{print NF}' "$TMP_DIR/$ASSET.sha256")"
SHA_DIGEST="$(awk 'NR==1{print $1}' "$TMP_DIR/$ASSET.sha256")"
SHA_NAME="$(awk 'NR==1{print $2}' "$TMP_DIR/$ASSET.sha256")"
[ "$SHA_LINES" = 1 ] && [ "$SHA_FIELDS" = 2 ] \
  || die "published SHA-256 file is malformed: $ASSET.sha256"
printf '%s' "$SHA_DIGEST" | grep -Eq '^[0-9a-f]{64}$' \
  || die "published SHA-256 file is malformed: $ASSET.sha256"
[ "$SHA_NAME" = "$ASSET" ] \
  || die "published SHA-256 file names an unexpected asset: $SHA_NAME"
(cd "$TMP_DIR" && sha256sum -c --strict -- "$ASSET.sha256") \
  || die "published SHA-256 verification failed for $ASSET — refusing to extract or execute anything from the bundle"
step 'release archive SHA-256 verified'

# ---- safe extraction ----------------------------------------------------------
safe_extract "$TMP_DIR/$ASSET" "$TMP_DIR" "$TMP_DIR/entries.txt"
BUNDLE_DIR="$TMP_DIR/o3k-$VERSION_NO_V"
[ -d "$BUNDLE_DIR" ] || die "release archive does not contain the expected bundle directory: o3k-$VERSION_NO_V"

# ---- bundled integrity and preflight ------------------------------------------
bash "$BUNDLE_DIR/packaging/verify-release-bundle.sh" "$BUNDLE_DIR" \
  || die "release bundle verification failed for o3k-$VERSION_NO_V"
step "O3K v$VERSION_NO_V verified"
bash "$BUNDLE_DIR/packaging/preflight.sh" --profile libvirt --data-dir /var/lib/o3k \
  || die "preflight failed (--profile libvirt --data-dir /var/lib/o3k): the host does not meet the certified TestLab requirements"
step 'KVM available'

# ---- TLS identities: preserve complete set, bootstrap only when absent --------
TLS_DIR=/etc/o3k/tls
TLS_FILES="ca.pem server.pem server-key.pem agent.pem agent-key.pem agent-id agent-fingerprint"
tls_present=0
for file in $TLS_FILES; do
  if [ -e "$TLS_DIR/$file" ] || [ -L "$TLS_DIR/$file" ]; then
    [ -f "$TLS_DIR/$file" ] && [ ! -L "$TLS_DIR/$file" ] && [ -s "$TLS_DIR/$file" ] \
      || die "TLS identity is not a regular non-empty file: $TLS_DIR/$file"
    tls_present=$((tls_present + 1))
  fi
done
if [ "$tls_present" -eq 7 ]; then
  step 'TLS identities preserved'
elif [ "$tls_present" -eq 0 ]; then
  bash "$BUNDLE_DIR/packaging/bootstrap-certs.sh" \
    --output-dir "$TLS_DIR" --server-name o3k-control-plane --agent-id compute-agent \
    || die 'TLS bootstrap failed'
  step 'mTLS identities ready'
else
  die "partial TLS identity set under $TLS_DIR ($tls_present of 7 files) — refusing to regenerate valid identities; complete the set manually (never use --force)"
fi

# ---- install from the verified bundle -----------------------------------------
# install.sh discovers bin/o3k-network inside the extracted bundle itself and
# installs it (with its unit, not enabled) when present — no extra flag needed.
# --defer-compute-start keeps the compute agent stopped so the canonical join
# below wins the NodeRegistry epoch race (see the canonical bootstrap section).
bash "$BUNDLE_DIR/packaging/install.sh" --profile libvirt --noninteractive \
  --defer-compute-start \
  --binary "$BUNDLE_DIR/bin/o3kd" --compute-binary "$BUNDLE_DIR/bin/o3k-compute" \
  --o3k-binary "$BUNDLE_DIR/bin/o3k" \
  || die 'installation failed; the host holds recoverable O3K-owned state and re-running the installer converges'
step 'o3kd installed'
step 'o3k-compute installed'

# ---- canonical P15.6 bootstrap (contracts/installer-v1.yaml) -------------------
# The installer is orchestration ONLY: it never fabricates topology, Placement
# providers, BuildingBlocks, CloudProfile state, agent identity, or readiness.
# Canonical init creates the CloudProfile + one-time enrollment grant; the
# authenticated join enrolls this host's agent identity (the mTLS certificate
# minted above) and creates exactly one local BuildingBlock with Placement
# inventory. Idempotent by construction: a repeated init converges on the
# durable profile and issues a fresh grant; a replayed join short-circuits on
# the durable enrolled-agent projection without consuming a second grant.
ENV_FILE=/etc/o3k/o3kd.env
O3K_BIN=/usr/local/bin/o3k
API_URL=http://127.0.0.1:18080/o3k/v1

# Read one shell-quoted scalar from the daemon env file. The generated
# secrets are hex-only, so %q quoting is always plain; anything else fails
# closed instead of misparsing a credential.
read_env_scalar() {
  key="$1"
  value=$(awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")
  case "$value" in
    ""|*[!0-9a-fA-F]*) die "$key is missing or not a plain hex value in $ENV_FILE" ;;
  esac
  printf '%s' "$value"
}

wait_http_ok http://127.0.0.1:18080/healthz 30 \
  || die 'o3kd did not become healthy (http://127.0.0.1:18080/healthz)'
step 'control plane ready'

BOOTSTRAP_SECRET=$(read_env_scalar O3K_BOOTSTRAP_SECRET)
AGENT_ID=$(cat "$TLS_DIR/agent-id" 2>/dev/null || true)
case "$AGENT_ID" in *[!A-Za-z0-9._-]*|'') die "agent identity is invalid: $TLS_DIR/agent-id" ;; esac
VCPUS=$(nproc 2>/dev/null || true)
MEMORY_MB=$(awk '/^MemTotal:/ {print int($2 / 1024); exit}' /proc/meminfo)
DISK_GB=$(awk -F= '$1 == "O3K_COMPUTE_MAX_DISK_GB" {sub(/^[^=]*=/, ""); print; exit}' /etc/o3k/o3k-compute.env)
[ -n "$DISK_GB" ] || DISK_GB=10
case "$VCPUS" in ''|*[!0-9]*) die 'host inventory is unavailable (vcpus)' ;; esac
case "$MEMORY_MB" in ''|*[!0-9]*) die 'host inventory is unavailable (memory)' ;; esac
case "$DISK_GB" in ''|*[!0-9]*) die 'host inventory is unavailable (disk)' ;; esac

RUNUSER_BIN=$(command -v runuser || true)
[ -n "$RUNUSER_BIN" ] || RUNUSER_BIN=/usr/sbin/runuser
[ -x "$RUNUSER_BIN" ] || die 'runuser is unavailable; cannot invoke canonical bootstrap as the o3k service account'

# Canonical init, executed as the o3k service account. The response (which
# carries the one-time enrollment token) goes to a root-owned 0600 temporary
# file opened by this shell before privilege drop; it is parsed and destroyed
# immediately and is never printed.
INIT_OUT="$TMP_DIR/o3k-init.json"
( umask 077 && : >"$INIT_OUT" )
"$RUNUSER_BIN" -u o3k -- env O3K_API_URL="$API_URL" \
  O3K_BOOTSTRAP_SECRET="$BOOTSTRAP_SECRET" "$O3K_BIN" init --agent-id "$AGENT_ID" \
  >"$INIT_OUT" || die 'canonical o3k init failed (see o3kd logs: journalctl -u o3kd)'
ENROLLMENT_TOKEN=$(python3 - "$INIT_OUT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
token = response.get("enrollment_token")
if not isinstance(token, str) or not token:
    raise SystemExit("canonical init did not return an enrollment token")
print(token)
PY
) || die 'canonical init response was invalid'
rm -f -- "$INIT_OUT"
step 'canonical bootstrap initialized (CloudProfile + enrollment grant)'

# Authenticated canonical join. A bounded retry converges across a transient
# store/provider conflict; the grant stays single-use either way.
JOIN_OUT="$TMP_DIR/o3k-join.json"
( umask 077 && : >"$JOIN_OUT" )
AGENT_EPOCH=$(openssl rand -hex 16)
join_ok=0
join_attempt=1
while [ "$join_attempt" -le 5 ]; do
  if "$RUNUSER_BIN" -u o3k -- env O3K_API_URL="$API_URL" "$O3K_BIN" join \
      --token "$ENROLLMENT_TOKEN" --agent-id "$AGENT_ID" --agent-epoch "$AGENT_EPOCH" \
      --certificate "$TLS_DIR/agent.pem" \
      --vcpus "$VCPUS" --memory-mb "$MEMORY_MB" --disk-gb "$DISK_GB" \
      >"$JOIN_OUT" 2>"$TMP_DIR/o3k-join.err"; then
    join_ok=1
    break
  fi
  if [ "$join_attempt" -lt 5 ]; then
    printf 'canonical authenticated o3k join attempt %s/5 did not converge; retrying\n' "$join_attempt" >&2
    sleep 2
  fi
  join_attempt=$((join_attempt + 1))
done
if [ "$join_ok" -ne 1 ]; then
  printf 'O3K installer: canonical authenticated o3k join failed: %s\n' \
    "$(tail -1 "$TMP_DIR/o3k-join.err" 2>/dev/null || echo 'no response')" >&2
  exit 1
fi
BUILDING_BLOCK_ID=$(python3 - "$JOIN_OUT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
block = response.get("building_block_id")
if not isinstance(block, str) or not block:
    raise SystemExit("canonical join did not return a building block id")
print(block)
PY
) || BUILDING_BLOCK_ID='(unavailable)'
rm -f -- "$JOIN_OUT" "$TMP_DIR/o3k-join.err"
step "canonical authenticated join complete (BuildingBlock $BUILDING_BLOCK_ID)"

# Only after canonical join does the compute agent start: its first
# registration adopts the join-established identity instead of fencing it.
systemctl start o3k-compute.service \
  || die 'o3k-compute.service failed to start'
wait_http_ok http://127.0.0.1:9100/readyz 90 \
  || die 'o3k-compute did not become ready (http://127.0.0.1:9100/readyz)'
step 'compute agent ready'
wait_http_ok http://127.0.0.1:18080/readyz 120 \
  || die 'o3kd did not reach canonical readiness (http://127.0.0.1:18080/readyz)'
step 'control plane ready (canonical readiness)'

# Canonical diagnostics gate: `o3k doctor` must report no failing checks.
# A fresh installation legitimately carries advisory WARNs (for example
# "no O3K-created backup exists yet"), which yields overall "warning" and
# exit 1 — that is still a successful diagnostic run. Only "unhealthy"
# (any FAIL) or a doctor invocation error (exit 2) fails the install.
DOCTOR_VERDICT=""
doctor_attempt=1
while [ "$doctor_attempt" -le 30 ]; do
  doctor_rc=0
  DOCTOR_OUT="$("$O3K_BIN" doctor --json 2>/dev/null)" || doctor_rc=$?
  if [ "$doctor_rc" -eq 2 ]; then
    die 'o3k doctor could not produce a report (usage or serialization error)'
  fi
  if [ "$doctor_rc" -le 1 ] && [ -n "$DOCTOR_OUT" ]; then
    DOCTOR_VERDICT="$(printf '%s' "$DOCTOR_OUT" | python3 -c '
import json
import sys

try:
    print(json.load(sys.stdin)["overall_status"])
except Exception:
    print("unknown")
')"
    if [ "$DOCTOR_VERDICT" = healthy ] || [ "$DOCTOR_VERDICT" = warning ]; then
      break
    fi
  fi
  DOCTOR_VERDICT=""
  sleep 5
  doctor_attempt=$((doctor_attempt + 1))
done
unset DOCTOR_OUT
[ -n "$DOCTOR_VERDICT" ] || die 'o3k doctor reported failing checks; the installation is not healthy'
step 'o3k doctor healthy'

# ---- bounded demo cloud (public APIs only) ------------------------------------
# Creates the frozen o3k-demo-v1 workload (CirrOS image, TestLab flavor,
# bounded flat network, keypair, test-vm) through the supported public CLI
# after canonical bootstrap. The script fails closed unless the canonical
# bootstrap state is durably ready; it fabricates nothing itself.
bash "$BUNDLE_DIR/packaging/bootstrap-testlab.sh" || die 'TestLab bootstrap failed'

printf '\nO3K is ready.\n\n'
printf 'Cloud: single-node demo (o3k-demo-v1)\n'
printf 'BuildingBlock: %s\n' "$BUILDING_BLOCK_ID"
printf 'Endpoints:\n'
printf '  identity/image/network/compute/placement: http://127.0.0.1:18080\n'
printf '  native API: %s\n' "$API_URL"
printf 'Credentials:\n'
printf '  /etc/o3k/admin-openrc\n'
printf '  /etc/o3k/clouds.yaml\n\n'
printf 'Try:\n\n'
printf '  source /etc/o3k/admin-openrc\n'
printf '  openstack server list\n'
printf '  openstack console log show test-vm\n'
printf '  sudo o3k doctor\n'
