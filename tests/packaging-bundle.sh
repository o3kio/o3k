#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-bundle.XXXXXX")"
DIRTY_MARKER="$ROOT_DIR/.o3k-release-dirty-test"
ESCAPE_SENTINEL="$ROOT_DIR/o3k-release-escape-sentinel"
cleanup() { rm -f -- "$DIRTY_MARKER" "$ESCAPE_SENTINEL"; rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT

BUNDLE_DIR="$WORK_DIR/bundle"
mkdir -p "$BUNDLE_DIR/bin" "$BUNDLE_DIR/packaging" "$BUNDLE_DIR/scripts"
for file in \
  install.sh o3kd.service reset.sh uninstall.sh diagnose.sh preflight.sh \
  bootstrap-certs.sh bootstrap-testlab.sh release-gate.sh validate-human-review.sh scan-release-evidence.sh generate-candidate-evidence-manifest.py o3k-compute.service o3k-network.service 50-o3k-libvirt.rules; do
  cp "$ROOT_DIR/packaging/$file" "$BUNDLE_DIR/packaging/$file"
done
cp "$ROOT_DIR/scripts/generate-passwords.sh" "$BUNDLE_DIR/scripts/generate-passwords.sh"

printf '#!/usr/bin/env bash\nprintf bundled-o3kd\n' >"$BUNDLE_DIR/bin/o3kd"
chmod 0755 "$BUNDLE_DIR/bin/o3kd"
printf '#!/usr/bin/env bash\nprintf bundled-o3k\n' >"$BUNDLE_DIR/bin/o3k"
chmod 0755 "$BUNDLE_DIR/bin/o3k"
printf '#!/usr/bin/env bash\nprintf bundled-o3k-compute\n' >"$BUNDLE_DIR/bin/o3k-compute"
chmod 0755 "$BUNDLE_DIR/bin/o3k-compute"
printf '#!/usr/bin/env bash\nprintf bundled-o3k-network\n' >"$BUNDLE_DIR/bin/o3k-network"
chmod 0755 "$BUNDLE_DIR/bin/o3k-network"
# Bundle-root provenance fixtures (issue #617): install.sh installs them as
# share/o3k/release-manifest.json and share/o3k/SHA256SUMS exactly like the
# real bundle produced by make-release.sh.
printf '{"version":"0.0-bundle-test","profile":"fake"}\n' >"$BUNDLE_DIR/manifest.json"
(cd "$BUNDLE_DIR" && sha256sum manifest.json >SHA256SUMS)

CARGO_DIR="$WORK_DIR/no-cargo"
mkdir -p "$CARGO_DIR"
cat >"$CARGO_DIR/cargo" <<'EOF'
#!/usr/bin/env bash
touch "${CARGO_MARKER:?}"
printf 'cargo must not be called for a release bundle\n' >&2
exit 97
EOF
chmod 0755 "$CARGO_DIR/cargo"

touch "$DIRTY_MARKER"
if CARGO_MARKER="$WORK_DIR/dirty-cargo-invoked" PATH="$CARGO_DIR:$PATH" \
    bash "$ROOT_DIR/packaging/make-release.sh" 0.0-dirty-test fake; then
  echo "release builder accepted a dirty source tree" >&2
  exit 1
fi
[[ ! -e "$WORK_DIR/dirty-cargo-invoked" ]]
rm -f -- "$DIRTY_MARKER"

printf 'must survive invalid version input\n' >"$ESCAPE_SENTINEL"
for invalid_version in '../../../o3k-release-escape' '1.2.3/escape' '1.2.3 bad' '1.2.3"quote'; do
  if CARGO_MARKER="$WORK_DIR/invalid-version-cargo" PATH="$CARGO_DIR:$PATH" \
      bash "$ROOT_DIR/packaging/make-release.sh" "$invalid_version" fake; then
    echo "release builder accepted unsafe version: $invalid_version" >&2
    exit 1
  fi
  [[ ! -e "$WORK_DIR/invalid-version-cargo" ]]
  grep -qx 'must survive invalid version input' "$ESCAPE_SENTINEL"
done
rm -f -- "$ESCAPE_SENTINEL"

DIST_TARGET="$WORK_DIR/dist-target"
DIST_LINK="$WORK_DIR/dist-link"
mkdir -p "$DIST_TARGET"
ln -s "$DIST_TARGET" "$DIST_LINK"
if O3K_RELEASE_DIST_DIR="$DIST_LINK" CARGO_MARKER="$WORK_DIR/symlink-dist-cargo" \
    PATH="$CARGO_DIR:$PATH" bash "$ROOT_DIR/packaging/make-release.sh" 0.0-symlink-dist fake; then
  echo "release builder accepted a symlinked dist root" >&2
  exit 1
fi
[[ ! -e "$WORK_DIR/symlink-dist-cargo" ]]
[[ -z "$(find "$DIST_TARGET" -mindepth 1 -print -quit)" ]]

PREFIX="$WORK_DIR/prefix"
CARGO_MARKER="$WORK_DIR/cargo-invoked" PATH="$CARGO_DIR:$PATH" bash "$BUNDLE_DIR/packaging/install.sh" \
  --profile fake --noninteractive \
  --prefix "$PREFIX" --data-dir "$WORK_DIR/data" \
  --config-dir "$WORK_DIR/config" --log-dir "$WORK_DIR/log"

cmp -s "$BUNDLE_DIR/bin/o3kd" "$PREFIX/bin/o3kd"
cmp -s "$BUNDLE_DIR/bin/o3k" "$PREFIX/bin/o3k"
[[ -f "$PREFIX/share/o3k/o3kd.service" ]]
cmp -s "$BUNDLE_DIR/manifest.json" "$PREFIX/share/o3k/release-manifest.json"
cmp -s "$BUNDLE_DIR/SHA256SUMS" "$PREFIX/share/o3k/SHA256SUMS"
grep -Fqx 'bin/o3k' "$PREFIX/share/o3k/.o3k-installed"
grep -Fqx 'share/o3k/release-manifest.json' "$PREFIX/share/o3k/.o3k-installed"
grep -Fqx 'share/o3k/SHA256SUMS' "$PREFIX/share/o3k/.o3k-installed"
[[ ! -e "$WORK_DIR/cargo-invoked" ]]

# Keep this deterministic and host-independent: the real preflight contract is
# exercised separately, while this invocation only verifies bundle selection.
cat >"$BUNDLE_DIR/packaging/preflight.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
EOF
chmod 0755 "$BUNDLE_DIR/packaging/preflight.sh"

# A libvirt bundle must validate certificate inputs before creating any
# installation state. This keeps a failed clean install repair-free.
if bash "$BUNDLE_DIR/packaging/install.sh" \
    --profile libvirt --noninteractive \
    --prefix "$WORK_DIR/invalid-libvirt-prefix" \
    --data-dir "$WORK_DIR/invalid-libvirt-data" \
    --config-dir "$WORK_DIR/invalid-libvirt-config" \
    --log-dir "$WORK_DIR/invalid-libvirt-log"; then
  echo "libvirt installer accepted missing TLS inputs" >&2
  exit 1
fi
[[ ! -e "$WORK_DIR/invalid-libvirt-prefix" && ! -e "$WORK_DIR/invalid-libvirt-data" ]]

TLS_DIR="$WORK_DIR/libvirt-config/tls"
mkdir -p "$TLS_DIR"
printf 'o3k-owned-v1 path=%s\n' "$WORK_DIR/libvirt-config" >"$WORK_DIR/libvirt-config/.o3k-owned"
for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem; do
  printf 'test credential\n' >"$TLS_DIR/$file"
done
printf '%064d\n' 0 >"$TLS_DIR/agent-fingerprint"
printf 'compute-agent\n' >"$TLS_DIR/agent-id"

LIBVIRT_PREFIX="$WORK_DIR/libvirt-prefix"
if id o3k >/dev/null 2>&1 && id -nG o3k | tr ' ' '\n' | grep -Eq '^(libvirt|kvm)$'; then
  if CARGO_MARKER="$WORK_DIR/cargo-invoked" PATH="$CARGO_DIR:$PATH" bash "$BUNDLE_DIR/packaging/install.sh" \
      --profile libvirt --noninteractive \
      --prefix "$LIBVIRT_PREFIX" --data-dir "$WORK_DIR/libvirt-data" \
      --config-dir "$WORK_DIR/libvirt-config" --log-dir "$WORK_DIR/libvirt-log"; then
    echo "libvirt bundle installer reused a privileged control account" >&2
    exit 1
  fi
  echo "libvirt bundle install correctly refused a privileged control-account reuse"
else
  CARGO_MARKER="$WORK_DIR/cargo-invoked" PATH="$CARGO_DIR:$PATH" bash "$BUNDLE_DIR/packaging/install.sh" \
    --profile libvirt --noninteractive \
    --prefix "$LIBVIRT_PREFIX" --data-dir "$WORK_DIR/libvirt-data" \
    --config-dir "$WORK_DIR/libvirt-config" --log-dir "$WORK_DIR/libvirt-log"
  cmp -s "$BUNDLE_DIR/bin/o3kd" "$LIBVIRT_PREFIX/bin/o3kd"
  cmp -s "$BUNDLE_DIR/bin/o3k" "$LIBVIRT_PREFIX/bin/o3k"
  cmp -s "$BUNDLE_DIR/bin/o3k-compute" "$LIBVIRT_PREFIX/bin/o3k-compute"
  cmp -s "$BUNDLE_DIR/bin/o3k-network" "$LIBVIRT_PREFIX/bin/o3k-network"
  [[ -f "$LIBVIRT_PREFIX/share/o3k/o3k-compute.service" ]]
  [[ -f "$LIBVIRT_PREFIX/share/o3k/o3k-network.service" ]]
  # Uninstall must process the network entries recorded in the ownership
  # manifest and remove them (regression: allowlist used to reject them).
  bash "$BUNDLE_DIR/packaging/uninstall.sh" --yes \
    --prefix "$LIBVIRT_PREFIX" --data-dir "$WORK_DIR/libvirt-data" \
    --config-dir "$WORK_DIR/libvirt-config" --log-dir "$WORK_DIR/libvirt-log" \
    >"$WORK_DIR/libvirt-uninstall.log" 2>&1
  [[ ! -e "$LIBVIRT_PREFIX/bin/o3k-network" ]] \
    || { echo "uninstall left bin/o3k-network behind" >&2; exit 1; }
  [[ ! -e "$LIBVIRT_PREFIX/share/o3k/o3k-network.service" ]] \
    || { echo "uninstall left the network unit behind" >&2; exit 1; }
  echo "uninstall processed the network manifest entries"
fi

# ---- release bundles fail closed instead of compiling on the target --------
# A bundle (manifest.json + SHA256SUMS at the root) missing a REQUIRED prebuilt
# binary must abort; it must never fall back to cargo on the installation
# target (contracts/installer-v1.yaml no_target_compilation).
INCOMPLETE_BUNDLE="$WORK_DIR/incomplete-bundle"
cp -a "$BUNDLE_DIR" "$INCOMPLETE_BUNDLE"
rm -f -- "$INCOMPLETE_BUNDLE/bin/o3k"
if CARGO_MARKER="$WORK_DIR/incomplete-cargo" PATH="$CARGO_DIR:$PATH" \
    bash "$INCOMPLETE_BUNDLE/packaging/install.sh" \
    --profile fake --noninteractive \
    --prefix "$WORK_DIR/incomplete-prefix" \
    --data-dir "$WORK_DIR/incomplete-data" \
    --config-dir "$WORK_DIR/incomplete-config" \
    --log-dir "$WORK_DIR/incomplete-log" 2>"$WORK_DIR/incomplete.err"; then
  echo "release bundle installer accepted a missing required binary" >&2
  exit 1
fi
[[ ! -e "$WORK_DIR/incomplete-cargo" ]] \
  || { echo "release bundle installer compiled on the target" >&2; exit 1; }
grep -Fq 'refusing to compile O3K on the installation target' "$WORK_DIR/incomplete.err" \
  || { echo "missing fail-closed message for the missing-binary bundle" >&2; exit 1; }
echo "release bundle fail-closed (no target compilation) passed"

# ---- install.sh first-class release asset (successful fake-profile build) ----
# make-release.sh refuses a dirty source tree (its own contract, exercised
# above), so the success-path build runs only on a clean checkout — normal CI.
# On a dirty developer tree the identity gate is instead enforced at
# make-release/make-release-archive time on the release machine, so the asset
# assertions skip with an explicit message rather than fail spuriously.
if [[ -z "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=all)" ]]; then
  ASSET_DIST="$WORK_DIR/asset-dist"
  # The upgrade_from fence is operator-declared: a build without
  # O3K_UPGRADE_FROM_MIN_VERSION must fail closed before any packaging.
  if O3K_RELEASE_DIST_DIR="$ASSET_DIST" O3K_RELEASE_BINARIES_DIR="$BUNDLE_DIR/bin" \
      bash "$ROOT_DIR/packaging/make-release.sh" 0.0.1 fake \
      2>"$WORK_DIR/no-upgrade-from.err"; then
    echo "release builder accepted an unset O3K_UPGRADE_FROM_MIN_VERSION" >&2
    exit 1
  fi
  grep -Fq 'O3K_UPGRADE_FROM_MIN_VERSION is unset' "$WORK_DIR/no-upgrade-from.err" \
    || { echo "missing operator instruction on the unset upgrade_from fence" >&2; exit 1; }
  O3K_UPGRADE_FROM_MIN_VERSION=0.0.1-prev \
  O3K_RELEASE_DIST_DIR="$ASSET_DIST" \
  O3K_RELEASE_BINARIES_DIR="$BUNDLE_DIR/bin" \
    bash "$ROOT_DIR/packaging/make-release.sh" 0.0-installerasset fake
  [[ -f "$ASSET_DIST/install.sh" && -x "$ASSET_DIST/install.sh" ]] \
    || { echo "install.sh release asset missing or not 0755" >&2; exit 1; }
  cmp -s "$ROOT_DIR/packaging/get-o3k.sh" "$ASSET_DIST/install.sh" \
    || { echo "dist/install.sh drifted from packaging/get-o3k.sh" >&2; exit 1; }
  EXPECTED_INSTALLER_SHA256="$(sha256sum "$ROOT_DIR/packaging/get-o3k.sh" | awk '{print $1}')"
  # The declared schema_version must equal the max migration prefix under
  # crates/o3k-store/migrations/ (computed independently so a future
  # migration does not silently break this assertion).
  EXPECTED_SCHEMA_VERSION="$(ls "$ROOT_DIR/crates/o3k-store/migrations/"*.sql \
    | sed 's|.*/||' | sed -n 's/^\([0-9][0-9]*\)_.*\.sql$/\1/p' \
    | sort -n | tail -n1 | sed 's/^0*//')"
  [[ -n "$EXPECTED_SCHEMA_VERSION" ]] || { echo "no migrations found" >&2; exit 1; }
  python3 - "$ASSET_DIST/o3k-0.0-installerasset/manifest.json" \
    "$EXPECTED_INSTALLER_SHA256" "$EXPECTED_SCHEMA_VERSION" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
assert manifest.get("installer_asset") == "install.sh", manifest
assert manifest.get("installer_sha256") == sys.argv[2], manifest
assert manifest.get("schema_version") == sys.argv[3], manifest
assert manifest.get("upgrade_from", {}).get("min_version") == "0.0.1-prev", manifest
PY
  echo "install.sh release asset contract passed (byte-identity + manifest installer_sha256 + schema_version + upgrade_from.min_version)"
else
  echo "skipping install.sh asset build assertions: source tree is not clean"
fi

echo "release bundle installer test passed"
