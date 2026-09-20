#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The DAC identity checks below execute as the packaged service accounts.  A
# root-owned 0750 /tmp (common on hardened hosts) would make those checks fail
# before the fixture's ownership policy is exercised.  Use the world-
# traversable temporary root by default, with an explicit override for CI.
PACKAGING_TEST_ROOT="${O3K_PACKAGING_TEST_ROOT:-/var/tmp}"
WORK_DIR="$(mktemp -d "${PACKAGING_TEST_ROOT%/}/o3k-packaging.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
BINARY="${O3K_PACKAGING_BINARY:-${ROOT_DIR}/target/debug/o3kd}"
if [[ ! -x "$BINARY" ]]; then
  cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --bin o3kd >/dev/null
fi
[[ -x "$BINARY" ]] || { echo "packaging test binary is missing: $BINARY" >&2; exit 2; }
# The installer's repo-tree fallback would build o3k in release mode inside
# every install run; prebuild once and pass --o3k-binary so this test stays
# deterministic and fast (the fallback itself remains the dev-install path).
O3K_BINARY="${O3K_PACKAGING_O3K_BINARY:-${ROOT_DIR}/target/release/o3k}"
if [[ ! -x "$O3K_BINARY" ]]; then
  cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --bin o3k >/dev/null
fi
[[ -x "$O3K_BINARY" ]] || { echo "packaging o3k test binary is missing: $O3K_BINARY" >&2; exit 2; }

# Disk-space evidence is a safety precondition, not an optional diagnostic.
# A command that exits successfully without producing a parseable df row must
# fail closed instead of allowing installation to continue.
mkdir -p "$WORK_DIR/fake-preflight-bin"
cat >"$WORK_DIR/fake-preflight-bin/df" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$WORK_DIR/fake-preflight-bin/df"
if PATH="$WORK_DIR/fake-preflight-bin:/usr/bin:/bin" \
  bash "$ROOT_DIR/packaging/preflight.sh" --profile fake; then
  echo "preflight accepted missing disk-space evidence" >&2
  exit 1
fi
mkdir -p "$WORK_DIR/custom-data" "$WORK_DIR/path-preflight-bin"
cat >"$WORK_DIR/path-preflight-bin/df" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${DF_PATH_LOG:?}"
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf '/dev/test 1000000 0 100000 1%% /custom\n'
EOF
chmod +x "$WORK_DIR/path-preflight-bin/df"
if PATH="$WORK_DIR/path-preflight-bin:/usr/bin:/bin" DF_PATH_LOG="$WORK_DIR/df-path.log" \
  bash "$ROOT_DIR/packaging/preflight.sh" --profile fake --data-dir "$WORK_DIR/custom-data/nested"; then
  echo "preflight accepted low space on the configured data filesystem" >&2
  exit 1
fi
grep -Fq -- "$WORK_DIR/custom-data" "$WORK_DIR/df-path.log"

# Invalid installation paths must be rejected before the installer creates a
# partial prefix or state directory.
(cd "$WORK_DIR" && if bash "$ROOT_DIR/packaging/install.sh" \
    --profile fake --noninteractive --binary "$BINARY" \
    --prefix relative-prefix --data-dir "$WORK_DIR/data" \
    --config-dir "$WORK_DIR/config" --log-dir "$WORK_DIR/log"; then
  echo "installer accepted a relative prefix" >&2
  exit 1
fi)
[[ ! -e "$WORK_DIR/relative-prefix" ]]
for dot_path in "$WORK_DIR/./dot-prefix" "$WORK_DIR/../dot-prefix"; do
  if bash "$ROOT_DIR/packaging/install.sh" \
      --profile fake --noninteractive --binary "$BINARY" \
      --prefix "$dot_path" --data-dir "$WORK_DIR/dot-data" \
      --config-dir "$WORK_DIR/dot-config" --log-dir "$WORK_DIR/dot-log"; then
    echo "installer accepted a lexical dot component: $dot_path" >&2
    exit 1
  fi
done
[[ ! -e "$WORK_DIR/dot-prefix" && ! -e "$WORK_DIR/dot-data" && ! -e "$WORK_DIR/dot-config" ]]
mkdir -p "$WORK_DIR/symlink-target"
ln -s "$WORK_DIR/symlink-target" "$WORK_DIR/symlink-data"
if bash "$ROOT_DIR/packaging/install.sh" \
    --profile fake --noninteractive --binary "$BINARY" \
    --prefix "$WORK_DIR/symlink-prefix" --data-dir "$WORK_DIR/symlink-data" \
    --config-dir "$WORK_DIR/symlink-config" --log-dir "$WORK_DIR/symlink-log"; then
  echo "installer accepted a symlink data directory" >&2
  exit 1
fi
[[ ! -e "$WORK_DIR/symlink-prefix" && ! -e "$WORK_DIR/symlink-config" ]]

mkdir -p "$WORK_DIR/symlink-parent-target"
ln -s "$WORK_DIR/symlink-parent-target" "$WORK_DIR/symlink-parent"
if bash "$ROOT_DIR/packaging/install.sh" \
    --profile fake --noninteractive --binary "$BINARY" \
    --prefix "$WORK_DIR/symlink-parent/prefix" --data-dir "$WORK_DIR/symlink-parent/data" \
    --config-dir "$WORK_DIR/symlink-parent/config" --log-dir "$WORK_DIR/symlink-parent/log"; then
  echo "installer accepted a symlink installation path component" >&2
  exit 1
fi
[[ ! -e "$WORK_DIR/symlink-parent-target/prefix" && ! -e "$WORK_DIR/symlink-parent-target/data" ]]

mkdir -p "$WORK_DIR/preexisting"
printf 'keep me\n' >"$WORK_DIR/preexisting/user-data"
if bash "$ROOT_DIR/packaging/install.sh" \
    --profile fake --noninteractive --binary "$BINARY" \
    --prefix "$WORK_DIR/prefix" --data-dir "$WORK_DIR/preexisting" \
    --config-dir "$WORK_DIR/config" --log-dir "$WORK_DIR/log"; then
  echo "installer claimed a populated unowned directory" >&2
  exit 1
fi
[[ -f "$WORK_DIR/preexisting/user-data" ]]

mkdir -p "$WORK_DIR/symlink-bin-target" "$WORK_DIR/symlink-bin-prefix"
ln -s "$WORK_DIR/symlink-bin-target" "$WORK_DIR/symlink-bin-prefix/bin"
if bash "$ROOT_DIR/packaging/install.sh" \
    --profile fake --noninteractive --binary "$BINARY" \
    --prefix "$WORK_DIR/symlink-bin-prefix" --data-dir "$WORK_DIR/symlink-bin-data" \
    --config-dir "$WORK_DIR/symlink-bin-config" --log-dir "$WORK_DIR/symlink-bin-log"; then
  echo "installer accepted a symlinked prefix/bin directory" >&2
  exit 1
fi
[[ -z "$(find "$WORK_DIR/symlink-bin-target" -mindepth 1 -print -quit)" ]]

mkdir -p "$WORK_DIR/foreign-prefix/bin" "$WORK_DIR/foreign-prefix/share/o3k"
printf 'foreign binary\n' >"$WORK_DIR/foreign-prefix/bin/o3kd"
printf 'foreign helper\n' >"$WORK_DIR/foreign-prefix/share/o3k/reset.sh"
if bash "$ROOT_DIR/packaging/install.sh" \
    --profile fake --noninteractive --binary "$BINARY" \
    --prefix "$WORK_DIR/foreign-prefix" --data-dir "$WORK_DIR/foreign-data" \
    --config-dir "$WORK_DIR/foreign-config" --log-dir "$WORK_DIR/foreign-log"; then
  echo "installer overwrote foreign O3K-named files" >&2
  exit 1
fi
grep -Fqx 'foreign binary' "$WORK_DIR/foreign-prefix/bin/o3kd"
grep -Fqx 'foreign helper' "$WORK_DIR/foreign-prefix/share/o3k/reset.sh"

mkdir -p "$WORK_DIR/foreign-uninstall-prefix/bin" "$WORK_DIR/foreign-uninstall-prefix/share/o3k"
printf 'foreign binary\n' >"$WORK_DIR/foreign-uninstall-prefix/bin/o3kd"
if bash "$ROOT_DIR/packaging/uninstall.sh" \
    --prefix "$WORK_DIR/foreign-uninstall-prefix" --data-dir "$WORK_DIR/foreign-uninstall-data" \
    --config-dir "$WORK_DIR/foreign-uninstall-config" --log-dir "$WORK_DIR/foreign-uninstall-log"; then
  echo "uninstall removed files without an ownership manifest" >&2
  exit 1
fi
grep -Fqx 'foreign binary' "$WORK_DIR/foreign-uninstall-prefix/bin/o3kd"

bash "$ROOT_DIR/packaging/install.sh" \
  --profile fake --noninteractive --binary "$BINARY" --o3k-binary "$O3K_BINARY" \
  --prefix "$WORK_DIR/prefix" --data-dir "$WORK_DIR/data" \
  --config-dir "$WORK_DIR/config" --log-dir "$WORK_DIR/log"
grep -Fqx "o3k-installed-v1 prefix=$WORK_DIR/prefix" "$WORK_DIR/prefix/share/o3k/.o3k-installed"
grep -Fqx 'bin/o3kd' "$WORK_DIR/prefix/share/o3k/.o3k-installed"
grep -Fqx 'bin/o3k' "$WORK_DIR/prefix/share/o3k/.o3k-installed"
[[ -x "$WORK_DIR/prefix/bin/o3k" ]]
# Repo-tree installs have no release bundle: the bundle-root provenance files
# (manifest.json, SHA256SUMS) are bundle-only and must not be invented here.
! grep -Fqx 'share/o3k/release-manifest.json' "$WORK_DIR/prefix/share/o3k/.o3k-installed"
! grep -Fqx 'share/o3k/SHA256SUMS' "$WORK_DIR/prefix/share/o3k/.o3k-installed"
[[ ! -e "$WORK_DIR/prefix/share/o3k/release-manifest.json" && ! -e "$WORK_DIR/prefix/share/o3k/SHA256SUMS" ]]
# The fake profile keeps the configuration default: the generated daemon env
# must not override O3K_PROVIDER (config default `fake`,
# crates/o3k-config/src/lib.rs).
if grep -q '^O3K_PROVIDER=' "$WORK_DIR/config/o3kd.env"; then
  echo "fake-profile env unexpectedly overrides O3K_PROVIDER" >&2
  exit 1
fi

# Uninstall must apply the same path boundary as install. A dot component
# resolving to the installed prefix must be rejected before any helper or
# binary is removed.
if bash "$ROOT_DIR/packaging/uninstall.sh" \
    --prefix "$WORK_DIR/./prefix" --data-dir "$WORK_DIR/data" \
    --config-dir "$WORK_DIR/config" --log-dir "$WORK_DIR/log"; then
  echo "uninstall accepted a lexical dot component in its prefix" >&2
  exit 1
fi
[[ -x "$WORK_DIR/prefix/bin/o3kd" && -x "$WORK_DIR/prefix/bin/o3k" \
  && -f "$WORK_DIR/prefix/share/o3k/uninstall.sh" ]]

# Purge targets must reject the same lexical path tricks as install targets;
# otherwise ownership checks could be applied to a resolved directory outside
# the requested path.
mkdir -p "$WORK_DIR/purge-target"
ln -s "$WORK_DIR/purge-target" "$WORK_DIR/purge-link"
for unsafe_path in "$WORK_DIR/./purge-target" "$WORK_DIR/purge-link/state"; do
  if bash "$ROOT_DIR/packaging/uninstall.sh" --purge --yes \
      --prefix "$WORK_DIR/prefix" --data-dir "$unsafe_path" \
      --config-dir "$WORK_DIR/purge-config" --log-dir "$WORK_DIR/purge-log"; then
    echo "uninstall accepted an unsafe purge target: $unsafe_path" >&2
    exit 1
  fi
done
[[ -d "$WORK_DIR/purge-target" ]]

mkdir -p "$WORK_DIR/fake-bin"
cat >"$WORK_DIR/fake-bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SYSTEMCTL_LOG"
EOF
chmod +x "$WORK_DIR/fake-bin/systemctl"
PATH="$WORK_DIR/fake-bin:$PATH" SYSTEMCTL_LOG="$WORK_DIR/systemctl.log" \
  bash "$ROOT_DIR/packaging/reset.sh" --yes --data-dir "$WORK_DIR/./data" --log-dir "$WORK_DIR/log" && {
    echo "reset accepted a lexical dot component" >&2
    exit 1
  }
[[ ! -e "$WORK_DIR/systemctl.log" ]]
mkdir -p "$WORK_DIR/reset-parent-target" "$WORK_DIR/reset-final-target"
ln -s "$WORK_DIR/reset-parent-target" "$WORK_DIR/reset-parent"
ln -s "$WORK_DIR/reset-final-target" "$WORK_DIR/reset-final"
for unsafe_reset_path in "$WORK_DIR/reset-parent/data" "$WORK_DIR/reset-final"; do
  if PATH="$WORK_DIR/fake-bin:$PATH" SYSTEMCTL_LOG="$WORK_DIR/systemctl.log" \
      bash "$ROOT_DIR/packaging/reset.sh" --yes --data-dir "$unsafe_reset_path" --log-dir "$WORK_DIR/log"; then
    echo "reset accepted an unsafe path: $unsafe_reset_path" >&2
    exit 1
  fi
  [[ ! -e "$WORK_DIR/systemctl.log" ]]
done
PATH="$WORK_DIR/fake-bin:$PATH" SYSTEMCTL_LOG="$WORK_DIR/systemctl.log" \
  bash "$ROOT_DIR/packaging/reset.sh" --yes --data-dir "$WORK_DIR/data" --log-dir "$WORK_DIR/log"
printf 'foreign reset state\n' >"$WORK_DIR/data/foreign-canary"
if PATH="$WORK_DIR/fake-bin:$PATH" SYSTEMCTL_LOG="$WORK_DIR/systemctl.log" \
    bash "$ROOT_DIR/packaging/reset.sh" --yes --data-dir "$WORK_DIR/data" --log-dir "$WORK_DIR/log"; then
  echo "reset accepted unclassified foreign state" >&2
  exit 1
fi
[[ -f "$WORK_DIR/data/foreign-canary" ]]
rm -f -- "$WORK_DIR/data/foreign-canary"
grep -Fqx 'stop o3k-compute.service' "$WORK_DIR/systemctl.log"
grep -Fqx 'stop o3kd.service' "$WORK_DIR/systemctl.log"
[[ -f "$WORK_DIR/data/.o3k-owned" && -f "$WORK_DIR/log/.o3k-owned" ]]

# A custom-prefix/release-bundle uninstall must not operate on the host's
# systemd units. The rm sentinel fails if either unrelated unit is targeted;
# this keeps the assertion deterministic without creating files under /etc.
cat >"$WORK_DIR/fake-bin/rm" <<'EOF'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    /etc/systemd/system/o3kd.service|/etc/systemd/system/o3k-compute.service)
      echo "unrelated system unit targeted: $arg" >&2
      exit 97
      ;;
  esac
done
exec /bin/rm "$@"
EOF
chmod +x "$WORK_DIR/fake-bin/rm"
: >"$WORK_DIR/systemctl.log"

printf '%s\n' 'foreign helper' >"$WORK_DIR/prefix/share/o3k/foreign-helper.sh"
PATH="$WORK_DIR/fake-bin:$PATH" SYSTEMCTL_LOG="$WORK_DIR/systemctl.log" \
  bash "$WORK_DIR/prefix/share/o3k/uninstall.sh" \
  --prefix "$WORK_DIR/prefix" --data-dir "$WORK_DIR/data" \
  --config-dir "$WORK_DIR/config" --log-dir "$WORK_DIR/log"
for file in o3kd.service o3k-compute.service reset.sh uninstall.sh diagnose.sh preflight.sh bootstrap-certs.sh; do
  [[ ! -e "$WORK_DIR/prefix/share/o3k/$file" ]] || { echo "uninstall left helper file: $file" >&2; exit 1; }
done
[[ ! -e "$WORK_DIR/prefix/bin/o3kd" && ! -e "$WORK_DIR/prefix/bin/o3k" \
  && ! -e "$WORK_DIR/prefix/bin/o3k-compute" ]]
[[ -f "$WORK_DIR/prefix/share/o3k/foreign-helper.sh" ]]
[[ -f "$WORK_DIR/data/.o3k-owned" && -f "$WORK_DIR/config/o3kd.env" && -f "$WORK_DIR/log/.o3k-owned" ]]
[[ ! -s "$WORK_DIR/systemctl.log" ]]

# Keep the destructive precondition ahead of any default-layout service
# mutation. This source-order assertion is portable and does not require
# creating foreign directories under /var/lib or /etc on the test host.
ownership_line="$(grep -n 'refusing purge of unowned path' "$ROOT_DIR/packaging/uninstall.sh" | head -n1 | cut -d: -f1)"
systemd_line="$(grep -n 'systemctl disable --now o3kd.service' "$ROOT_DIR/packaging/uninstall.sh" | head -n1 | cut -d: -f1)"
[[ -n "$ownership_line" && -n "$systemd_line" && "$ownership_line" -lt "$systemd_line" ]]

bash "$ROOT_DIR/packaging/install.sh" \
  --profile fake --noninteractive --binary "$BINARY" --o3k-binary "$O3K_BINARY" \
  --prefix "$WORK_DIR/purge-prefix" --data-dir "$WORK_DIR/purge-data" \
  --config-dir "$WORK_DIR/purge-config" --log-dir "$WORK_DIR/purge-log"
printf 'foreign state\n' >"$WORK_DIR/purge-data/foreign-canary"
if bash "$ROOT_DIR/packaging/uninstall.sh" --purge --yes \
  --prefix "$WORK_DIR/purge-prefix" --data-dir "$WORK_DIR/purge-data" \
  --config-dir "$WORK_DIR/purge-config" --log-dir "$WORK_DIR/purge-log"; then
  echo "purge removed or accepted unclassified foreign state" >&2
  exit 1
fi
[[ -f "$WORK_DIR/purge-data/foreign-canary" ]]
rm -f -- "$WORK_DIR/purge-data/foreign-canary"
# A same-path replacement of generated configuration is foreign state. Purge
# must preserve it even though the surrounding config directory is O3K-owned.
printf 'foreign configuration replacement\n' >"$WORK_DIR/purge-config/o3kd.env"
if bash "$ROOT_DIR/packaging/uninstall.sh" --purge --yes \
  --prefix "$WORK_DIR/purge-prefix" --data-dir "$WORK_DIR/purge-data" \
  --config-dir "$WORK_DIR/purge-config" --log-dir "$WORK_DIR/purge-log"; then
  echo "purge removed or accepted a replaced foreign config file" >&2
  exit 1
fi
[[ -f "$WORK_DIR/purge-config/o3kd.env" ]]
rm -f -- "$WORK_DIR/purge-config/o3kd.env"
bash "$ROOT_DIR/packaging/uninstall.sh" --purge --yes \
  --prefix "$WORK_DIR/purge-prefix" --data-dir "$WORK_DIR/purge-data" \
  --config-dir "$WORK_DIR/purge-config" --log-dir "$WORK_DIR/purge-log"
[[ ! -e "$WORK_DIR/purge-data" && ! -e "$WORK_DIR/purge-config" && ! -e "$WORK_DIR/purge-log" ]]

mkdir -p "$WORK_DIR/foreign-cert-target"
ln -s "$WORK_DIR/foreign-cert-target" "$WORK_DIR/foreign-cert-link"
if bash "$ROOT_DIR/packaging/bootstrap-certs.sh" --output-dir "$WORK_DIR/foreign-cert-link/tls" \
    --server-name o3k-control-plane --agent-id compute-agent; then
  echo "certificate bootstrap followed a symlinked output path" >&2
  exit 1
fi
[[ -z "$(find "$WORK_DIR/foreign-cert-target" -mindepth 1 -print -quit)" ]]

TLS_DIR="$WORK_DIR/certs-root/tls"
bash "$ROOT_DIR/packaging/bootstrap-certs.sh" \
  --output-dir "$TLS_DIR" --server-name o3k-control-plane --agent-id compute-agent
for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem agent-id agent-fingerprint; do
  [[ -s "$TLS_DIR/$file" ]] || { echo "missing generated TLS file: $file" >&2; exit 1; }
done
openssl x509 -in "$TLS_DIR/server.pem" -noout -checkend 0
openssl x509 -in "$TLS_DIR/agent.pem" -noout -checkend 0
grep -q 'DNS:o3k-control-plane' <(openssl x509 -in "$TLS_DIR/server.pem" -noout -text)
grep -q 'URI:urn:o3k:compute:agent:compute-agent' <(openssl x509 -in "$TLS_DIR/agent.pem" -noout -text)
[[ "$(wc -c <"$TLS_DIR/agent-fingerprint")" -ge 64 ]]

EXTRA_TLS_DIR="$WORK_DIR/certs-extra/tls"
printf 'block-a\nblock-b\n' >"$WORK_DIR/extra-agent-ids"
bash "$ROOT_DIR/packaging/bootstrap-certs.sh" \
  --output-dir "$EXTRA_TLS_DIR" --server-name o3k-control-plane --agent-id compute-agent \
  --extra-agent-ids-file "$WORK_DIR/extra-agent-ids"
for extra_id in block-a block-b; do
  for file in agent.pem agent-key.pem agent-id agent-fingerprint; do
    [[ -s "$EXTRA_TLS_DIR/agents/$extra_id/$file" ]] \
      || { echo "missing generated extra TLS file: $extra_id/$file" >&2; exit 1; }
  done
  grep -q "URI:urn:o3k:compute:agent:$extra_id" \
    <(openssl x509 -in "$EXTRA_TLS_DIR/agents/$extra_id/agent.pem" -noout -text)
done
echo block-a >"$WORK_DIR/duplicate-extra-agent-ids"
echo block-a >>"$WORK_DIR/duplicate-extra-agent-ids"
if bash "$ROOT_DIR/packaging/bootstrap-certs.sh" \
    --output-dir "$WORK_DIR/certs-duplicate/tls" --server-name o3k-control-plane --agent-id compute-agent \
    --extra-agent-ids-file "$WORK_DIR/duplicate-extra-agent-ids"; then
  echo "certificate bootstrap accepted duplicate extra agent ids" >&2
  exit 1
fi

# The packaged real-libvirt profile runs the local agent provider
# (O3K_PROVIDER=agent, driven by o3k-compute.service): ADR-0086
# (docs/adr/ADR-0086-libvirt-profile-fail-closed.md) blocks the direct libvirt
# provider at daemon startup (ConfigError::DirectLibvirtProviderUnavailable),
# so install.sh must select the agent provider and never write
# O3K_PROVIDER=libvirt into the daemon env.
if ! grep -Fq '"O3K_PROVIDER=agent"' "$ROOT_DIR/packaging/install.sh"; then
  echo "install.sh libvirt profile does not select the agent provider" >&2
  exit 1
fi
if grep -Fq '"O3K_PROVIDER=libvirt"' "$ROOT_DIR/packaging/install.sh"; then
  echo "install.sh still writes the startup-blocked direct-libvirt provider" >&2
  exit 1
fi
# The daemon unit must not hardcode --listen-addr: it would override
# O3K_LISTEN_ADDR from /etc/o3k/o3kd.env and can conflict with other local
# services (the packaged libvirt profile sets 127.0.0.1:18080 in the env).
if grep -Fq -- '--listen-addr' "$ROOT_DIR/packaging/o3kd.service"; then
  echo "o3kd.service hardcodes --listen-addr" >&2
  exit 1
fi
if ! grep -Fq $'User=o3k-compute' "$ROOT_DIR/packaging/o3k-compute.service" || ! grep -Fq '/var/lib/o3k/compute' "$ROOT_DIR/packaging/o3k-compute.service"; then
  echo "compute service does not use a separate identity and state root" >&2
  exit 1
fi
if [[ "$(grep -Fc 'SupplementaryGroups=' "$ROOT_DIR/packaging/o3k-compute.service")" -ne 1 ]] || ! grep -Fq 'SupplementaryGroups=libvirt kvm' "$ROOT_DIR/packaging/o3k-compute.service"; then
  echo "compute service has an ambiguous or incomplete supplementary group boundary" >&2
  exit 1
fi
if ! grep -Fq 'refusing to reuse o3k account with host-execution groups' "$ROOT_DIR/packaging/install.sh"; then
  echo "installer does not reject unsafe reuse of a privileged control account" >&2
  exit 1
fi
if ! grep -Fq 'refusing to reuse o3k-compute account with unexpected group' "$ROOT_DIR/packaging/install.sh"; then
  echo "installer does not reject unexpected compute-account groups" >&2
  exit 1
fi
# The control-plane o3k account and separate o3k-compute account read the TLS
# material at runtime; install.sh makes the non-secret directory traversal
# explicit while keeping env files root-owned 0600. Private keys must be
# separately scoped to their service identities.
if ! grep -Fq 'chgrp root "$CONFIG_DIR"' "$ROOT_DIR/packaging/install.sh"; then
  echo "install.sh does not establish root ownership for config traversal" >&2
  exit 1
fi
if ! grep -Fq 'chmod 0755 "$CONFIG_DIR"' "$ROOT_DIR/packaging/install.sh" \
  || ! grep -Fq 'chgrp o3k-compute "$TLS_DIR/$file"' "$ROOT_DIR/packaging/install.sh" \
  || ! grep -Fq 'chgrp o3k "$TLS_DIR/$file"' "$ROOT_DIR/packaging/install.sh"; then
  echo "install.sh does not enforce split TLS private-key ownership" >&2
  exit 1
fi
# ADR-0146 (docs/adr/ADR-0146-agent-inventory-publication.md): the compute
# agent publishes Placement DISK_GB capacity from the operator's
# O3K_COMPUTE_MAX_DISK_GB declaration and defaults to 0 (the provider is
# Unavailable, every create 409s) when unset; the packaged libvirt install
# must declare the capacity so a clean install can schedule the E2E flavor
# (--disk 10), and must preserve an operator-pre-set value.
if ! grep -Fq 'O3K_COMPUTE_MAX_DISK_GB=30' "$ROOT_DIR/packaging/install.sh"; then
  echo "install.sh does not declare compute-agent disk capacity" >&2
  exit 1
fi
if ! grep -Fq '^O3K_COMPUTE_MAX_DISK_GB=' "$ROOT_DIR/packaging/install.sh"; then
  echo "install.sh does not preserve an operator-pre-set capacity value" >&2
  exit 1
fi
# Defect 6 (issue #90, clean Debian 12): libvirtd defaults to
# auth_unix_rw = "polkit" and org.libvirt.unix.manage requires
# auth_admin_keep, which the session-less o3k service account cannot satisfy
# (no polkit agent available) — the agent publishes zeroed capabilities and
# every create 409s. The packaged install must apply the policykit-1 rule
# granting ONLY user o3k the manage action (inert on hosts with an active
# auth_unix_rw = "none", e.g. Ubuntu 24.04).
if ! grep -Fq 'install_owned_system_file "$ROOT_DIR/packaging/50-o3k-libvirt.rules"' "$ROOT_DIR/packaging/install.sh" \
  || ! grep -Fq '/etc/polkit-1/rules.d/50-o3k-libvirt.rules 0644' "$ROOT_DIR/packaging/install.sh"; then
  echo "install.sh does not apply the libvirt polkit rule" >&2
  exit 1
fi
if ! grep -Fq 'org.libvirt.unix.manage" && subject.user === "o3k-compute"' "$ROOT_DIR/packaging/50-o3k-libvirt.rules"; then
  echo "packaged polkit rule does not grant org.libvirt.unix.manage to o3k-compute" >&2
  exit 1
fi
if grep -Fq 'rm -f -- /etc/systemd/system/o3kd.service' "$ROOT_DIR/packaging/uninstall.sh" \
  || grep -Fq 'rm -f -- /etc/polkit-1/rules.d/50-o3k-libvirt.rules' "$ROOT_DIR/packaging/uninstall.sh" \
  || ! grep -Fq 'remove_owned_system_file' "$ROOT_DIR/packaging/uninstall.sh"; then
  echo "uninstall does not content-fence fixed system files" >&2
  exit 1
fi
purge_inspection_line="$(grep -n 'assert_no_owned_host_state || exit 2' "$ROOT_DIR/packaging/uninstall.sh" | head -n1 | cut -d: -f1)"
purge_systemd_line="$(grep -n 'systemctl disable --now o3kd.service' "$ROOT_DIR/packaging/uninstall.sh" | head -n1 | cut -d: -f1)"
[[ -n "$purge_inspection_line" && -n "$purge_systemd_line" && "$purge_inspection_line" -lt "$purge_systemd_line" ]] \
  || { echo "purge does not inspect host state before service mutation" >&2; exit 1; }
for required_guard in 'refusing purge while O3K-owned libvirt domain exists' \
  'refusing purge while O3K-owned network link exists' \
  'refusing purge while O3K DHCP process exists'; do
  grep -Fq "$required_guard" "$ROOT_DIR/packaging/uninstall.sh" \
    || { echo "purge host-state guard is missing: $required_guard" >&2; exit 1; }
done

# The libvirt profile must not share private keys between the control-plane
# and host-execution identities. This is an executable DAC regression rather
# than a source-shape assertion: the compute account must be denied the
# server key, and o3kd must be denied the agent key.
if [[ "$EUID" -eq 0 ]] && id o3k >/dev/null 2>&1 && id o3k-compute >/dev/null 2>&1 \
  && command -v setpriv >/dev/null 2>&1; then
  chgrp o3k "$WORK_DIR"
  chmod 0755 "$WORK_DIR"
  tls_boundary="$WORK_DIR/tls-boundary"
  install -d -o root -g root -m 0755 "$tls_boundary"
  printf 'server-private-sentinel\n' >"$tls_boundary/server-key.pem"
  printf 'agent-private-sentinel\n' >"$tls_boundary/agent-key.pem"
  chown root:o3k "$tls_boundary/server-key.pem"
  chmod 0640 "$tls_boundary/server-key.pem"
  chown root:o3k-compute "$tls_boundary/agent-key.pem"
  chmod 0640 "$tls_boundary/agent-key.pem"
  if setpriv --reuid="$(id -u o3k-compute)" --regid="$(id -g o3k-compute)" \
      --clear-groups -- cat "$tls_boundary/server-key.pem" >/dev/null 2>&1; then
    echo "compute identity can read the control-plane private key" >&2
    exit 1
  fi
  if setpriv --reuid="$(id -u o3k)" --regid="$(id -g o3k)" \
      --clear-groups -- cat "$tls_boundary/agent-key.pem" >/dev/null 2>&1; then
    echo "control-plane identity can read the compute private key" >&2
    exit 1
  fi
  setpriv --reuid="$(id -u o3k)" --regid="$(id -g o3k)" \
    --clear-groups -- cat "$tls_boundary/server-key.pem" >/dev/null 2>&1 \
    || { echo "control-plane identity cannot read its server private key" >&2; exit 1; }
  setpriv --reuid="$(id -u o3k-compute)" --regid="$(id -g o3k-compute)" \
    --clear-groups -- cat "$tls_boundary/agent-key.pem" >/dev/null 2>&1 \
    || { echo "compute identity cannot read its agent private key" >&2; exit 1; }
fi
echo "packaging safety tests passed"
