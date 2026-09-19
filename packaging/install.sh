#!/usr/bin/env bash
set -Eeuo pipefail
PREFIX=/usr/local
DATA_DIR=/var/lib/o3k
CONFIG_DIR=/etc/o3k
LOG_DIR=/var/log/o3k
BINARY=
COMPUTE_BINARY=
O3K_BINARY=
NETWORK_BINARY=
PROFILE=fake
NONINTERACTIVE=0
# Canonical-bootstrap orchestration (PP.2, contracts/installer-v1.yaml
# invoke_canonical_init_join): the outer installer runs `o3k init` and the
# authenticated `o3k join` BEFORE the compute agent's first control-plane
# registration (the NodeRegistry epoch lease fences a live agent's
# replacement; join must win the race). With this flag the unit is enabled
# but not started; the outer installer starts it after canonical join.
DEFER_COMPUTE_START=0
while (($#)); do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --data-dir) DATA_DIR="$2"; shift 2;;
    --config-dir) CONFIG_DIR="$2"; shift 2;;
    --log-dir) LOG_DIR="$2"; shift 2;;
    --binary) BINARY="$2"; shift 2;;
    --compute-binary) COMPUTE_BINARY="$2"; shift 2;;
    --o3k-binary) O3K_BINARY="$2"; shift 2;;
    --network-binary) NETWORK_BINARY="$2"; shift 2;;
    --profile) PROFILE="$2"; shift 2;;
    --noninteractive) NONINTERACTIVE=1; shift;;
    --defer-compute-start) DEFER_COMPUTE_START=1; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[[ "$PROFILE" == fake || "$PROFILE" == libvirt ]] || { echo "profile must be fake or libvirt" >&2; exit 2; }
if [[ -n "$NETWORK_BINARY" && "$PROFILE" != libvirt ]]; then
  echo "the network agent is only installed with the libvirt profile" >&2
  exit 2
fi
[[ -n "$PREFIX" && -n "$DATA_DIR" && -n "$CONFIG_DIR" && -n "$LOG_DIR" ]] || { echo "installation paths must not be empty" >&2; exit 2; }
validate_install_path() {
  local name="$1" path="$2"
  [[ "$path" == /* && "$path" != / ]] || {
    echo "$name must be an absolute non-root path: $path" >&2
    exit 2
  }
  local current=/ component
  while IFS= read -r component; do
    [[ -n "$component" ]] || continue
    case "$component" in
      .|..)
        echo "$name must not contain lexical dot components: $path" >&2
        exit 2
        ;;
    esac
    current="$current/$component"
    if [[ -L "$current" ]]; then
      echo "refusing symlink installation path for $name: $path" >&2
      exit 2
    fi
  done < <(tr '/' '\n' <<< "${path#/}")
  if [[ -e "$path" && ! -d "$path" ]]; then
    echo "installation path for $name is not a directory: $path" >&2
    exit 2
  fi
}
validate_install_path prefix "$PREFIX"
validate_install_path data-dir "$DATA_DIR"
validate_install_path config-dir "$CONFIG_DIR"
validate_install_path log-dir "$LOG_DIR"
SYSTEM_INSTALL=0
if [[ "$PREFIX" == /usr/local && "$DATA_DIR" == /var/lib/o3k && "$CONFIG_DIR" == /etc/o3k && "$LOG_DIR" == /var/log/o3k ]]; then SYSTEM_INSTALL=1; fi
if [[ $EUID -ne 0 && ( "$PREFIX" == /usr/* || "$DATA_DIR" == /var/* || "$CONFIG_DIR" == /etc/* ) ]]; then echo "system paths require root; use sudo or explicit user paths" >&2; exit 2; fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Release-bundle detection: a release bundle carries manifest.json and
# SHA256SUMS at its root (packaging/make-release.sh). Inside a release bundle
# the installer must NEVER compile on the target host: a missing required
# prebuilt binary fails closed (contracts/installer-v1.yaml
# no_target_compilation). Repo-tree/dev installs keep the cargo fallback.
RELEASE_BUNDLE=0
if [[ -f "$ROOT_DIR/manifest.json" && -f "$ROOT_DIR/SHA256SUMS" ]]; then
  RELEASE_BUNDLE=1
fi
bundle_missing_binary() {
  echo "release bundle is missing required prebuilt binary: $1" >&2
  echo "refusing to compile O3K on the installation target (contracts/installer-v1.yaml no_target_compilation)" >&2
  exit 1
}
if [[ "$PROFILE" == libvirt ]]; then "$ROOT_DIR/packaging/preflight.sh" --profile libvirt --data-dir "$DATA_DIR"; fi
if [[ -z "$BINARY" ]]; then
  if [[ -x "$ROOT_DIR/bin/o3kd" ]]; then
    BINARY="$ROOT_DIR/bin/o3kd"
  else
    if [[ "$RELEASE_BUNDLE" == 1 ]]; then
      bundle_missing_binary "$ROOT_DIR/bin/o3kd (o3kd)"
    fi
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --bin o3kd
    BINARY="$ROOT_DIR/target/release/o3kd"
  fi
fi
[[ -x "$BINARY" ]] || { echo "binary is not executable: $BINARY" >&2; exit 1; }
if [[ "$PROFILE" == libvirt && -z "$COMPUTE_BINARY" ]]; then
  if [[ -x "$ROOT_DIR/bin/o3k-compute" ]]; then
    COMPUTE_BINARY="$ROOT_DIR/bin/o3k-compute"
  else
    # The cargo bin target is `o3k-compute-bin` (bins/o3k-compute package);
    # its `libvirt` feature gates the libvirt backend
    # (bins/o3k-compute/Cargo.toml).
    if [[ "$RELEASE_BUNDLE" == 1 ]]; then
      bundle_missing_binary "$ROOT_DIR/bin/o3k-compute (o3k-compute)"
    fi
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --features libvirt --bin o3k-compute-bin
    COMPUTE_BINARY="$ROOT_DIR/target/release/o3k-compute-bin"
  fi
fi
if [[ "$PROFILE" == libvirt ]]; then [[ -x "$COMPUTE_BINARY" ]] || { echo "compute binary is not executable: $COMPUTE_BINARY" >&2; exit 1; }; fi
# o3k doctor is profile-independent: installed in every profile (issue #617).
# The release bundle carries bin/o3k next to bin/o3kd; repo-tree/dev installs
# build it from the workspace unless the caller supplies --o3k-binary (used by
# tests to avoid in-script release builds). In a release bundle a missing
# bin/o3k fails closed instead of compiling.
if [[ -z "$O3K_BINARY" ]]; then
  if [[ -x "$ROOT_DIR/bin/o3k" ]]; then
    O3K_BINARY="$ROOT_DIR/bin/o3k"
  else
    if [[ "$RELEASE_BUNDLE" == 1 ]]; then
      bundle_missing_binary "$ROOT_DIR/bin/o3k (o3k)"
    fi
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml" --bin o3k
    O3K_BINARY="$ROOT_DIR/target/release/o3k"
  fi
fi
[[ -x "$O3K_BINARY" ]] || { echo "o3k binary is not executable: $O3K_BINARY" >&2; exit 1; }
# Optional o3k-network execution agent (o3k-small-edge-v1 network boundary):
# shipped in libvirt-profile release bundles from PP.1 onward. It is installed
# together with its systemd unit but never enabled here — small-edge
# orchestration enrolls it through the canonical init/join path. Optional
# everywhere and never compiled on the target host.
if [[ "$PROFILE" == libvirt && -z "$NETWORK_BINARY" && -x "$ROOT_DIR/bin/o3k-network" ]]; then
  NETWORK_BINARY="$ROOT_DIR/bin/o3k-network"
fi
if [[ -n "$NETWORK_BINARY" ]]; then
  [[ -x "$NETWORK_BINARY" ]] || { echo "network binary is not executable: $NETWORK_BINARY" >&2; exit 1; }
fi
TLS_DIR="$CONFIG_DIR/tls"
if [[ "$PROFILE" == libvirt ]]; then
  [[ -d "$TLS_DIR" && ! -L "$TLS_DIR" ]] || { echo "libvirt TLS directory is missing or unsafe: $TLS_DIR" >&2; exit 2; }
  for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem agent-id agent-fingerprint; do
    [[ -f "$TLS_DIR/$file" && ! -L "$TLS_DIR/$file" && -s "$TLS_DIR/$file" ]] || {
      echo "libvirt TLS bootstrap is incomplete: $TLS_DIR/$file" >&2
      exit 2
    }
  done
  FINGERPRINT="$(<"$TLS_DIR/agent-fingerprint")"
  [[ "$FINGERPRINT" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "agent fingerprint is invalid" >&2; exit 2; }
fi
if [[ $EUID -eq 0 ]]; then
  getent group o3k >/dev/null || groupadd --system o3k
  if id o3k >/dev/null 2>&1; then
    control_record="$(getent passwd o3k || true)"
    [[ "$control_record" == *":/var/lib/o3k:/usr/sbin/nologin" ]] || {
      echo "refusing to reuse an unrelated o3k account" >&2
      exit 2
    }
    if [[ "$PROFILE" == libvirt ]]; then
      while read -r group; do
        [[ -z "$group" || "$group" == o3k ]] || {
          echo "refusing to reuse o3k account with unexpected group: $group" >&2
          exit 2
        }
      done < <(id -nG o3k | tr ' ' '\n')
    fi
  else
    useradd --system --gid o3k --home-dir /var/lib/o3k --shell /usr/sbin/nologin o3k
  fi
  if [[ "$PROFILE" == libvirt ]]; then
    if id -nG o3k | tr ' ' '\n' | grep -Eq '^(libvirt|kvm)$'; then
      echo "refusing to reuse o3k account with host-execution groups" >&2
      exit 2
    fi
    getent group o3k-compute >/dev/null || groupadd --system o3k-compute
    if id o3k-compute >/dev/null 2>&1; then
      compute_record="$(getent passwd o3k-compute || true)"
      [[ "$compute_record" == *":/var/lib/o3k/compute:/usr/sbin/nologin" ]] || {
        echo "refusing to reuse an unrelated o3k-compute account" >&2
        exit 2
      }
      while read -r group; do
        case "$group" in
          ""|o3k-compute|libvirt|kvm) ;;
          *)
            echo "refusing to reuse o3k-compute account with unexpected group: $group" >&2
            exit 2
            ;;
        esac
      done < <(id -nG o3k-compute | tr ' ' '\n')
    else
      useradd --system --gid o3k-compute --home-dir /var/lib/o3k/compute --shell /usr/sbin/nologin o3k-compute
    fi
  fi
  if [[ -n "$NETWORK_BINARY" ]]; then
    getent group o3k-network >/dev/null || groupadd --system o3k-network
    if id o3k-network >/dev/null 2>&1; then
      network_record="$(getent passwd o3k-network || true)"
      [[ "$network_record" == *":/var/lib/o3k/network:/usr/sbin/nologin" ]] || {
        echo "refusing to reuse an unrelated o3k-network account" >&2
        exit 2
      }
      while read -r group; do
        case "$group" in
          ""|o3k-network) ;;
          *)
            echo "refusing to reuse o3k-network account with unexpected group: $group" >&2
            exit 2
            ;;
        esac
      done < <(id -nG o3k-network | tr ' ' '\n')
    else
      useradd --system --gid o3k-network --home-dir /var/lib/o3k/network --shell /usr/sbin/nologin o3k-network
    fi
  fi
  RUN_USER=o3k
else RUN_USER="$(id -un)"; fi

mark_owned_dir() {
  local path="$1" marker="$1/.o3k-owned"
  if [[ -e "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || { echo "refusing non-directory install path: $path" >&2; exit 2; }
    if [[ -e "$marker" ]]; then
      [[ -f "$marker" && ! -L "$marker" ]] || { echo "refusing invalid ownership marker: $marker" >&2; exit 2; }
      grep -Fqx "o3k-owned-v1 path=$path" "$marker" || { echo "refusing unrecognized ownership marker: $marker" >&2; exit 2; }
    elif [[ -n "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      echo "refusing to claim populated unowned directory: $path" >&2
      exit 2
    else
      printf 'o3k-owned-v1 path=%s\n' "$path" >"$marker"
    fi
  else
    install -d -m 0755 "$path"
    printf 'o3k-owned-v1 path=%s\n' "$path" >"$marker"
  fi
  chmod 0644 "$marker"
}

for path in "$PREFIX/bin" "$PREFIX/share" "$PREFIX/share/o3k"; do
  if [[ -L "$path" ]]; then
    echo "refusing symlink installation path: $path" >&2
    exit 2
  fi
  if [[ -e "$path" && ! -d "$path" ]]; then
    echo "installation child path is not a directory: $path" >&2
    exit 2
  fi
done
install -d -m 0755 "$PREFIX/bin" "$PREFIX/share/o3k"
INSTALL_MANIFEST="$PREFIX/share/o3k/.o3k-installed"
if [[ -L "$INSTALL_MANIFEST" || ( -e "$INSTALL_MANIFEST" && ! -f "$INSTALL_MANIFEST" ) ]]; then
  echo "refusing invalid installation ownership manifest: $INSTALL_MANIFEST" >&2
  exit 2
fi
manifest_owns() {
  [[ -f "$INSTALL_MANIFEST" ]] && grep -Fqx "$1" "$INSTALL_MANIFEST"
}
if [[ -f "$INSTALL_MANIFEST" ]] && ! grep -Fqx "o3k-installed-v1 prefix=$PREFIX" "$INSTALL_MANIFEST"; then
  echo "refusing unrecognized installation ownership manifest: $INSTALL_MANIFEST" >&2
  exit 2
fi
install_owned_file() {
  local source="$1" destination="$2" relative="$3" mode="$4"
  if [[ -L "$destination" ]]; then
    echo "refusing symlink installation target: $destination" >&2
    exit 2
  fi
  if [[ -e "$destination" ]] && ! manifest_owns "$relative"; then
    echo "refusing to overwrite foreign installation file: $destination" >&2
    exit 2
  fi
  install -m "$mode" "$source" "$destination"
}
install_owned_system_file() {
  local source="$1" destination="$2" mode="$3"
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" && -r "$destination" ]] || {
      echo "refusing to overwrite foreign system file: $destination" >&2
      exit 2
    }
    cmp -s "$source" "$destination" || {
      echo "refusing to overwrite foreign system file: $destination" >&2
      exit 2
    }
  fi
  install -m "$mode" "$source" "$destination"
}
COMPUTE_DATA_DIR="$DATA_DIR/compute"
for path in "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"; do mark_owned_dir "$path"; done
if [[ "$PROFILE" == libvirt ]]; then mark_owned_dir "$COMPUTE_DATA_DIR"; fi
INSTALLED_FILES=(
  bin/o3kd
  bin/o3k
  share/o3k/o3kd.service
  share/o3k/reset.sh
  share/o3k/uninstall.sh
  share/o3k/diagnose.sh
  share/o3k/preflight.sh
  share/o3k/bootstrap-certs.sh
  share/o3k/bootstrap-testlab.sh
  share/o3k/generate-passwords.sh
)
install_owned_file "$BINARY" "$PREFIX/bin/o3kd" bin/o3kd 0755
install_owned_file "$O3K_BINARY" "$PREFIX/bin/o3k" bin/o3k 0755
install_owned_file "$ROOT_DIR/packaging/o3kd.service" "$PREFIX/share/o3k/o3kd.service" share/o3k/o3kd.service 0644
for file in reset.sh uninstall.sh diagnose.sh preflight.sh bootstrap-certs.sh bootstrap-testlab.sh; do
  install_owned_file "$ROOT_DIR/packaging/$file" "$PREFIX/share/o3k/$file" "share/o3k/$file" 0755
done
install_owned_file "$ROOT_DIR/scripts/generate-passwords.sh" \
  "$PREFIX/share/o3k/generate-passwords.sh" share/o3k/generate-passwords.sh 0755
# Release-bundle provenance files (issue #617): manifest.json and SHA256SUMS
# sit at the release bundle root (packaging/make-release.sh writes them next
# to bin/) and let `o3k doctor` verify the installed release. Repo-tree/dev
# installs have no release bundle, so the two files are installed and tracked
# in the ownership manifest only when the bundle sources exist.
if [[ -f "$ROOT_DIR/manifest.json" ]]; then
  install_owned_file "$ROOT_DIR/manifest.json" "$PREFIX/share/o3k/release-manifest.json" \
    share/o3k/release-manifest.json 0644
  INSTALLED_FILES+=(share/o3k/release-manifest.json)
fi
if [[ -f "$ROOT_DIR/SHA256SUMS" ]]; then
  install_owned_file "$ROOT_DIR/SHA256SUMS" "$PREFIX/share/o3k/SHA256SUMS" \
    share/o3k/SHA256SUMS 0644
  INSTALLED_FILES+=(share/o3k/SHA256SUMS)
fi
if [[ "$PROFILE" == libvirt ]]; then
  install_owned_file "$COMPUTE_BINARY" "$PREFIX/bin/o3k-compute" bin/o3k-compute 0755
  install_owned_file "$ROOT_DIR/packaging/o3k-compute.service" "$PREFIX/share/o3k/o3k-compute.service" share/o3k/o3k-compute.service 0644
  install_owned_file "$ROOT_DIR/packaging/50-o3k-libvirt.rules" "$PREFIX/share/o3k/50-o3k-libvirt.rules" share/o3k/50-o3k-libvirt.rules 0644
  INSTALLED_FILES+=(bin/o3k-compute share/o3k/o3k-compute.service share/o3k/50-o3k-libvirt.rules)
fi
if [[ "$PROFILE" == libvirt && -n "$NETWORK_BINARY" ]]; then
  install_owned_file "$NETWORK_BINARY" "$PREFIX/bin/o3k-network" bin/o3k-network 0755
  install_owned_file "$ROOT_DIR/packaging/o3k-network.service" "$PREFIX/share/o3k/o3k-network.service" share/o3k/o3k-network.service 0644
  INSTALLED_FILES+=(bin/o3k-network share/o3k/o3k-network.service)
  if [[ $EUID -eq 0 ]]; then
    install -d -o o3k-network -g o3k-network -m 0700 "$DATA_DIR/network"
  fi
fi
MANIFEST_TEMP="$INSTALL_MANIFEST.tmp-$$"
{
  printf 'o3k-installed-v1 prefix=%s\n' "$PREFIX"
  printf '%s\n' "${INSTALLED_FILES[@]}"
} >"$MANIFEST_TEMP"
mv -f -- "$MANIFEST_TEMP" "$INSTALL_MANIFEST"
chmod 0644 "$INSTALL_MANIFEST"
ENV_FILE="$CONFIG_DIR/o3kd.env"
O3K_PASSWORD_FILE="$ENV_FILE" \
  O3K_KOLLA_PASSWORD_FILE="${O3K_KOLLA_PASSWORD_FILE:-/etc/kolla/passwords.yml}" \
  bash "$ROOT_DIR/scripts/generate-passwords.sh" --output "$ENV_FILE"
if ! grep -q '^O3K_DATA_DIR=' "$ENV_FILE"; then
  umask 077
  printf 'O3K_DATA_DIR=%q\n' "$DATA_DIR" >>"$ENV_FILE"
  chmod 0600 "$ENV_FILE"
fi
if [[ "$PROFILE" == libvirt ]]; then
  for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem agent-id agent-fingerprint; do
    [[ -s "$TLS_DIR/$file" ]] || { echo "libvirt TLS bootstrap is incomplete: $TLS_DIR/$file" >&2; exit 2; }
  done
  if [[ $EUID -eq 0 ]]; then
    # bootstrap-certs.sh creates the config dir as root:root 0750. The
    # directory and public certificates are non-secret and readable by both
    # identities; private keys remain
    # separately scoped: o3kd receives only the server key, while
    # o3k-compute receives only the agent key. The shared CA and public
    # certificates are readable by both identities; env files stay root-owned
    # 0600 and are read by systemd as root.
    chgrp root "$CONFIG_DIR"
    chmod 0755 "$CONFIG_DIR"
    chgrp root "$TLS_DIR"
    chmod 0755 "$TLS_DIR"
    for file in ca.pem server.pem server-key.pem; do
      if [[ "$file" == server-key.pem ]]; then
        chgrp o3k "$TLS_DIR/$file"
        chmod 0640 "$TLS_DIR/$file"
      else
        chgrp root "$TLS_DIR/$file"
        chmod 0644 "$TLS_DIR/$file"
      fi
    done
    for file in agent.pem agent-key.pem agent-id agent-fingerprint; do
      if [[ "$file" == agent-key.pem ]]; then
        chgrp o3k-compute "$TLS_DIR/$file"
        chmod 0640 "$TLS_DIR/$file"
      else
        chgrp root "$TLS_DIR/$file"
        chmod 0644 "$TLS_DIR/$file"
      fi
    done
  fi
  if [[ ! -e "$CONFIG_DIR/o3k-compute.env" ]]; then
    umask 077
    printf 'O3K_COMPUTE_DATA_DIR=%q\nO3K_COMPUTE_PROFILE=libvirt\nO3K_COMPUTE_TLS_DIR=%q\n' "$COMPUTE_DATA_DIR" "$TLS_DIR" >"$CONFIG_DIR/o3k-compute.env"
    chmod 0600 "$CONFIG_DIR/o3k-compute.env"
  fi
  # ADR-0146 (docs/adr/ADR-0146-agent-inventory-publication.md): the compute
  # agent publishes Placement disk capacity from the operator's bounded
  # O3K_COMPUTE_MAX_DISK_GB declaration and is intentionally unschedulable
  # (DISK_GB total=0) while it is unset. The packaged install declares 30 GB
  # per host: the bounded o3k-demo-v1 cloud must host the installer's TestLab
  # VM (10 GB flavor) plus at least two user-created VMs — a 10 GB default
  # left the second create unschedulable (Scheduler(NoValidHost), found in the
  # PP.4 campaign). Operators tune per host via docs/CONFIGURATION.md; an
  # operator-pre-set value is preserved.
  if ! grep -q '^O3K_COMPUTE_MAX_DISK_GB=' "$CONFIG_DIR/o3k-compute.env"; then
    umask 077
    printf 'O3K_COMPUTE_MAX_DISK_GB=30\n' >>"$CONFIG_DIR/o3k-compute.env"
    chmod 0600 "$CONFIG_DIR/o3k-compute.env"
  fi
  if [[ $EUID -eq 0 ]]; then
    # Defect 6 (issue #90, clean Debian 12): libvirtd defaults to
    # auth_unix_rw = "polkit" and org.libvirt.unix.manage requires
    # auth_admin_keep, which the session-less o3k service account cannot
    # satisfy (no polkit agent available); the agent then publishes zeroed
    # capabilities and every create 409s. Install a policykit-1 JS rule
    # granting ONLY user o3k the manage action (Debian 12 and Ubuntu 24.04
    # both load /etc/polkit-1/rules.d/*.rules); on hosts with an active
    # auth_unix_rw = "none" (Ubuntu 24.04) polkit is never consulted and the
    # rule is inert. polkitd reloads rules on change; the guarded reload
    # makes it deterministic.
    install -d -m 0755 /etc/polkit-1/rules.d
    install_owned_system_file "$ROOT_DIR/packaging/50-o3k-libvirt.rules" \
      /etc/polkit-1/rules.d/50-o3k-libvirt.rules 0644
    systemctl reload polkitd 2>/dev/null || systemctl reload polkit 2>/dev/null || true
  fi
  # ADR-0086 (docs/adr/ADR-0086-libvirt-profile-fail-closed.md) deliberately
  # blocks the direct libvirt provider at daemon startup
  # (ConfigError::DirectLibvirtProviderUnavailable); the packaged real-libvirt
  # profile therefore runs the agent provider, driven by the local
  # o3k-compute.service over the mTLS control plane bootstrapped above.
  # Listen on 127.0.0.1:18080 like the disposable-testlab path
  # (O3K_LISTEN_ADDR) instead of the default 127.0.0.1:8080; the unit does not
  # hardcode a listen address so this env governs.
  for setting in \
    "O3K_PROVIDER=agent" \
    "O3K_LISTEN_ADDR=127.0.0.1:18080" \
    "O3K_COMPUTE_SERVER_CERTIFICATE=$TLS_DIR/server.pem" \
    "O3K_COMPUTE_SERVER_PRIVATE_KEY=$TLS_DIR/server-key.pem" \
    "O3K_COMPUTE_CLIENT_CA=$TLS_DIR/ca.pem" \
    "O3K_COMPUTE_AUTHORIZED_AGENTS=$(<"$TLS_DIR/agent-id")=$FINGERPRINT"; do
    key="${setting%%=*}"
    grep -q "^${key}=" "$ENV_FILE" || printf '%s\n' "$setting" >>"$ENV_FILE"
  done
  # The compute agent reads its identity from ITS data directory
  # (bins/o3k-compute/src/main.rs: identity_file = data_dir.join("agent-id")),
  # so the identity must be installed there, owned by the compute account —
  # mirroring the disposable-testlab bootstrap. Installing it only under the
  # control data directory leaves the installed agent without an identity and
  # the mTLS registration is always rejected (PermissionDenied). The non-root
  # flow keeps the invoking user's ownership, matching RUN_USER below.
  if [[ $EUID -eq 0 ]]; then
    install -m 0640 -o o3k-compute -g o3k-compute \
      "$TLS_DIR/agent-id" "$COMPUTE_DATA_DIR/agent-id"
  else
    install -m 0640 "$TLS_DIR/agent-id" "$COMPUTE_DATA_DIR/agent-id"
  fi
fi

# Keep a root-owned content ledger for generated configuration and TLS files.
# Purge may remove a file only when its bytes still match the version recorded
# at installation time; operator edits or same-path foreign replacements are
# preserved rather than treated as O3K-owned state.
CONFIG_FILE_LEDGER="$CONFIG_DIR/.o3k-config-files"
config_file_specs=(o3kd.env admin-openrc clouds.yaml)
[[ -e "$CONFIG_DIR/o3kd.env.lock" ]] && config_file_specs+=(o3kd.env.lock)
if [[ "$PROFILE" == libvirt ]]; then
  config_file_specs+=(o3k-compute.env tls/ca.pem tls/server.pem tls/server-key.pem \
    tls/agent.pem tls/agent-key.pem tls/agent-id tls/agent-fingerprint)
fi
if [[ -e "$CONFIG_FILE_LEDGER" ]]; then
  [[ -f "$CONFIG_FILE_LEDGER" && ! -L "$CONFIG_FILE_LEDGER" ]] || {
    echo "refusing invalid configuration ownership ledger: $CONFIG_FILE_LEDGER" >&2
    exit 2
  }
  while IFS=$'\t' read -r marker relative digest extra; do
    [[ -z "${extra:-}" && "$marker" == o3k-config-file-v1 && "$relative" != /* \
      && "$digest" =~ ^[0-9a-f]{64}$ ]] || {
      echo "refusing malformed configuration ownership ledger: $CONFIG_FILE_LEDGER" >&2
      exit 2
    }
    [[ -f "$CONFIG_DIR/$relative" && ! -L "$CONFIG_DIR/$relative" ]] || {
      echo "refusing missing configuration file recorded in ledger: $relative" >&2
      exit 2
    }
    [[ "$(sha256sum "$CONFIG_DIR/$relative" | awk '{print $1}')" == "$digest" ]] || {
      echo "refusing to overwrite operator-modified configuration file: $relative" >&2
      exit 2
    }
  done <"$CONFIG_FILE_LEDGER"
fi

# Client credentials for the public OpenStack CLI (issue #613 §9). Both files
# are derived from the daemon environment on every run; the bootstrap password
# is preserved by generate-passwords.sh, so regeneration never invents a
# second credential source. Identity values mirror the seeded O3K universe
# (crates/o3k-identity/src/lib.rs seed_identity_defaults: user "admin",
# project "admin", domain "Default", region "RegionOne"); the listen address
# follows O3K_LISTEN_ADDR from the env file (libvirt profile:
# 127.0.0.1:18080), falling back to the config default 127.0.0.1:8080
# (crates/o3k-config/src/lib.rs DEFAULT_LISTEN_ADDR).
read_env_scalar() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE" \
    | python3 -c '
import ast, json, shlex, sys
key = sys.argv[1]
value = sys.stdin.read().rstrip("\r\n")
# Guard: packaging/install.sh writes paths with bash %q, which emits ANSI-C
# $'"'"'...'"'"' quoting when a value contains characters outside the safe set. The
# values read here (bootstrap password, listen address) are generated by
# scripts/generate-passwords.sh with a hex/base64-only charset, so $'"'"'...'"'"'
# can never occur today; if it ever does, fail loudly instead of silently
# misparsing an escaped value into a wrong credential or address.
if value.startswith("$'"'"'"):
    raise SystemExit(
        "unsupported ANSI-C quoted value for " + key + ": not a plain scalar"
    )
quote = None
escaped = False
for index, character in enumerate(value):
    if quote == chr(34) and escaped:
        escaped = False
    elif quote == chr(34) and character == chr(92):
        escaped = True
    elif character in (chr(34), chr(39)):
        quote = None if quote == character else character if quote is None else quote
    elif quote is None and character == chr(35) and index > 0 and value[index - 1].isspace():
        value = value[:index].rstrip()
        break
if len(value) >= 2 and value[0] == value[-1] == chr(34):
    value = json.loads(value)
elif len(value) >= 2 and value[0] == value[-1] == chr(39):
    value = ast.literal_eval(value)
elif chr(92) in value:
    parts = shlex.split(value, posix=True)
    if len(parts) == 1:
        value = parts[0]
print(value, end="")
' "$key"
}
sh_quote() {
  local value="$1"
  value="${value//\'/\'\\\'\'}"
  printf "'%s'" "$value"
}
yaml_quote() {
  local value="$1"
  value="${value//\'/\'\'}"
  printf "'%s'" "$value"
}
CLIENT_PASSWORD="$(read_env_scalar O3K_BOOTSTRAP_PASSWORD)"
[[ -n "$CLIENT_PASSWORD" ]] || { echo "bootstrap password is missing from $ENV_FILE" >&2; exit 2; }
CLIENT_LISTEN_ADDR="$(read_env_scalar O3K_LISTEN_ADDR)"
[[ -n "$CLIENT_LISTEN_ADDR" ]] || CLIENT_LISTEN_ADDR=127.0.0.1:8080
ledger_records() {
  [[ -f "$CONFIG_FILE_LEDGER" ]] || return 1
  awk -F $'\t' -v key="$1" '$1 == "o3k-config-file-v1" && $2 == key { found = 1 } END { exit !found }' \
    "$CONFIG_FILE_LEDGER"
}
# A same-path operator or foreign file is preserved, not overwritten
# (ADR-0112/0139 owned-file semantics): only ledger-recorded files may be
# regenerated, and the ledger verification above already confirmed their
# content.
for client_file in admin-openrc clouds.yaml; do
  if [[ -e "$CONFIG_DIR/$client_file" || -L "$CONFIG_DIR/$client_file" ]] \
    && ! ledger_records "$client_file"; then
    echo "refusing to overwrite unrecorded client credential file: $CONFIG_DIR/$client_file" >&2
    exit 2
  fi
done
umask 077
{
  printf 'export OS_AUTH_URL=http://%s/v3\n' "$CLIENT_LISTEN_ADDR"
  printf 'export OS_USERNAME=admin\n'
  printf 'export OS_PASSWORD=%s\n' "$(sh_quote "$CLIENT_PASSWORD")"
  printf 'export OS_PROJECT_NAME=admin\n'
  printf 'export OS_USER_DOMAIN_NAME=Default\n'
  printf 'export OS_PROJECT_DOMAIN_NAME=Default\n'
  printf 'export OS_REGION_NAME=RegionOne\n'
  printf 'export OS_INTERFACE=public\n'
  printf 'export OS_IDENTITY_API_VERSION=3\n'
  # Route the CLI through the generated clouds.yaml (auth + pinned
  # image/network endpoint overrides for the shared-port catalog): with only
  # OS_* env vars, commands that touch the image service fail version
  # discovery at the bare catalog root (recorded as the v0.4.0-rc.3 campaign
  # defect: `openstack server show` could not resolve its image/flavor
  # follow-up). This mirrors the canonical protected bootstrap, which exports
  # OS_CLOUD/OS_CLIENT_CONFIG_FILE alongside OS_*.
  printf 'export OS_CLOUD=o3k-testlab\n'
  printf 'export OS_CLIENT_CONFIG_FILE=%s\n' "$(sh_quote "$CONFIG_DIR/clouds.yaml")"
} >"$CONFIG_DIR/admin-openrc"
chmod 0600 "$CONFIG_DIR/admin-openrc"
{
  printf 'clouds:\n'
  printf '  o3k-testlab:\n'
  printf '    auth:\n'
  printf '      auth_url: http://%s/v3\n' "$CLIENT_LISTEN_ADDR"
  printf '      username: admin\n'
  printf '      password: %s\n' "$(yaml_quote "$CLIENT_PASSWORD")"
  printf '      project_name: admin\n'
  printf '      user_domain_name: Default\n'
  printf '      project_domain_name: Default\n'
  printf '    region_name: RegionOne\n'
  printf '    interface: public\n'
  printf '    identity_api_version: 3\n'
  # The native catalog advertises image/network at the shared-port root, which
  # serves the identity version document; python-openstackclient then reports
  # "does not have any supported versions" (recorded as an RC.1 fresh-host
  # defect). The protected bootstrap carries the same overrides
  # (scripts/bootstrap-disposable-testlab.sh); pin the versioned service roots
  # here so the generated client config works out of the box.
  printf '    image_api_version: "2"\n'
  printf '    image_endpoint_override: http://%s/v2\n' "$CLIENT_LISTEN_ADDR"
  printf '    network_endpoint_override: http://%s/v2.0\n' "$CLIENT_LISTEN_ADDR"
} >"$CONFIG_DIR/clouds.yaml"
chmod 0600 "$CONFIG_DIR/clouds.yaml"
echo "wrote client credentials to $CONFIG_DIR/admin-openrc and $CONFIG_DIR/clouds.yaml"

ledger_tmp="$CONFIG_FILE_LEDGER.tmp-$$"
umask 077
: >"$ledger_tmp"
for relative in "${config_file_specs[@]}"; do
  [[ -f "$CONFIG_DIR/$relative" && ! -L "$CONFIG_DIR/$relative" ]] || {
    echo "configuration file is missing or unsafe: $relative" >&2
    rm -f -- "$ledger_tmp"
    exit 2
  }
  printf 'o3k-config-file-v1\t%s\t%s\n' "$relative" \
    "$(sha256sum "$CONFIG_DIR/$relative" | awk '{print $1}')" >>"$ledger_tmp"
done
# PRESERVE records this installer does not own. bootstrap-testlab.sh appends
# testlab-key.pem and testlab-flavor-id to the same ledger; dropping them on
# every re-run would later make purge treat those files as unverified
# operator state and refuse to remove them. Merge the unknown entries back,
# re-verifying their digests against the files exactly like the known ones —
# a mismatch fails closed instead of silently re-owning a modified file. The
# known-file operator-modified refusal above is deliberately unchanged.
declare -A ledger_spec_seen=()
for relative in "${config_file_specs[@]}"; do ledger_spec_seen["$relative"]=1; done
if [[ -f "$CONFIG_FILE_LEDGER" ]]; then
  while IFS=$'\t' read -r marker relative digest extra; do
    [[ -z "${extra:-}" && "$marker" == o3k-config-file-v1 && "$relative" != /* \
      && "$digest" =~ ^[0-9a-f]{64}$ ]] || continue
    [[ -n "${ledger_spec_seen["$relative"]:-}" ]] && continue
    [[ -f "$CONFIG_DIR/$relative" && ! -L "$CONFIG_DIR/$relative" ]] || {
      echo "refusing missing configuration file recorded in ledger: $relative" >&2
      rm -f -- "$ledger_tmp"
      exit 2
    }
    [[ "$(sha256sum "$CONFIG_DIR/$relative" | awk '{print $1}')" == "$digest" ]] || {
      echo "refusing to overwrite operator-modified configuration file: $relative" >&2
      rm -f -- "$ledger_tmp"
      exit 2
    }
    printf 'o3k-config-file-v1\t%s\t%s\n' "$relative" "$digest" >>"$ledger_tmp"
  done <"$CONFIG_FILE_LEDGER"
fi
mv -f -- "$ledger_tmp" "$CONFIG_FILE_LEDGER"
chmod 0600 "$CONFIG_FILE_LEDGER"
if [[ $EUID -eq 0 && $SYSTEM_INSTALL -eq 1 ]]; then
  chown -R o3k:o3k-compute "$DATA_DIR"
  chown -R o3k:o3k "$LOG_DIR"
  find "$DATA_DIR" -mindepth 1 -maxdepth 1 -type d ! -path "$COMPUTE_DATA_DIR" -exec chmod 0700 {} +
  find "$DATA_DIR" -mindepth 1 -maxdepth 1 -type f -exec chmod 0600 {} +
  # The network agent state dir has its own identity: restore it after the
  # recursive control-plane chown so the (never-enabled-here) o3k-network
  # unit can write its state once small-edge orchestration enrolls it.
  if [[ "$PROFILE" == libvirt && -n "$NETWORK_BINARY" && -d "$DATA_DIR/network" ]]; then
    chown o3k-network:o3k-network "$DATA_DIR/network"
    chmod 0700 "$DATA_DIR/network"
  fi
  # Keep the QEMU access model through reinstall: the compute subtree stays
  # group-kvm (the setgid bit is restored below), so pre-existing runtime
  # files (base images, overlays, console sinks) remain QEMU-readable after a
  # reset+reinstall cycle instead of being silently chowned to the compute
  # account's group.
  chown -R o3k-compute:kvm "$COMPUTE_DATA_DIR"
  # The agent identity file is compute-private identity material, not QEMU
  # runtime state; restore its compute-primary-group ownership.
  if [[ -f "$COMPUTE_DATA_DIR/agent-id" ]]; then
    chown o3k-compute:o3k-compute "$COMPUTE_DATA_DIR/agent-id"
  fi
  install_owned_system_file "$ROOT_DIR/packaging/o3kd.service" /etc/systemd/system/o3kd.service 0644
  if [[ "$PROFILE" == libvirt ]]; then
    install_owned_system_file "$ROOT_DIR/packaging/o3k-compute.service" \
      /etc/systemd/system/o3k-compute.service 0644
  fi
  if [[ "$PROFILE" == libvirt && -n "$NETWORK_BINARY" ]]; then
    # Installed but deliberately NOT enabled: the network agent is enrolled
    # by small-edge orchestration through the canonical init/join path
    # (contracts/installer-v1.yaml authority boundary).
    install_owned_system_file "$ROOT_DIR/packaging/o3k-network.service" \
      /etc/systemd/system/o3k-network.service 0644
  fi
  systemctl daemon-reload
  systemctl enable --now o3kd.service
  if [[ "$PROFILE" == libvirt ]]; then
    if [[ "$DEFER_COMPUTE_START" -eq 1 ]]; then
      systemctl enable o3k-compute.service
    else
      systemctl enable --now o3k-compute.service
    fi
  fi
fi
# The runtime access model applies to every root install and mirrors the
# disposable-testlab bootstrap: the QEMU process (primary group kvm) must
# traverse the control data directory to reach the compute overlays
# (execute only, never a directory listing; the durable files stay 0600),
# and the compute data directory must be group-kvm with the setgid bit so
# every overlay, config-drive publication, and console sink created by the
# agent inherits group kvm and stays readable by QEMU. Without this the
# installed libvirt profile fails at domain start with "Cannot access
# storage file ... Permission denied".
if [[ $EUID -eq 0 && "$PROFILE" == libvirt ]]; then
  chmod 0711 "$DATA_DIR"
  # Recursive: on a reset+reinstall the compute subtree may already hold runtime
  # files (base images, overlays) owned by the compute account's primary group;
  # without the recursive re-chown QEMU loses read access to them.
  chown -R o3k-compute:kvm "$COMPUTE_DATA_DIR"
  # The agent identity file is compute-private identity material, not QEMU
  # runtime state; restore its compute-primary-group ownership.
  if [[ -f "$COMPUTE_DATA_DIR/agent-id" ]]; then
    chown o3k-compute:o3k-compute "$COMPUTE_DATA_DIR/agent-id"
  fi
  chmod 2710 "$COMPUTE_DATA_DIR"
  # Pre-create the image-cache overlay chain with group kvm and setgid at
  # every level: the agent creates the leaf qcow2 files with its own primary
  # group when the intermediate directory lacks setgid, and the QEMU process
  # (primary group kvm) must traverse and read them. The console subtree
  # self-manages its group via the agent's explicit 2730/0660 modes.
  install -d -o o3k-compute -g kvm -m 2770 "$COMPUTE_DATA_DIR/image-cache"
  install -d -o o3k-compute -g kvm -m 2770 "$COMPUTE_DATA_DIR/image-cache/overlays"
fi
echo "installed o3kd profile=$PROFILE at $PREFIX/bin/o3kd; data=$DATA_DIR; config=$ENV_FILE; user=$RUN_USER"
