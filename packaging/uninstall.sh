#!/usr/bin/env bash
# uninstall.sh — remove an O3K installation.
#
# Removes only O3K-owned state: the install.sh ownership-manifest files
# (binaries, units, helper scripts), and, with --purge, the data/config/log
# roots after ownership and live-state fencing. PP.4 (#973): also removes the
# Araf demo deployment material the one-line installer copied into
# /usr/local/share/o3k/araf-demo/ (path-fenced like every other removal). The
# Araf demo RUNTIME (state dir, containers, /etc/hosts entries, o3kd OIDC
# federation block) is owned by o3k-araf-demo.sh uninstall/purge — run that
# first; this script only drops the static demo material from the share dir.
set -Eeuo pipefail
PREFIX=/usr/local
DATA_DIR=/var/lib/o3k
CONFIG_DIR=/etc/o3k
LOG_DIR=/var/log/o3k
PURGE=0
CONFIRM=0
while (($#)); do case "$1" in --prefix) PREFIX="$2"; shift 2;; --data-dir) DATA_DIR="$2"; shift 2;; --config-dir) CONFIG_DIR="$2"; shift 2;; --log-dir) LOG_DIR="$2"; shift 2;; --purge) PURGE=1; shift;; --yes) CONFIRM=1; shift;; *) echo "unknown option: $1" >&2; exit 2;; esac; done
[[ $PURGE -eq 0 || $CONFIRM -eq 1 ]] || { echo "--purge requires --yes" >&2; exit 2; }
validate_path() {
  local name="$1" path="$2"
  [[ -n "$path" && "$path" == /* && "$path" != / ]] || {
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
      echo "refusing symlink uninstall path for $name: $path" >&2
      exit 2
    fi
  done < <(tr '/' '\n' <<< "${path#/}")
}
validate_path prefix "$PREFIX"
for path in "$PREFIX/bin" "$PREFIX/share" "$PREFIX/share/o3k"; do
  if [[ -L "$path" ]]; then
    echo "refusing symlink uninstall path: $path" >&2
    exit 2
  fi
  if [[ -e "$path" && ! -d "$path" ]]; then
    echo "uninstall path is not a directory: $path" >&2
    exit 2
  fi
done
INSTALL_MANIFEST="$PREFIX/share/o3k/.o3k-installed"
[[ -f "$INSTALL_MANIFEST" && ! -L "$INSTALL_MANIFEST" ]] || {
  echo "refusing to remove files without an installation ownership manifest: $INSTALL_MANIFEST" >&2
  exit 2
}
MANIFEST_HEADER="o3k-installed-v1 prefix=$PREFIX"
[[ "$(head -n 1 "$INSTALL_MANIFEST")" == "$MANIFEST_HEADER" ]] || {
  echo "refusing unrecognized installation ownership manifest: $INSTALL_MANIFEST" >&2
  exit 2
}
MANIFEST_FILES=()
while IFS= read -r line; do
  [[ -n "$line" ]] || { echo "refusing malformed installation ownership manifest: $INSTALL_MANIFEST" >&2; exit 2; }
  [[ "$line" == "$MANIFEST_HEADER" ]] && continue
  case "$line" in
    bin/o3kd|bin/o3k|bin/o3k-compute|bin/o3k-network|share/o3k/o3kd.service|share/o3k/o3k-compute.service|share/o3k/o3k-network.service|share/o3k/50-o3k-libvirt.rules|share/o3k/release-manifest.json|share/o3k/SHA256SUMS|share/o3k/reset.sh|share/o3k/uninstall.sh|share/o3k/diagnose.sh|share/o3k/preflight.sh|share/o3k/bootstrap-certs.sh|share/o3k/bootstrap-testlab.sh|share/o3k/generate-passwords.sh)
      MANIFEST_FILES+=("$line")
      ;;
    *)
      echo "refusing unrecognized installation ownership entry: $line" >&2
      exit 2
      ;;
  esac
done < "$INSTALL_MANIFEST"
(( ${#MANIFEST_FILES[@]} > 0 )) || {
  echo "refusing empty installation ownership manifest: $INSTALL_MANIFEST" >&2
  exit 2
}
owned_marker() { [[ -f "$1/.o3k-owned" && ! -L "$1/.o3k-owned" ]] && grep -Fqx "o3k-owned-v1 path=$1" "$1/.o3k-owned"; }
SYSTEM_INSTALL=0
if [[ "$PREFIX" == /usr/local && "$DATA_DIR" == /var/lib/o3k && "$CONFIG_DIR" == /etc/o3k && "$LOG_DIR" == /var/log/o3k ]]; then SYSTEM_INSTALL=1; fi
if [[ $PURGE -eq 1 ]]; then
  for path in "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"; do
    validate_path purge-target "$path"
    if [[ -e "$path" ]] && ! owned_marker "$path"; then
      echo "refusing purge of unowned path: $path" >&2
      exit 2
    fi
  done
fi

assert_no_owned_host_state() {
  local compute_service=false
  if printf '%s\n' "${MANIFEST_FILES[@]}" | grep -Fqx 'share/o3k/o3k-compute.service'; then
    compute_service=true
  fi
  local compute_root="$DATA_DIR/compute"

  if [[ "$compute_service" == true ]]; then
    command -v virsh >/dev/null 2>&1 || {
      echo "refusing purge: libvirt inspection tool is unavailable" >&2
      return 1
    }
    virsh -c qemu:///system uri >/dev/null 2>&1 || {
      echo "refusing purge: libvirt state could not be inspected" >&2
      return 1
    }
    while IFS= read -r domain; do
      [[ -n "$domain" ]] || continue
      local xml
      xml="$(virsh -c qemu:///system dumpxml "$domain" 2>/dev/null)" || {
        echo "refusing purge: domain inspection failed for $domain" >&2
        return 1
      }
      if grep -Fq 'managed_by="o3k-compute"' <<<"$xml" \
        && grep -Fq '<o3k:domain' <<<"$xml"; then
        echo "refusing purge while O3K-owned libvirt domain exists: $domain" >&2
        return 1
      fi
    done < <(virsh -c qemu:///system list --all --name 2>/dev/null) || {
      echo "refusing purge: libvirt domain listing failed" >&2
      return 1
    }

    local network_manifest="$compute_root/network/ownership.json"
    if [[ -e "$network_manifest" ]]; then
      [[ -f "$network_manifest" && ! -L "$network_manifest" ]] || {
        echo "refusing purge: network ownership manifest is unsafe" >&2
        return 1
      }
      command -v python3 >/dev/null 2>&1 || {
        echo "refusing purge: cannot inspect network ownership manifest" >&2
        return 1
      }
      local network_names
      network_names="$(python3 - "$network_manifest" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    manifest = json.load(stream)
bridge = manifest.get("bridge") or {}
if bridge.get("created_by_o3k") and bridge.get("name"):
    print(bridge["name"])
for name, record in (manifest.get("taps") or {}).items():
    if record.get("created_by_o3k") and name:
        print(name)
PY
      )" || {
        echo "refusing purge: network ownership manifest is corrupt" >&2
        return 1
      }
      if [[ -n "$network_names" ]]; then
        command -v ip >/dev/null 2>&1 || {
          echo "refusing purge: network inspection tool is unavailable" >&2
          return 1
        }
        local links
        links="$(ip -o link show 2>/dev/null)" || {
          echo "refusing purge: network state could not be inspected" >&2
          return 1
        }
        while IFS= read -r name; do
          [[ -n "$name" ]] || continue
          if grep -Eq "^[0-9]+: ${name}(@[^:]+)?:" <<<"$links"; then
            echo "refusing purge while O3K-owned network link exists: $name" >&2
            return 1
          fi
        done <<<"$network_names"
      fi
    fi

    local dhcp_root="$compute_root/dhcp"
    if [[ -d "$dhcp_root" && ! -L "$dhcp_root" ]]; then
      while IFS= read -r pidfile; do
        [[ -n "$pidfile" ]] || continue
        local pid raw cmdline
        raw="$(<"$pidfile")" || return 1
        [[ "$raw" =~ ^[0-9]+$ ]] || {
          echo "refusing purge: malformed DHCP pidfile $pidfile" >&2
          return 1
        }
        pid="$raw"
        if kill -0 "$pid" 2>/dev/null; then
          cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null)" || {
            echo "refusing purge: DHCP process identity is unreadable" >&2
            return 1
          }
          if [[ "$cmdline" == *"$dhcp_root"* ]]; then
            echo "refusing purge while O3K DHCP process exists: $pid" >&2
            return 1
          fi
          echo "refusing purge: DHCP pidfile points to an unverified live process: $pid" >&2
          return 1
        fi
      done < <(find "$dhcp_root" -maxdepth 1 -type f -name 'dnsmasq-*.pid' -print)
    elif [[ -e "$dhcp_root" ]]; then
      echo "refusing purge: DHCP state root is unsafe" >&2
      return 1
    fi
  fi
}
if [[ $PURGE -eq 1 ]]; then
  assert_no_owned_host_state || exit 2
fi
if [[ $SYSTEM_INSTALL -eq 1 ]]; then
  command -v systemctl >/dev/null 2>&1 && systemctl disable --now o3kd.service 2>/dev/null || true
  command -v systemctl >/dev/null 2>&1 && systemctl disable --now o3k-compute.service 2>/dev/null || true
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
fi
remove_owned_system_file() {
  local source="$1" destination="$2"
  [[ ! -e "$destination" && ! -L "$destination" ]] && return 0
  if [[ -f "$source" && ! -L "$source" && -f "$destination" && ! -L "$destination" ]] \
    && cmp -s "$source" "$destination"; then
    rm -f -- "$destination"
  else
    echo "preserving foreign system file: $destination" >&2
  fi
}
if [[ $PURGE -eq 1 ]]; then
  purge_empty_owned_dir() {
    local path="$1"
    [[ -d "$path" && ! -L "$path" ]] || return 0
    if find "$path" -mindepth 1 -maxdepth 1 ! -name .o3k-owned -print -quit | grep -q .; then
      echo "refusing purge of non-empty state root with unclassified entries: $path" >&2
      exit 2
    fi
    rm -f -- "$path/.o3k-owned"
    rmdir -- "$path" 2>/dev/null || true
  }
  # Runtime data and logs are intentionally not recursively deleted: their
  # children have no independent installer ledger, so an unknown child may be
  # foreign state. Operators can reset/reconcile it explicitly first.
  purge_empty_owned_dir "$DATA_DIR"
  purge_empty_owned_dir "$LOG_DIR"
  if [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]]; then
    # Config files are removed only by exact, non-symlink paths created by the
    # installer and whose bytes still match the install-time content ledger.
    # A same-path operator or foreign replacement is preserved.
    CONFIG_FILE_LEDGER="$CONFIG_DIR/.o3k-config-files"
    config_file_unverified=false
    config_file_owned() {
      local relative="$1" target="$CONFIG_DIR/$1" expected actual
      [[ -f "$CONFIG_FILE_LEDGER" && ! -L "$CONFIG_FILE_LEDGER" ]] || return 1
      [[ -f "$target" && ! -L "$target" ]] || return 1
      expected="$(awk -F $'\t' -v key="$relative" \
        '$1 == "o3k-config-file-v1" && $2 == key { print $3; exit }' \
        "$CONFIG_FILE_LEDGER")"
      [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
      actual="$(sha256sum "$target" | awk '{print $1}')"
      [[ "$actual" == "$expected" ]]
    }
    # Admin/testlab client credential files, the disposable testlab key, and
    # the testlab flavor ownership record are ledger-owned too (install.sh
    # and bootstrap-testlab.sh record them), so purge removes them under the
    # same digest-verification fence.
    for file in o3kd.env o3kd.env.lock o3k-compute.env admin-openrc clouds.yaml testlab-key.pem testlab-flavor-id; do
      if config_file_owned "$file"; then
        rm -f -- "$CONFIG_DIR/$file"
      elif [[ -e "$CONFIG_DIR/$file" ]]; then
        echo "preserving unverified config file: $CONFIG_DIR/$file" >&2
        config_file_unverified=true
      fi
    done
    if [[ -d "$CONFIG_DIR/tls" && ! -L "$CONFIG_DIR/tls" ]]; then
      for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem agent-id agent-fingerprint; do
        if config_file_owned "tls/$file"; then
          rm -f -- "$CONFIG_DIR/tls/$file"
        elif [[ -e "$CONFIG_DIR/tls/$file" ]]; then
          echo "preserving unverified TLS file: $CONFIG_DIR/tls/$file" >&2
          config_file_unverified=true
        fi
      done
      rmdir -- "$CONFIG_DIR/tls" 2>/dev/null || true
    fi
    if find "$CONFIG_DIR" -mindepth 1 -maxdepth 1 ! -name .o3k-owned ! -name .o3k-config-files -print -quit | grep -q .; then
      echo "preserving unknown config state: $CONFIG_DIR" >&2
    else
      rm -f -- "$CONFIG_FILE_LEDGER"
      rm -f -- "$CONFIG_DIR/.o3k-owned"
      rmdir -- "$CONFIG_DIR" 2>/dev/null || true
    fi
    if [[ "$config_file_unverified" == true ]]; then
      echo "refusing purge while unverified configuration remains" >&2
      exit 2
    fi
  fi
  # The libvirt-profile polkit rule applied by install.sh is O3K-applied
  # state: purge removes it (issue #90). The rule is inert on hosts whose
  # libvirtd uses auth_unix_rw = "none" (Ubuntu 24.04) and is scoped to the
  # o3k user only, so removing it restores the host's default posture.
  # install.sh only applies the rule when EUID == 0; mirror that guard so a
  # sandboxed non-root purge (packaging tests) never touches host paths.
  if [[ $EUID -eq 0 ]]; then
    remove_owned_system_file "$PREFIX/share/o3k/50-o3k-libvirt.rules" \
      /etc/polkit-1/rules.d/50-o3k-libvirt.rules
  else
    echo "skipping /etc/polkit-1/rules.d/50-o3k-libvirt.rules removal (not root)" >&2
  fi
fi

if [[ $SYSTEM_INSTALL -eq 1 ]]; then
  remove_owned_system_file "$PREFIX/share/o3k/o3kd.service" /etc/systemd/system/o3kd.service
  remove_owned_system_file "$PREFIX/share/o3k/o3k-compute.service" /etc/systemd/system/o3k-compute.service
  remove_owned_system_file "$PREFIX/share/o3k/o3k-network.service" /etc/systemd/system/o3k-network.service
fi
for relative in "${MANIFEST_FILES[@]}"; do
  destination="$PREFIX/$relative"
  if [[ -L "$destination" ]]; then
    echo "refusing to remove symlink installation target: $destination" >&2
    exit 2
  fi
  if [[ -e "$destination" && ! -f "$destination" ]]; then
    echo "refusing to remove non-file installation target: $destination" >&2
    exit 2
  fi
  [[ -e "$destination" ]] && rm -f -- "$destination"
done
rm -f -- "$INSTALL_MANIFEST"
# PP.4 (#973): the one-line installer copies the Araf demo deployment material
# (orchestrator + compose material) into this O3K-owned share path; it is not
# part of the install.sh ownership ledger, so it is removed here under the
# same fencing (validate_path refuses symlink components; the tree itself is
# O3K-owned demo material).
DEMO_SHARE_DIR="$PREFIX/share/o3k/araf-demo"
if [[ -e "$DEMO_SHARE_DIR" || -L "$DEMO_SHARE_DIR" ]]; then
  validate_path demo-share-dir "$DEMO_SHARE_DIR"
  if [[ -L "$DEMO_SHARE_DIR" ]]; then
    echo "refusing to remove symlink demo material path: $DEMO_SHARE_DIR" >&2
    exit 2
  fi
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^o3k-araf-demo-'; then
    echo "refusing to remove the Araf demo material while the demo stack is running;" >&2
    echo "  run: sudo $DEMO_SHARE_DIR/o3k-araf-demo.sh uninstall" >&2
    exit 2
  fi
  # Remove only the files this installer owns; anything else under the tree is
  # operator state and is preserved (the directory is left in place).
  demo_removed=0
  for demo_file in o3k-araf-demo.sh araf-demo/compose.yaml araf-demo/nginx.conf \
    araf-demo/api-relay.conf araf-demo/realm.json araf-demo/README.md; do
    if [[ -f "$DEMO_SHARE_DIR/$demo_file" ]]; then
      rm -f -- "$DEMO_SHARE_DIR/$demo_file"
      demo_removed=$((demo_removed + 1))
    fi
  done
  rmdir "$DEMO_SHARE_DIR/araf-demo" "$DEMO_SHARE_DIR" 2>/dev/null || {
    echo "preserved operator files under $DEMO_SHARE_DIR (not owned by the installer)"
  }
fi
if [[ $PURGE -eq 1 ]]; then
  echo "o3k binaries, helper files, and owned state removed"
else
  echo "o3k binaries and helper files removed; data/config/logs preserved (use --purge --yes to remove them)"
fi
