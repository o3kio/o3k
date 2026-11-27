#!/usr/bin/env bash
set -Eeuo pipefail
DATA_DIR=/var/lib/o3k
LOG_DIR=/var/log/o3k
CONFIRM=0
while (($#)); do case "$1" in --data-dir) DATA_DIR="$2"; shift 2;; --log-dir) LOG_DIR="$2"; shift 2;; --yes) CONFIRM=1; shift;; *) echo "unknown option: $1" >&2; exit 2;; esac; done
[[ $CONFIRM -eq 1 ]] || { echo "reset removes owned data; repeat with --yes" >&2; exit 2; }
validate_reset_path() {
  local name="$1" path="$2" current=/ component
  [[ -n "$path" && "$path" == /* && "$path" != / ]] || {
    echo "refusing unsafe reset path for $name: $path" >&2
    exit 2
  }
  while IFS= read -r component; do
    [[ -n "$component" ]] || continue
    case "$component" in
      .|..)
        echo "refusing lexical dot component in reset path for $name: $path" >&2
        exit 2
        ;;
    esac
    current="$current/$component"
    if [[ -L "$current" ]]; then
      echo "refusing symlink reset path for $name: $path" >&2
      exit 2
    fi
  done < <(tr '/' '\n' <<< "${path#/}")
}
validate_reset_path data-dir "$DATA_DIR"
validate_reset_path log-dir "$LOG_DIR"
owned_marker() { [[ -f "$1/.o3k-owned" && ! -L "$1/.o3k-owned" ]] && grep -Fqx "o3k-owned-v1 path=$1" "$1/.o3k-owned"; }
for path in "$DATA_DIR" "$LOG_DIR"; do
  if [[ -e "$path" ]] && ! owned_marker "$path"; then
    echo "refusing reset of unowned path: $path" >&2
    exit 2
  fi
done
for path in "$DATA_DIR" "$LOG_DIR"; do
  [[ -d "$path" ]] || continue
  if find "$path" -mindepth 1 -maxdepth 1 ! -name .o3k-owned -print -quit | grep -q .; then
    echo "refusing reset of non-empty state root with unclassified entries: $path" >&2
    exit 2
  fi
done
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop o3k-compute.service 2>/dev/null || true
systemctl stop o3k-storage.service 2>/dev/null || true
  systemctl stop o3kd.service 2>/dev/null || true
fi
echo "reset O3K-owned state under $DATA_DIR and $LOG_DIR; credentials were preserved"
