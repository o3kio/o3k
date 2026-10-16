#!/usr/bin/env bash
set -euo pipefail

for command in sudo truncate mkfs.ext4 mountpoint findmnt stat df cargo git python3 realpath; do
  command -v "$command" >/dev/null || {
    printf 'required command missing: %s\n' "$command" >&2
    exit 1
  }
done
sudo -n true || {
  echo "non-interactive sudo is required for real ext4 ENOSPC evidence" >&2
  exit 1
}

runner_temp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p -- "$runner_temp"
runner_temp="$(realpath -e -- "$runner_temp")"
export RUNNER_TEMP="$runner_temp"
evidence="${O3K_SQLITE_PRESSURE_EVIDENCE_PATH:-${runner_temp}/pp6-sqlite-disk-pressure.json}"
if [[ "$(basename -- "$evidence")" != "pp6-sqlite-disk-pressure.json" || \
      "$(realpath -e -- "$(dirname -- "$evidence")")" != "$runner_temp" ]]; then
  echo "evidence output must be the named file directly under RUNNER_TEMP" >&2
  exit 1
fi
if [[ -e "$evidence" || -L "$evidence" ]]; then
  echo "evidence output already exists; refusing to replace it: $evidence" >&2
  exit 1
fi

state_root="$(mktemp -d "${TMPDIR:-/tmp}/o3k-sqlite-pressure.XXXXXXXX")"
mount_dir="${state_root}/mount"
image="${state_root}/filesystem.img"
mkdir -- "$mount_dir"
mounted=0

cleanup() {
  local status=$?
  local cleanup_result=PASS
  trap - EXIT
  if (( mounted )); then
    if ! sudo -n umount -- "$mount_dir"; then
      echo "failed to unmount isolated SQLite pressure filesystem: $mount_dir" >&2
      cleanup_result=FAIL
      status=1
    else
      mounted=0
    fi
  fi
  if mountpoint -q -- "$mount_dir"; then
    echo "isolated mount unexpectedly remains active: $mount_dir" >&2
    cleanup_result=FAIL
    status=1
  fi
  if (( ! mounted )) && ! mountpoint -q -- "$mount_dir"; then
    if [[ -e "$image" ]] && ! unlink -- "$image"; then
      echo "failed to unlink isolated filesystem image: $image" >&2
      cleanup_result=FAIL
      status=1
    fi
    if ! rmdir -- "$mount_dir" "$state_root"; then
      echo "failed to remove isolated SQLite pressure harness directory" >&2
      cleanup_result=FAIL
      status=1
    fi
  fi
  if [[ -f "$evidence" ]]; then
    if ! python3 - "$evidence" "$status" "$cleanup_result" <<'PY'
import json
import os
import stat
import sys

path = sys.argv[1]
test_status = int(sys.argv[2])
cleanup_result = sys.argv[3]
descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
if not stat.S_ISREG(os.fstat(descriptor).st_mode):
    os.close(descriptor)
    raise SystemExit("SQLite pressure evidence output is not a regular file")
with os.fdopen(descriptor, "r+", encoding="utf-8") as evidence_file:
    report = json.load(evidence_file)
    report["cleanup_result"] = cleanup_result
    report["cleanup"] = "isolated mount unmounted and loopback image and harness directory removed" if cleanup_result == "PASS" else "isolated mount or loopback cleanup failed"
    if test_status == 0 and cleanup_result == "PASS":
        report["disposition"] = "PASS"
    else:
        report["disposition"] = "ACCEPTANCE_PENDING" if test_status == 0 else "FAIL"
    evidence_file.seek(0)
    evidence_file.truncate()
    evidence_file.write(json.dumps(report, indent=2, sort_keys=True) + "\n")

if test_status == 0 and cleanup_result == "PASS":
    required = {
        "disposition": "PASS",
        "test": "o3k-store::sqlite_store_fails_atomically_when_real_wal_filesystem_is_full",
        "failed_resource_id_absent": True,
        "baseline_resource_and_operation_unchanged": True,
        "foreign_state_mutated": False,
        "cleanup_result": "PASS",
    }
    for key, expected in required.items():
        if report.get(key) != expected:
            raise SystemExit(f"SQLite pressure evidence missing/invalid {key}: {report.get(key)!r}")
    if report.get("observed_error", {}).get("category") != "SQLITE_FULL":
        raise SystemExit("SQLite pressure evidence did not classify SQLITE_FULL")
    for key in (
        "source_commit", "source_tree", "execution_commit", "execution_tree",
        "sqlite_version", "sqlx_version", "journal_mode", "filesystem_source",
        "filesystem_size_bytes", "migration_count", "latest_migration", "profile",
    ):
        if not report.get(key):
            raise SystemExit(f"SQLite pressure evidence missing {key}")
    print(f"validated source-bound SQLite disk-pressure evidence: {path}")
PY
    then
      status=1
    fi
  elif (( status == 0 )); then
    echo "SQLite pressure test passed without writing its evidence record" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

# A bounded disposable image avoids consuming the runner's root filesystem.
truncate -s 48M -- "$image"
sudo -n mkfs.ext4 -F -q "$image"
sudo -n mount -o loop,nodev,nosuid,noexec -- "$image" "$mount_dir"
mounted=1
sudo -n chown "$(id -u):$(id -g)" -- "$mount_dir"

filesystem_type="$(findmnt --noheadings --output FSTYPE --target "$mount_dir")"
filesystem_size_bytes="$(df --block-size=1 --output=size "$mount_dir" | tail -n 1 | tr -d '[:space:]')"
filesystem_source="$(findmnt --noheadings --output SOURCE --target "$mount_dir")"
if [[ "$filesystem_type" != ext4 || "$filesystem_source" != /dev/loop* ]]; then
  printf 'expected an isolated ext4 loopback filesystem, got type=%s source=%s\n' \
    "$filesystem_type" "$filesystem_source" >&2
  exit 1
fi
if [[ ! -d "$mount_dir" || "$(stat -f -c '%T' -- "$mount_dir")" != ext2/ext3 ]]; then
  echo "pressure root is not on the expected ext filesystem" >&2
  exit 1
fi

source_commit="${O3K_SQLITE_PRESSURE_SOURCE_COMMIT:-$(git rev-parse HEAD)}"
source_tree="$(git rev-parse "${source_commit}^{tree}")"
execution_commit="$(git rev-parse HEAD)"
execution_tree="$(git rev-parse HEAD^{tree})"
sqlx_version="$(python3 -c 'import pathlib,tomllib; data=tomllib.loads(pathlib.Path("Cargo.lock").read_text()); print(next(p["version"] for p in data["package"] if p["name"] == "sqlx"))')"
mkdir -p -- "$(dirname -- "$evidence")"
token="$(python3 -c 'import uuid; print(uuid.uuid4())')"
printf '%s\n' "$token" > "$mount_dir/.o3k-sqlite-pressure-harness"
chmod 0600 -- "$mount_dir/.o3k-sqlite-pressure-harness"
O3K_SQLITE_PRESSURE_ROOT="$mount_dir" \
O3K_SQLITE_PRESSURE_EVIDENCE_PATH="$evidence" \
O3K_SQLITE_PRESSURE_HARNESS_TOKEN="$token" \
O3K_SQLITE_PRESSURE_SOURCE_COMMIT="$source_commit" \
O3K_SQLITE_PRESSURE_SOURCE_TREE="$source_tree" \
O3K_SQLITE_PRESSURE_EXECUTION_COMMIT="$execution_commit" \
O3K_SQLITE_PRESSURE_EXECUTION_TREE="$execution_tree" \
O3K_SQLITE_PRESSURE_OS="$(uname -srmo)" \
O3K_SQLITE_PRESSURE_FS_TYPE="$filesystem_type" \
O3K_SQLITE_PRESSURE_FS_SIZE_BYTES="$filesystem_size_bytes" \
O3K_SQLITE_PRESSURE_FS_SOURCE="$filesystem_source" \
O3K_SQLITE_PRESSURE_SQLX_VERSION="$sqlx_version" \
  cargo test --locked -p o3k-store --test sqlite_disk_pressure --all-features -- --ignored --nocapture
